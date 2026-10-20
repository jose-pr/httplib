"""The default transport: HTTP/1.1 on `http.client`, with no third-party code."""

from __future__ import annotations

import errno as _errno
import http.client as _client
import logging as _logging
import select as _select
import socket as _socket
import ssl as _ssl
import threading as _threading
import time as _time
import typing as _ty

from . import _pool
from ._body import prepare_body
from ._headers import (
    Target,
    check_body,
    check_headers,
    check_method,
    check_timeout,
    check_url,
    wants_decoding,
)
from ._response import HTTPResponse

_log = _logging.getLogger(__name__)


@_ty.runtime_checkable
class Transport(_ty.Protocol):
    """What `HTTPClient` sends through: one request, one response, no redirect,
    no credentials added.

    `send()` takes the arguments `prepare_request()` checks and returns an
    `HTTPResponse` (`stream=False`: its body already read; `stream=True`: the
    caller closes it); `close()` releases whatever the transport holds."""

    def send(
        self,
        method: str,
        url: str,
        *,
        headers: "_ty.Mapping[str, str]",
        body: "bytes | _ty.BinaryIO | _ty.Iterable[bytes] | None" = None,
        timeout: "float | tuple | None",
        stream: bool = False,
    ) -> HTTPResponse: ...

    def close(self) -> None: ...


REUSE_WINDOW = 1.0
"""A request that cannot be sent again uses an idle connection only if the
connection carried a response within this many seconds; an older one may have
been dropped by the server, and the request would be lost with it."""

_IDEMPOTENT = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE", "PROPFIND"})

_now = _time.monotonic

_DEFAULT_CONTEXT: "_ssl.SSLContext | None" = None
_UNVERIFIED_CONTEXT: "_ssl.SSLContext | None" = None
_DEFAULT_CONTEXT_LOCK = _threading.Lock()


def _default_context() -> "_ssl.SSLContext":
    """One verifying context for every transport that is not given its own."""
    global _DEFAULT_CONTEXT
    with _DEFAULT_CONTEXT_LOCK:
        if _DEFAULT_CONTEXT is None:
            _DEFAULT_CONTEXT = _ssl.create_default_context()
        return _DEFAULT_CONTEXT


def _unverified_context() -> "_ssl.SSLContext":
    """One context that accepts any certificate, for `verify=False`."""
    global _UNVERIFIED_CONTEXT
    with _DEFAULT_CONTEXT_LOCK:
        if _UNVERIFIED_CONTEXT is None:
            context = _ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = _ssl.CERT_NONE
            _UNVERIFIED_CONTEXT = context
        return _UNVERIFIED_CONTEXT


def _failure(error: BaseException) -> BaseException:
    """`error` of the socket, TLS or `http.client` layer as the exception a
    transport raises: `TimeoutError`, `ConnectionError`, `ssl.SSLError`, or
    else `OSError(EIO)`. The text never holds a URL or a header."""
    if isinstance(error, (_socket.timeout, TimeoutError)):
        return TimeoutError(_errno.ETIMEDOUT, "the request timed out")
    if isinstance(error, _ssl.SSLError):
        if "timed out" in str(error):
            return TimeoutError(_errno.ETIMEDOUT, "the request timed out")
        return error
    if isinstance(error, _client.RemoteDisconnected):
        return ConnectionResetError(_errno.ECONNRESET, "the server closed the connection without a response")
    if isinstance(error, ConnectionError):
        return error
    if isinstance(error, _socket.gaierror):
        return ConnectionError(_errno.EHOSTUNREACH, "the host name could not be resolved")
    if isinstance(error, _client.NotConnected):
        return ConnectionAbortedError(_errno.ECONNABORTED, "the connection was closed")
    if isinstance(error, _client.IncompleteRead):
        return OSError(_errno.EIO, "the response ended before its stated length")
    if isinstance(error, _client.HTTPException):
        return OSError(_errno.EIO, f"the response is not valid HTTP ({type(error).__name__})")
    return error


def _dropped(error: BaseException) -> bool:
    """Whether `error` says the server closed an idle connection (as opposed to
    a request that went wrong): nothing of a response had arrived."""
    return isinstance(
        error,
        (
            ConnectionResetError,
            ConnectionAbortedError,
            BrokenPipeError,
            _ssl.SSLEOFError,
            _ssl.SSLZeroReturnError,
        ),
    )


def _unusable(sock) -> bool:
    """Whether an idle connection must not carry a request: the server closed
    it, or sent bytes nobody asked for, which the next reply would start with."""
    if sock is None:
        return True
    try:
        if getattr(sock, "pending", None) is not None and sock.pending():
            return True
        return bool(_select.select([sock], [], [], 0)[0])
    except (OSError, ValueError):
        return True


MAX_INTERIM_REPLIES = 8
"""Most interim (1xx) replies the transport skips before the reply it returns;
a server that sends more is not answering."""


def _skip_headers(fp) -> None:
    """Reads the header lines of an interim reply, up to its blank line."""
    for _ in range(100):
        line = fp.readline(65537)
        if len(line) > 65536:
            raise _client.LineTooLong("header line")
        if line in (b"\r\n", b"\n", b""):
            return
    raise _client.HTTPException("got more than 100 headers")


class _Reply(_client.HTTPResponse):
    """A response that goes past every interim (1xx) reply, not only `100`
    (`http.client` takes any other as the final one, and the real reply is then
    read as the answer to the next request), and at most `MAX_INTERIM_REPLIES`
    of them."""

    _interim = 0

    def _read_status(self):
        while True:
            version, status, reason = super()._read_status()
            if not 100 <= status < 200:
                return version, status, reason
            self._interim += 1
            if self._interim > MAX_INTERIM_REPLIES:
                raise _client.HTTPException("too many interim replies")
            if status == _client.CONTINUE:
                return version, status, reason  # `begin()` skips its headers
            _skip_headers(self.fp)


class _Dropped(Exception):
    """An idle connection the server had closed."""

    def __init__(self, error: BaseException):
        super().__init__()
        self.error = error


class _Payload:
    """The request body, whether it can be sent twice, and the
    `Content-Length` to add to the request (`None`: none to add)."""

    def __init__(self, body, pairs):
        self.repeatable = check_body(body)
        self.value, self.length = prepare_body(body, pairs)


class _Body:
    """The body of one response, read from its connection. The connection goes
    back to the pool once the body has been read to its end; one that is
    closed earlier, fails, or ends short is closed."""

    def __init__(self, owner, pool, connection, response, expected: "int | None"):
        # The transport stays alive while its reply is open: collecting it
        # would close the connection the reply is reading.
        self._owner = owner
        self._pool = pool
        self._connection = connection
        self._response = response
        self._expected = expected
        self._received = 0
        self._done = False
        if expected == 0:
            self._finish()

    def _finish(self) -> None:
        if self._done:
            return
        self._done = True
        # Closing the response closes its file object, not the socket; a
        # response left open would make `http.client` refuse the next request.
        self._response.close()
        if self._response.will_close:
            self._pool.discard(self._connection)
        else:
            self._pool.give_back(self._connection, _now())

    def _abort(self) -> None:
        if not self._done:
            self._done = True
            self._response.close()
            self._pool.discard(self._connection)

    def read(self, amount: int) -> bytes:
        if self._done:
            return b""
        try:
            chunk = self._response.read1(amount)
        except (OSError, _client.HTTPException) as error:
            self._abort()
            raise _failure(error) from None
        except BaseException:
            self._abort()
            raise
        if chunk:
            self._received += len(chunk)
            if self._response.isclosed():
                self._finish()
            return chunk
        if self._expected is not None and self._received < self._expected:
            self._abort()
            raise OSError(
                _errno.EIO,
                f"the response ended after {self._received} of {self._expected} bytes",
            )
        self._finish()
        return b""

    def close(self) -> None:
        self._abort()


class HTTPTransport:
    """Sends HTTP requests on the standard library: `http.client` over a socket,
    with TLS from `ssl`, and no third-party code.

    `send()` makes exactly one request: it follows no redirect, adds no
    credentials and retries only as described below. A transport is a context
    manager, and `close()` closes every connection it holds.

    `https:` servers are verified against `ssl_context`; without one, against
    `ssl.create_default_context()` (the system trust store). `verify=False`
    is the one way to turn verification off, and `ssl_context` wins over it.

    Each thread keeps one idle connection per server (at most 8), which a later
    request reuses unless the server has closed it or sent bytes on it since;
    the connections of a thread are closed when it ends. A
    request that fails before any response byte on a reused connection because
    the server had closed it is sent once more on a new connection, but only
    if it is repeatable (`GET`, `HEAD`, `OPTIONS`, `PUT`, `DELETE`,
    `PROPFIND`) and its body is `None` or in memory. Any other request reuses a
    connection only if it carried a response within the last second."""

    def __init__(
        self,
        *,
        ssl_context: "_ssl.SSLContext | None" = None,
        verify: bool = True,
    ):
        self._ssl_context = ssl_context
        self._verify = bool(verify)
        if not self._verify and ssl_context is None:
            _log.warning("HTTPTransport(verify=False): TLS certificates are not verified")
        self._pool = _pool.Pool()
        self._finalizer = _pool.finalize_with(self, self._pool)

    def __repr__(self) -> str:
        return f"HTTPTransport(verify={self._verify})"

    def __enter__(self) -> "HTTPTransport":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def close(self) -> None:
        """Closes every connection, idle or in use. Harmless when called again;
        a later request connects afresh."""
        self._pool.close()

    def _context(self) -> "_ssl.SSLContext":
        if self._ssl_context is not None:
            return self._ssl_context
        return _default_context() if self._verify else _unverified_context()

    def send(
        self,
        method: str,
        url: str,
        *,
        headers: "_ty.Mapping[str, str]",
        body: "bytes | _ty.BinaryIO | _ty.Iterable[bytes] | None" = None,
        timeout: "float | tuple | None",
        stream: bool = False,
    ) -> HTTPResponse:
        """One request, one response.

        `headers` are sent as given; `Accept-Encoding: gzip, deflate` is added
        (and a coded body decoded) unless they name an `Accept-Encoding`.
        A `body` whose length is known without reading it goes under a
        `Content-Length`, any other chunked; a `Content-Length` in `headers`
        is used as it is. `timeout` is seconds for the connection and for each wait on the
        server: a number, a `(connect, read)` pair, or `None` to wait for ever.
        With `stream=False` the body has been read when this returns; with
        `stream=True` it is read from the response, which must be closed.

        Raises `ValueError` before anything is sent for a header or URL with
        a control character, a URL with credentials or another scheme;
        `TimeoutError`, `ConnectionError` and `ssl.SSLError` for the network;
        `OSError(EIO)` for a reply that is not valid HTTP or ends early."""
        method = check_method(method)
        target = check_url(url)
        pairs = check_headers(headers)
        connect_timeout, read_timeout = check_timeout(timeout)
        payload = _Payload(body, pairs)
        names = {name.lower() for name, _ in pairs}
        decode = wants_decoding(pairs)
        # As the server will see it: no fragment, "/" for an empty path.
        plain_url = f"{target.scheme}://{target.authority}{target.path}"
        response = self._attempt(
            method, target, pairs, names, payload, connect_timeout, read_timeout, plain_url, decode
        )
        return response if stream else response._buffered()

    def _attempt(
        self,
        method: str,
        target: Target,
        pairs,
        names,
        payload: _Payload,
        connect_timeout,
        read_timeout,
        url: str,
        decode: bool,
    ) -> HTTPResponse:
        key = (target.scheme, target.host, target.port)
        repeatable = method in _IDEMPOTENT and payload.repeatable
        scope = _pool.scope_id()
        connection = self._pool.take(key, scope)
        if connection is not None and not repeatable and _now() - connection.released_at > REUSE_WINDOW:
            self._pool.discard(connection)
            connection = None
        if connection is not None and _unusable(connection.http.sock):
            self._pool.discard(connection)
            connection = None
        reused = connection is not None
        while True:
            if connection is None:
                connection = self._open(target, key, scope, connect_timeout, read_timeout)
                reused = False
            sock = connection.http.sock
            try:
                if sock is None:
                    raise ConnectionAbortedError(_errno.ECONNABORTED, "the connection was closed")
                sock.settimeout(read_timeout)
            except OSError:
                # An idle socket that is already closed: nothing was sent.
                self._pool.discard(connection)
                if not reused:
                    raise
                connection, reused = None, False
                continue
            try:
                return self._exchange(
                    connection,
                    method,
                    target,
                    pairs,
                    names,
                    payload,
                    url,
                    decode,
                    reused,
                )
            except _Dropped as dropped:
                if reused and repeatable:
                    connection, reused = None, False
                    continue
                raise dropped.error from None

    def _headers(self, target: Target, pairs, names, payload) -> "dict[str, str]":
        sent = dict(pairs)
        if payload.length is not None:
            sent["Content-Length"] = str(payload.length)
        if "host" not in names:
            sent["Host"] = target.authority
        if "accept-encoding" not in names:
            sent["Accept-Encoding"] = "gzip, deflate"
        return sent

    def _exchange(
        self,
        connection,
        method,
        target,
        pairs,
        names,
        payload,
        url,
        decode,
        reused,
    ) -> HTTPResponse:
        http = connection.http
        try:
            http.request(
                method,
                target.path,
                body=payload.value,
                headers=self._headers(target, pairs, names, payload),
            )
            response = http.getresponse()
        except (OSError, _client.HTTPException) as error:
            self._pool.discard(connection)
            if reused and _dropped(error):
                raise _Dropped(_failure(error)) from None
            raise _failure(error) from None
        except BaseException:
            self._pool.discard(connection)
            raise
        headers = response.getheaders()
        body = _Body(self, self._pool, connection, response, response.length)
        return HTTPResponse(response.status, response.reason, headers, url, body, decode=decode)

    def _open(self, target, key, scope, connect_timeout, read_timeout):
        try:
            raw = _socket.create_connection((target.host, target.port), timeout=connect_timeout)
        except (OSError, _client.HTTPException) as error:
            raise _failure(error) from None
        sock = raw
        try:
            raw.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
            if target.scheme == "https":
                sock = self._context().wrap_socket(raw, server_hostname=target.host)
            sock.settimeout(read_timeout)
        except (OSError, _client.HTTPException) as error:
            raw.close()
            raise _failure(error) from None
        except BaseException:
            raw.close()
            raise
        http = _client.HTTPConnection(target.host, target.port)
        # A connection that was closed stays closed: `http.client` would
        # otherwise reconnect by itself, in plain TCP, outside the TLS session,
        # the proxy and the timeout this request was given.
        http.auto_open = 0
        http.response_class = _Reply
        http.sock = sock
        connection = _pool.Connection(http, key, scope, self._pool.generation)
        self._pool.register(connection)
        return connection

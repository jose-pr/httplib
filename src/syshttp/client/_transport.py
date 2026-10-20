"""The default transport: HTTP/1.1 on `http.client`, with no third-party code."""

from __future__ import annotations

import errno as _errno
import http.client as _client
import logging as _logging
import os as _os
import select as _select
import socket as _socket
import ssl as _ssl
import threading as _threading
import time as _time
import typing as _ty

import proxylib

from .. import proxy as _proxy
from ..env import HTTPEnv
from . import _pool, _route
from ._body import prepare_body
from ._context import TLSChoice
from ._headers import (
    Target,
    bracket,
    check_body,
    check_headers,
    check_method,
    check_timeout,
    check_url,
    wants_decoding,
)
from ._response import HTTPResponse
from ._tlstunnel import TunneledTLS

_log = _logging.getLogger(__name__)


@_ty.runtime_checkable
class Transport(_ty.Protocol):
    """What `HTTPClient` sends through: one request, one response, no redirect,
    no credentials added.

    `send()` takes the arguments `prepare_request()` checks and returns an
    `HTTPResponse` (`stream=False`: its body already read; `stream=True`: the
    caller closes it); `close()` releases whatever the transport holds. The
    client does the redirects, cookies, tokens, hooks, retries and deadline
    above it. Routing (the proxy map, `CONNECT`, gateways), TLS verification,
    connection reuse and decoding a `gzip` or `deflate` body are the
    transport's: `HTTPTransport` does them with syshttp's proxy map and the
    system's TLS, and a transport on another library brings that library's."""

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


class _Route(_ty.NamedTuple):
    """Where a request is sent and how it is written for the first server it
    reaches."""

    wire: Target  # the server written for: the origin, or a gateway
    proxy: "proxylib.Proxy | None"  # the http or https proxy it passes through
    gateway: "proxylib.Proxy | None"  # the URL-prefix gateway it is handed to
    key: tuple  # what a pooled connection is keyed by


class HTTPTransport:
    """Sends HTTP requests on the standard library: `http.client` over a socket,
    with TLS from `ssl`, and no third-party code.

    `send()` makes exactly one request: it follows no redirect, adds no
    credentials of the caller's and retries only as described below. A
    transport is a context manager, and `close()` closes every connection it
    holds.

    **Routing.** Each request asks `proxymap` (a proxylib proxy map; default
    `proxy.proxy_map(env=env)`: `SYSHTTP_PROXY`, the `*_PROXY` variables,
    `NO_PROXY`, then the system's configuration) which entries it may use, and
    takes the first that accepts a connection (`proxylib.Probed`; with no entry
    reachable and no direct one, `proxylib.NoReachableProxyError`). A direct
    entry connects to the origin. An `http:` or `https:` proxy gets an
    absolute-form request for an `http:` origin and a `CONNECT` for an `https:`
    one; its headers (a credential) go to it alone, in the `CONNECT` or on the
    plain-http request, never through the tunnel. A `prefix+http(s)` gateway is
    asked for `<gateway><path><URL>` with its credential as a header of that
    request, and the response keeps the URL asked for. SOCKS entries are not
    spoken (`proxylib.UnsupportedProxyError` when nothing else is offered). A
    map with no opinion for a URL, `{}` included, means a direct connection.

    **TLS.** `https:` origins are verified against `ssl_context` when given,
    else the CA bundle named by the `CA_BUNDLE` setting, else the system's
    context (`tls.os_ssl_context()`). `verify=False` is the one way to turn
    verification off, `verify=<path>` names a bundle, and an `ssl_context`
    beside either is `ValueError`. An `https:` proxy or gateway is spoken to
    with `proxy_ssl_context`, else the system's context.

    Each thread keeps one idle connection per route (at most 8), which a later
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
        proxymap: "_ty.Any" = None,
        env: "HTTPEnv | None" = None,
        ssl_context: "_ssl.SSLContext | None" = None,
        proxy_ssl_context: "_ssl.SSLContext | None" = None,
        verify: "bool | str | _os.PathLike[str]" = True,
    ):
        self._env = HTTPEnv() if env is None else env
        self._tls = TLSChoice(self._env, ssl_context, proxy_ssl_context, verify)
        if proxymap is None:
            # Decided at every request; a malformed setting is refused now.
            _proxy.configured_proxy(env=self._env)
            self._proxymap: "_ty.Any" = _proxy.proxy_map(env=self._env)
        else:
            self._proxymap = _ty.cast(_ty.Any, proxylib.ProxyMap)(proxymap)
        if self._tls.unverified:
            _log.warning("HTTPTransport(verify=False): TLS certificates are not verified")
        self._pool = _pool.Pool()
        self._finalizer = _pool.finalize_with(self, self._pool)

    def __repr__(self) -> str:
        return f"HTTPTransport(verify={not self._tls.unverified})"

    def __enter__(self) -> "HTTPTransport":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def close(self) -> None:
        """Closes every connection, idle or in use. Harmless when called again;
        a later request connects afresh."""
        self._pool.close()

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
        `OSError(EIO)` for a reply that is not valid HTTP or ends early. The
        route adds `proxylib.NoReachableProxyError`,
        `proxylib.UnsupportedProxyError` and, for a setting that cannot be used,
        `ConfigurationError`."""
        method = check_method(method)
        target = check_url(url)
        pairs = check_headers(headers)
        connect_timeout, read_timeout = check_timeout(timeout)
        payload = _Payload(body, pairs)
        names = {name.lower() for name, _ in pairs}
        decode = wants_decoding(pairs)
        # As the server will see it: no fragment, "/" for an empty path.
        plain_url = f"{target.scheme}://{target.authority}{target.path}"
        scope = _pool.scope_id()
        route = self._route(target, plain_url, connect_timeout, scope)
        response = self._attempt(
            route, method, pairs, names, payload, connect_timeout, read_timeout, plain_url, decode, scope
        )
        return response if stream else response._buffered()

    def _plan(self, entry: "proxylib.Proxy | None", target: Target, plain_url: str) -> _Route:
        if entry is None:
            return _Route(target, None, None, (target.scheme, target.host, target.port, None))
        if entry.is_gateway:
            wire = check_url(entry.gateway_url(plain_url))
            return _Route(wire, None, entry, ("gateway", wire.scheme, wire.host, wire.port))
        peer = (entry.scheme, entry.host, _route.port(entry))
        return _Route(target, entry, None, (target.scheme, target.host, target.port, peer))

    def _route(self, target: Target, plain_url: str, connect_timeout, scope: int) -> _Route:
        """The route of a request: the first entry the proxy map answers whose
        proxy accepts a connection. One this thread already holds a connection
        to is known to answer, and is not probed again."""
        entries = _route.entries(self._proxymap, plain_url)
        first = self._plan(entries[0], target, plain_url)
        if entries[0] is None or self._pool.has_idle(first.key, scope):
            return first
        chosen = _route.reachable(entries, plain_url, connect_timeout)
        return first if chosen == entries[0] else self._plan(chosen, target, plain_url)

    def _attempt(
        self,
        route: _Route,
        method: str,
        pairs,
        names,
        payload: _Payload,
        connect_timeout,
        read_timeout,
        url: str,
        decode: bool,
        scope: int,
    ) -> HTTPResponse:
        repeatable = method in _IDEMPOTENT and payload.repeatable
        connection = self._pool.take(route.key, scope)
        if connection is not None and not repeatable and _now() - connection.released_at > REUSE_WINDOW:
            self._pool.discard(connection)
            connection = None
        if connection is not None and _unusable(connection.http.sock):
            self._pool.discard(connection)
            connection = None
        reused = connection is not None
        while True:
            if connection is None:
                connection = self._open(route, scope, connect_timeout, read_timeout)
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
                return self._exchange(connection, route, method, pairs, names, payload, url, decode, reused)
            except _Dropped as dropped:
                if reused and repeatable:
                    connection, reused = None, False
                    continue
                raise dropped.error from None

    def _headers(self, route: _Route, pairs, names, payload) -> "dict[str, str]":
        sent = dict(pairs)
        if payload.length is not None:
            sent["Content-Length"] = str(payload.length)
        if "host" not in names:
            sent["Host"] = route.wire.authority
        if "accept-encoding" not in names:
            sent["Accept-Encoding"] = "gzip, deflate"
        # What a proxy or gateway is given for itself rides on a request it
        # reads: not on one inside a tunnel.
        owner = route.gateway or (route.proxy if route.wire.scheme == "http" else None)
        if owner is not None:
            for name, value in _route.credentials(owner):
                if name.lower() not in names:
                    sent[name] = value
        return sent

    def _exchange(self, connection, route: _Route, method, pairs, names, payload, url, decode, reused) -> HTTPResponse:
        http = connection.http
        wire = route.wire
        line = f"http://{wire.authority}{wire.path}" if route.proxy is not None and wire.scheme == "http" else wire.path
        try:
            http.request(method, line, body=payload.value, headers=self._headers(route, pairs, names, payload))
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

    def _open(self, route: _Route, scope: int, connect_timeout, read_timeout):
        proxy, wire = route.proxy, route.wire
        host, port = (proxy.host, _route.port(proxy)) if proxy is not None else (wire.host, wire.port)
        try:
            raw = _socket.create_connection((host, port), timeout=connect_timeout)
        except (OSError, _client.HTTPException) as error:
            raise _failure(error) from None
        sock: _ty.Any = raw
        try:
            raw.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
            sock = self._layers(raw, route)
            sock.settimeout(read_timeout)
        except (OSError, _client.HTTPException) as error:
            sock.close()
            raise _failure(error) from None
        except BaseException:
            sock.close()
            raise
        http = _client.HTTPConnection(wire.host, wire.port)
        # A connection that was closed stays closed: `http.client` would
        # otherwise reconnect by itself, in plain TCP, outside the TLS session,
        # the proxy and the timeout this request was given.
        http.auto_open = 0
        http.response_class = _Reply
        http.sock = sock
        connection = _pool.Connection(http, route.key, scope, self._pool.generation)
        self._pool.register(connection)
        return connection

    def _layers(self, raw, route: _Route):
        """`raw`, connected to the first server of `route`, with the tunnel and
        the TLS the route needs on it. What it made is closed when a step fails."""
        proxy, wire = route.proxy, route.wire
        sock: _ty.Any = raw
        try:
            if proxy is not None and proxy.scheme == "https":
                sock = self._tls.proxy().wrap_socket(raw, server_hostname=proxy.host)
            if proxy is not None and wire.scheme == "https":
                self._tunnel(sock, wire, proxy)
                if proxy.scheme == "https":
                    # The origin's TLS cannot be wrapped around another TLS socket.
                    sock = TunneledTLS(sock, self._tls.origin(), wire.host)
                else:
                    sock = self._tls.origin().wrap_socket(sock, server_hostname=wire.host)
            elif route.gateway is not None:
                if wire.scheme == "https":
                    sock = self._tls.proxy().wrap_socket(raw, server_hostname=wire.host)
            elif wire.scheme == "https":
                sock = self._tls.origin().wrap_socket(raw, server_hostname=wire.host)
            return sock
        except BaseException:
            sock.close()
            raise

    @staticmethod
    def _tunnel(sock, target: Target, proxy: "proxylib.Proxy") -> None:
        """Asks the proxy to connect `sock` to the server (RFC 9110 9.3.6). Only
        what the proxy is configured with goes in the request."""
        authority = f"{bracket(target.host)}:{target.port}"
        lines = [f"CONNECT {authority} HTTP/1.1", f"Host: {authority}"]
        lines += [f"{name}: {value}" for name, value in _route.credentials(proxy)]
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
        reply = _client.HTTPResponse(sock, method="CONNECT")
        try:
            reply.begin()
            status = reply.status
        finally:
            reply.close()
        if not 200 <= status < 300:
            raise ConnectionRefusedError(_errno.ECONNREFUSED, f"the proxy refused CONNECT (HTTP {status})")

"""Loopback servers for the HTTP client, scripted at the byte level: an origin
that records what it receives and answers from a script, a proxy, and the test
certificate authority of tests/data. Nothing here leaves the loopback
interface."""

from __future__ import annotations

import pathlib
import select
import socket
import ssl
import threading
import time
import typing

CRLF = b"\r\n"


def wait_until(predicate, timeout: float = 15.0, interval: float = 0.02) -> bool:
    """Poll `predicate` until it is true or `timeout` seconds have passed;
    returns its last value. A test asserts the result: what must be true
    after the wait, not how long it took to get there."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return bool(predicate())


# How often a blocked accept() looks at the stop flag. Closing a listening
# socket from another thread does not wake an accept() on every platform
# (Linux leaves it blocked), so the accept loops never rely on it.
_POLL = 0.05


def _stop_listening(stop, thread, listener, sockets, lock):
    """Stop an accept loop and drop every connection it accepted."""
    stop.set()
    thread.join(timeout=10)  # a safety net: the loop sees the flag within _POLL
    try:
        listener.close()
    except OSError:
        pass
    with lock:
        accepted = list(sockets)
    for sock in accepted:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()


class Request(typing.NamedTuple):
    """One request as the server received it."""

    method: str
    target: str
    headers: "list[tuple[str, str]]"
    body: bytes
    connection: int  # which accepted connection carried it, from 0

    def header(self, name: str):
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None


class Reply(typing.NamedTuple):
    """Bytes to send, whether to close the connection after them, and bytes
    to send `delay` seconds later on the same connection."""

    raw: bytes
    close: bool = False
    later: bytes = b""
    delay: float = 0.0


class Drop:
    """Close the connection without answering."""


class Hang:
    """Never answer; the connection stays open until the server closes."""


def response(status=200, headers=None, body=b"", reason="OK", length=True) -> bytes:
    """A complete HTTP/1.1 response; `Content-Length` is added unless
    `length` is false or `headers` names one."""
    head = [f"HTTP/1.1 {status} {reason}"]
    names = {k.lower() for k in (headers or {})}
    for key, value in (headers or {}).items():
        head.append(f"{key}: {value}")
    if length and "content-length" not in names and "transfer-encoding" not in names:
        head.append(f"Content-Length: {len(body)}")
    return "\r\n".join(head).encode("latin-1") + CRLF + CRLF + body


def _read_until(sock, marker: bytes, limit=1 << 20, start: bytes = b"") -> "tuple[bytes, bytes] | None":
    data = start
    while marker not in data:
        chunk = sock.recv(65536)
        if not chunk:
            return None
        data += chunk
        if len(data) > limit:
            return None
    head, _, rest = data.partition(marker)
    return head, rest


def _read_exactly(sock, rest: bytes, count: int) -> bytes:
    while len(rest) < count:
        chunk = sock.recv(65536)
        if not chunk:
            break
        rest += chunk
    return rest


def _read_chunked(sock, rest: bytes) -> "tuple[bytes, bytes]":
    """The body, and the bytes that followed it on the connection."""
    body = b""
    while True:
        while CRLF not in rest:
            chunk = sock.recv(65536)
            if not chunk:
                return body, b""
            rest += chunk
        line, _, rest = rest.partition(CRLF)
        size = int(line.split(b";")[0], 16)
        rest = _read_exactly(sock, rest, size + 2)
        body += rest[:size]
        rest = rest[size + 2 :]
        if size == 0:
            return body, rest


class Wire:
    """An origin on a loopback port. `script(request)` returns what to send:
    `bytes`, a `Reply`, `Drop()` or `Hang()`; the default answers `200 ok`.
    `requests` lists what was received, `connections` how many connections
    were accepted, and `closed` the connections the client closed. With `tls`
    (an `ssl.SSLContext`) every connection is wrapped by the server first."""

    def __init__(self, script=None, tls: "ssl.SSLContext | None" = None):
        self.script = script or (lambda request: response(body=b"ok"))
        self.tls = tls
        self.requests: "list[Request]" = []
        self._connections = 0
        self._taking = threading.Lock()
        self.closed: "list[int]" = []
        self.handshakes_failed = 0
        self._lock = threading.Lock()
        self._sockets: "list[socket.socket]" = []
        self._stop = threading.Event()
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._listener.setblocking(False)
        self.port = self._listener.getsockname()[1]
        self.host = "127.0.0.1"
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        return f"{'https' if self.tls else 'http'}://127.0.0.1:{self.port}"

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()

    def close(self):
        _stop_listening(self._stop, self._thread, self._listener, self._sockets, self._lock)

    @property
    def connections(self) -> int:
        """How many connections the client has made. A connection waiting in
        the kernel's queue is taken first, so a test asking "was one made?"
        does not depend on the accept thread having run."""
        self._take()
        return self._connections

    def _accept(self):
        while not self._stop.is_set():
            try:
                select.select([self._listener], [], [], _POLL)
            except (OSError, ValueError):
                return
            self._take()

    def _take(self):
        """Accept every connection that is waiting, and start serving it."""
        with self._taking:
            while True:
                try:
                    sock, _ = self._listener.accept()
                except OSError:  # nothing waiting, or the listener is closed
                    return
                sock.setblocking(True)
                with self._lock:
                    index = self._connections
                    self._connections += 1
                    self._sockets.append(sock)
                threading.Thread(target=self._serve, args=(sock, index), daemon=True).start()

    def _serve(self, sock, index):
        try:
            if self.tls is not None:
                try:
                    sock = self.tls.wrap_socket(sock, server_side=True)
                except (OSError, ssl.SSLError):
                    with self._lock:
                        self.handshakes_failed += 1
                    return
                with self._lock:
                    self._sockets.append(sock)
            carry = b""  # what the client sent beyond the request just read
            while not self._stop.is_set():
                parsed = _read_until(sock, CRLF + CRLF, start=carry)
                if parsed is None:
                    return
                head, rest = parsed
                lines = head.decode("latin-1").split("\r\n")
                method, target, _version = lines[0].split(" ", 2)
                headers = [tuple(line.split(":", 1)) for line in lines[1:]]
                headers = [(k, v.strip()) for k, v in headers]
                length = next((int(v) for k, v in headers if k.lower() == "content-length"), 0)
                chunked = any(k.lower() == "transfer-encoding" and "chunked" in v.lower() for k, v in headers)
                if chunked:
                    body, carry = _read_chunked(sock, rest)
                else:
                    data = _read_exactly(sock, rest, length)
                    body, carry = data[:length], data[length:]
                request = Request(method, target, headers, body, index)
                with self._lock:
                    self.requests.append(request)
                action = self.script(request)
                if isinstance(action, Drop):
                    return
                if isinstance(action, Hang):
                    self._stop.wait(30)
                    return
                if isinstance(action, bytes):
                    action = Reply(action)
                sock.sendall(action.raw)
                if action.later:
                    time.sleep(action.delay)
                    sock.sendall(action.later)
                if action.close:
                    return
        except (OSError, ssl.SSLError, ValueError):
            # A request line that does not parse, as after bytes the client
            # should not have sent, ends the connection as a server would.
            return
        finally:
            with self._lock:
                self.closed.append(index)
            try:
                sock.close()
            except OSError:
                pass


class Proxy:
    """An HTTP proxy on a loopback port. A request in absolute form is
    answered by `script(request)` as an origin would; `CONNECT host:port` is
    answered `200` and then relayed to `upstream` (a `(host, port)`), whatever
    the host asked for, or refused with `refuse` (a status) when given.
    `requests` lists what it received, `CONNECT`s included."""

    def __init__(self, script=None, upstream=None, refuse=None):
        self.script = script or (lambda request: response(body=b"via proxy"))
        self.upstream = upstream
        self.refuse = refuse
        self.requests: "list[Request]" = []
        self._lock = threading.Lock()
        self._sockets: "list[socket.socket]" = []
        self._stop = threading.Event()
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._listener.settimeout(_POLL)
        self.port = self._listener.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()

    def close(self):
        _stop_listening(self._stop, self._thread, self._listener, self._sockets, self._lock)

    def _accept(self):
        while not self._stop.is_set():
            try:
                sock, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            sock.settimeout(None)
            with self._lock:
                self._sockets.append(sock)
            threading.Thread(target=self._serve, args=(sock,), daemon=True).start()

    def _serve(self, sock):
        try:
            while not self._stop.is_set():
                parsed = _read_until(sock, CRLF + CRLF)
                if parsed is None:
                    return
                head, rest = parsed
                lines = head.decode("latin-1").split("\r\n")
                method, target, _version = lines[0].split(" ", 2)
                headers = [(k, v.strip()) for k, v in (l.split(":", 1) for l in lines[1:])]
                length = next((int(v) for k, v in headers if k.lower() == "content-length"), 0)
                body = _read_exactly(sock, rest, length)[:length]
                request = Request(method, target, headers, body, 0)
                with self._lock:
                    self.requests.append(request)
                if method == "CONNECT":
                    if self.refuse:
                        sock.sendall(response(self.refuse, reason="Refused"))
                        return
                    self._tunnel(sock)
                    return
                action = self.script(request)
                if isinstance(action, Drop):
                    return
                if isinstance(action, bytes):
                    action = Reply(action)
                sock.sendall(action.raw)
                if action.close:
                    return
        except OSError:
            return
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _tunnel(self, client):
        upstream = socket.create_connection(self.upstream)
        with self._lock:
            self._sockets.append(upstream)
        client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

        def pump(source, sink):
            try:
                while True:
                    data = source.recv(65536)
                    if not data:
                        break
                    sink.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    sink.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        thread = threading.Thread(target=pump, args=(upstream, client), daemon=True)
        thread.start()
        pump(client, upstream)
        # The client is gone, so nobody reads the upstream's side any more;
        # shutting it wakes the other pump however the origin behaves.
        try:
            upstream.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        thread.join(timeout=10)
        upstream.close()


def refusing_port() -> int:
    """A loopback port nothing listens on."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


DATA = pathlib.Path(__file__).parent / "data"


class Authority(typing.NamedTuple):
    """The test certificate authority of tests/data and the server certificate
    it signed, which names `localhost` and `127.0.0.1`."""

    ca_file: str
    cert_file: str
    key_file: str

    def server_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert_file, self.key_file)
        return context

    def client_context(self) -> ssl.SSLContext:
        return ssl.create_default_context(cafile=self.ca_file)


def loopback_authority() -> Authority:
    return Authority(str(DATA / "ca.pem"), str(DATA / "server.pem"), str(DATA / "server.key"))

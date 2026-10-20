"""TLS inside TLS: an https origin reached through an https proxy.

`ssl` wraps a plain socket only, so the inner session runs on memory buffers
and this object moves its bytes over the already encrypted connection to the
proxy."""

from __future__ import annotations

import io as _io
import socket as _socket
import ssl as _ssl
import typing as _ty

_BLOCK = 16384


class TunneledTLS:
    """The socket `http.client` needs (`sendall`, `makefile("rb")`, `settimeout`,
    `shutdown`, `close`, `fileno`, `pending`) for a TLS session whose bytes
    travel over `outer`, a connected `ssl.SSLSocket` to the proxy that has
    already carried the `CONNECT`. Closing it closes `outer`.

    The handshake runs on construction, with `context.wrap_bio()`, so a
    context that verifies the chain (the system's included) does so here."""

    def __init__(self, outer: "_ssl.SSLSocket", context: "_ssl.SSLContext", server_hostname: str):
        self._outer = outer
        self._incoming = _ssl.MemoryBIO()
        self._outgoing = _ssl.MemoryBIO()
        self._inner = context.wrap_bio(self._incoming, self._outgoing, server_hostname=server_hostname)
        self._io_refs = 0
        self._closed = False
        self._run(self._inner.do_handshake)

    def _run(self, call: "_ty.Callable[..., _ty.Any]", *args: _ty.Any) -> _ty.Any:
        """`call(*args)` on the inner session, moving bytes between its buffers
        and `outer` until it neither wants to read nor to write."""
        while True:
            wants_read = wants_write = False
            result = None
            try:
                result = call(*args)
            except _ssl.SSLWantReadError:
                wants_read = True
            except _ssl.SSLWantWriteError:
                wants_write = True
            produced = self._outgoing.read()
            if produced:
                self._outer.sendall(produced)
            if not (wants_read or wants_write):
                return result
            if wants_read:
                received = self._outer.recv(_BLOCK)
                if received:
                    self._incoming.write(received)
                else:
                    self._incoming.write_eof()

    def recv_into(self, buffer, nbytes: "int | None" = None) -> int:
        if nbytes is None:
            nbytes = len(buffer)
        try:
            return self._run(self._inner.read, nbytes, buffer)
        except (_ssl.SSLZeroReturnError, _ssl.SSLEOFError):
            return 0  # the peer ended the session, with or without close_notify

    def recv(self, size: int = _BLOCK, flags: int = 0) -> bytes:
        buffer = bytearray(size)
        return bytes(buffer[: self.recv_into(buffer)])

    def sendall(self, data, flags: int = 0) -> None:
        view = memoryview(data).cast("B")
        while view:
            sent = self._run(self._inner.write, view[:_BLOCK])
            view = view[sent:]

    def send(self, data, flags: int = 0) -> int:
        return self._run(self._inner.write, memoryview(data).cast("B")[:_BLOCK])

    def makefile(self, mode: str = "rb", buffering: "int | None" = None, **kwargs: _ty.Any):
        """A buffered binary reader over `recv_into`, as `socket.makefile`
        gives. Nothing else is read from a tunnelled session."""
        if mode != "rb":
            raise ValueError("a tunnelled TLS session is read as bytes: makefile('rb')")
        raw = _socket.SocketIO(self, "r")  # type: ignore[arg-type]
        self._io_refs += 1
        size = _io.DEFAULT_BUFFER_SIZE if buffering is None or buffering < 0 else buffering
        return raw if size == 0 else _io.BufferedReader(raw, size)

    def _decref_socketios(self) -> None:
        if self._io_refs > 0:
            self._io_refs -= 1
        if self._closed:
            self._outer.close()

    def pending(self) -> int:
        return self._inner.pending() + (self._outer.pending() or 0)

    def fileno(self) -> int:
        return self._outer.fileno()

    def settimeout(self, value: "float | None") -> None:
        self._outer.settimeout(value)

    def gettimeout(self) -> "float | None":
        return self._outer.gettimeout()

    def shutdown(self, how: int) -> None:
        self._outer.shutdown(how)

    def close(self) -> None:
        self._closed = True
        if self._io_refs <= 0:
            self._outer.close()

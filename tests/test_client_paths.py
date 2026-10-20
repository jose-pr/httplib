"""The client's riskier network paths, over loopback: an https origin through
a real CONNECT tunnel, and through an https:// proxy that demands a client
certificate (the origin's TLS runs inside the proxy's)."""

import select
import socket
import socketserver
import ssl
import threading

import pytest

from syshttp.client import HTTPClient  # noqa: E402
from syshttp.env import HTTPEnv  # noqa: E402
from test_client_tls import DATA, _client, mtls_server  # noqa: E402,F401  (fixture reused)

BEARER = "Bearer s3cret"


class _Tunnel(socketserver.BaseRequestHandler):
    """A forward proxy that answers ``CONNECT`` after checking the credential,
    then relays bytes to the target."""

    seen = []

    def handle(self):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        lines = data.split(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
        method, target, _ = lines[0].split(" ")
        headers = dict(line.split(": ", 1) for line in lines[1:])
        type(self).seen.append((method, target, headers.get("Proxy-Authorization")))
        if method != "CONNECT" or headers.get("Proxy-Authorization") != BEARER:
            self.request.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            return
        host, _, port = target.rpartition(":")
        upstream = socket.create_connection((host, int(port)), timeout=10)
        try:
            self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            sockets = [self.request, upstream]
            while True:
                # A TLS socket may hold decrypted bytes select() cannot see.
                ready = [sock for sock in sockets if isinstance(sock, ssl.SSLSocket) and sock.pending()]
                if not ready:
                    ready, _, _ = select.select(sockets, [], [], 10)
                if not ready:
                    return
                for sock in ready:
                    chunk = sock.recv(65536)
                    if not chunk:
                        return
                    (upstream if sock is self.request else self.request).sendall(chunk)
        finally:
            upstream.close()


class _TunnelServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    context = None  # set: the proxy itself speaks TLS

    def handle_error(self, request, client_address):
        pass  # a refused handshake is part of the tests, not noise

    def get_request(self):
        sock, address = super().get_request()
        if self.context is not None:
            sock = self.context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
        return sock, address


@pytest.fixture()
def tunnel():
    handler = type("Tunnel", (_Tunnel,), {"seen": []})
    server = _TunnelServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    handler.url = "http://127.0.0.1:%d" % server.server_address[1]
    try:
        yield handler
    finally:
        server.shutdown()
        server.server_close()


def test_an_https_origin_is_reached_through_a_connect_tunnel_with_the_credential(mtls_server, tunnel):  # noqa: F811
    env = HTTPEnv(environ={"SYSHTTP_PROXY": tunnel.url, "SYSHTTP_PROXY_AUTH": BEARER})
    with HTTPClient(ssl_context=_client(), env=env) as client:
        response = client.request("GET", mtls_server, timeout=10)
    assert response.text().split()[0] == "client-rsa", "the origin saw the client identity through the tunnel"
    origin = mtls_server.split("//")[1].rstrip("/")
    assert tunnel.seen == [("CONNECT", origin, BEARER)]


def test_the_tunnel_refuses_a_request_without_the_credential(mtls_server, tunnel):  # noqa: F811
    env = HTTPEnv(environ={"SYSHTTP_PROXY": tunnel.url})
    with HTTPClient(ssl_context=_client(), env=env) as client:
        with pytest.raises(ConnectionError, match="407"):
            client.request("GET", mtls_server, timeout=10)
    assert tunnel.seen and tunnel.seen[0][2] is None


@pytest.fixture()
def secure_tunnel():
    """A CONNECT proxy reached over TLS that demands a client certificate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(DATA / "server.pem", DATA / "server.key")
    context.load_verify_locations(DATA / "ca.pem")
    context.verify_mode = ssl.CERT_REQUIRED
    handler = type("Tunnel", (_Tunnel,), {"seen": []})
    server = _TunnelServer(("127.0.0.1", 0), handler)
    server.context = context
    threading.Thread(target=server.serve_forever, daemon=True).start()
    handler.url = "https://127.0.0.1:%d" % server.server_address[1]
    try:
        yield handler
    finally:
        server.shutdown()
        server.server_close()


def test_an_https_proxy_is_spoken_to_with_the_proxy_context(mtls_server, secure_tunnel):  # noqa: F811
    env = HTTPEnv(environ={"SYSHTTP_PROXY": secure_tunnel.url, "SYSHTTP_PROXY_AUTH": BEARER})
    origin = _client()
    with HTTPClient(ssl_context=origin, proxy_ssl_context=_client(), env=env) as client:
        ok = client.request("GET", mtls_server, timeout=10)
        again = client.request("GET", mtls_server, timeout=10)
    assert ok.text().split()[0] == "client-rsa" and again.status == 200
    assert len(secure_tunnel.seen) == 1, "the second request used the tunnel it had"
    with HTTPClient(ssl_context=origin, proxy_ssl_context=_client(identity=False), env=env) as client:
        with pytest.raises((ssl.SSLError, ConnectionError)):
            client.request("GET", mtls_server, timeout=10)

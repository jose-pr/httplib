"""The session's riskier network paths, over loopback: an https origin through
a real CONNECT tunnel, an https:// proxy that demands a client certificate, a
redirect to another host that must not carry the token, and the message when
requests is not installed."""

import select
import socket
import socketserver
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytest.importorskip("requests")

from syshttp.env import HTTPEnv  # noqa: E402
from syshttp.jar import MemoryTokenJar  # noqa: E402
from syshttp.session import new_session  # noqa: E402
from test_ssl_context import DATA, _client, mtls_server  # noqa: E402,F401  (fixture reused)

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
    response = new_session(retries=0, ssl_context=_client(), env=env).get(mtls_server, timeout=10)
    assert response.text.split()[0] == "client-rsa", "the origin saw the client identity through the tunnel"
    origin = mtls_server.split("//")[1].rstrip("/")
    assert tunnel.seen == [("CONNECT", origin, BEARER)]


def test_the_tunnel_refuses_a_request_without_the_credential(mtls_server, tunnel):  # noqa: F811
    import requests

    env = HTTPEnv(environ={"SYSHTTP_PROXY": tunnel.url})
    with pytest.raises(requests.exceptions.ProxyError):
        new_session(retries=0, ssl_context=_client(), env=env).get(mtls_server, timeout=10)
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
    import requests

    env = HTTPEnv(environ={"SYSHTTP_PROXY": secure_tunnel.url, "SYSHTTP_PROXY_AUTH": BEARER})
    origin = _client()
    with new_session(retries=0, ssl_context=origin, proxy_ssl_context=_client(), env=env) as session:
        ok = session.get(mtls_server, timeout=10)
    assert ok.text.split()[0] == "client-rsa" and len(secure_tunnel.seen) == 1
    with new_session(retries=0, ssl_context=origin, proxy_ssl_context=_client(identity=False), env=env) as session:
        with pytest.raises(requests.exceptions.RequestException):
            session.get(mtls_server, timeout=10)


class _Hop(BaseHTTPRequestHandler):
    redirect_to = None
    seen = []

    def do_GET(self):
        type(self).seen.append(self.headers.get("Authorization"))
        if type(self).redirect_to:
            self.send_response(302)
            self.send_header("Location", type(self).redirect_to)
            self.send_header("Content-Length", "0")
        else:
            self.send_response(200)
            self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


def _serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_a_redirect_to_another_host_does_not_carry_the_token():
    first = type("First", (_Hop,), {"seen": []})
    last = type("Last", (_Hop,), {"seen": [], "redirect_to": None})
    final, start = _serve(last), None
    try:
        first.redirect_to = "http://localhost:%d/final" % final.server_address[1]
        start = _serve(first)
        session = new_session(tokens=MemoryTokenJar({"127.0.0.1": "tok"}), retries=0, env=HTTPEnv(environ={}))
        response = session.get("http://127.0.0.1:%d/" % start.server_address[1], timeout=10)
        assert response.status_code == 200 and [r.status_code for r in response.history] == [302]
        assert first.seen == ["Bearer tok"], "the origin the token is for gets it"
        assert last.seen == [None], "the other host does not"
    finally:
        final.shutdown()
        final.server_close()
        if start is not None:
            start.shutdown()
            start.server_close()


def test_without_requests_new_session_says_what_to_install(monkeypatch):
    monkeypatch.setitem(sys.modules, "requests", None)
    with pytest.raises(ImportError, match=r"pip install 'syshttp\[session\]'"):
        new_session()

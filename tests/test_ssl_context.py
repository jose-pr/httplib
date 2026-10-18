"""A caller's ssl.SSLContext: mutual TLS, a pinned protocol version, and a
context that comes back exactly as it was given.

The server is a loopback HTTPS server that requires a client certificate from
the test CA in tests/data (test material, never real credentials) and answers
with the client certificate's common name and the protocol version."""

import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

pytest.importorskip("requests")

from syshttp.session import new_session  # noqa: E402  (after the importorskip)

DATA = Path(__file__).parent / "data"


class _WhoAmI(BaseHTTPRequestHandler):
    def do_GET(self):
        peer = self.connection.getpeercert() or {}
        cn = next((v for rdn in peer.get("subject", ()) for k, v in rdn if k == "commonName"), "")
        body = ("%s %s" % (cn, self.connection.version())).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture()
def mtls_server():
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(DATA / "server.pem", DATA / "server.key")
    server_ctx.load_verify_locations(DATA / "ca.pem")
    server_ctx.verify_mode = ssl.CERT_REQUIRED
    httpd = HTTPServer(("127.0.0.1", 0), _WhoAmI)
    httpd.socket = server_ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield "https://127.0.0.1:%d/" % httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def _client(identity=True):
    ctx = ssl.create_default_context(cafile=str(DATA / "ca.pem"))
    if identity:
        ctx.load_cert_chain(DATA / "client-rsa.pem", DATA / "client-rsa.key")
    return ctx


def test_the_callers_context_presents_its_client_certificate(mtls_server):
    resp = new_session(retries=0, ssl_context=_client()).get(mtls_server, timeout=5)
    assert resp.status_code == 200 and resp.text.split()[0] == "client-rsa"


def test_without_a_client_certificate_the_server_refuses(mtls_server):
    import requests

    with pytest.raises(requests.exceptions.ConnectionError):
        new_session(retries=0, ssl_context=_client(identity=False)).get(mtls_server, timeout=5)


def test_the_contexts_own_settings_reach_the_handshake(mtls_server):
    ctx = _client()
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    resp = new_session(retries=0, ssl_context=ctx).get(mtls_server, timeout=5)
    assert resp.text == "client-rsa TLSv1.2"


def test_the_context_comes_back_unchanged(mtls_server):
    ctx = _client()
    before = (ctx.verify_mode, ctx.check_hostname)
    new_session(retries=0, ssl_context=ctx).get(mtls_server, timeout=5)
    assert (ctx.verify_mode, ctx.check_hostname) == before


def test_the_os_trust_store_does_not_know_the_test_ca(mtls_server):
    """Without the caller's context the session verifies against the OS
    store, which does not trust the test CA: the context is what made the
    other tests pass."""
    import requests

    with pytest.raises(requests.exceptions.SSLError):
        new_session(retries=0).get(mtls_server, timeout=5)


def test_verify_and_a_context_contradict():
    with pytest.raises(ValueError, match="ssl_context"):
        new_session(ssl_context=_client(), verify=False)
    with pytest.raises(TypeError, match="ssl.SSLContext"):
        new_session(ssl_context="ca.pem")


def test_an_https_proxy_is_spoken_to_with_the_proxy_context():
    proxy_ctx = _client()
    adapter = new_session(proxy_ssl_context=proxy_ctx).get_adapter("https://h/")
    assert adapter.proxy_manager_for("https://proxy.example:8443").proxy_ssl_context is proxy_ctx
    assert getattr(adapter.proxy_manager_for("http://proxy.example:3128"), "proxy_ssl_context", None) is None

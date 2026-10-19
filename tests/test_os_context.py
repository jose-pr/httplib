"""syshttp.tls's default context is sslcontext's system context: a server
that asks for a client certificate gets one from the OS store, unless the
caller turned that off to load a certificate of its own.

The OS store is replaced by one test identity (tests/data, test material
only), and the trust by the test CA, by wrapping ``sslcontext.system_context``;
what syshttp asked for is what decides the handshake."""

import ssl
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import sslcontext
from sslcontext.testing import software_identity

from syshttp import tls as syshttp_tls

DATA = Path(__file__).parent / "data"


class _WhoAmI(BaseHTTPRequestHandler):
    def do_GET(self):
        peer = self.connection.getpeercert() or {}
        cn = next((v for rdn in peer.get("subject", ()) for k, v in rdn if k == "commonName"), "")
        body = cn.encode()
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
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield "https://127.0.0.1:%d/" % httpd.server_address[1]
    finally:
        httpd.shutdown()
        thread.join()
        httpd.server_close()


@pytest.fixture()
def store_with_one_identity(monkeypatch):
    """``sslcontext.system_context`` trusting the test CA, its default
    selector offering the test client identity as the OS store would."""
    real = sslcontext.system_context
    identity = software_identity((DATA / "client-rsa.pem").read_bytes(), (DATA / "client-rsa.key").read_bytes())
    asked = []

    def system_context(*, selector=None, **kwargs):
        asked.append(selector)
        if selector is None:
            selector = sslcontext.ClientCertificateSelector([identity], choose=lambda request, found: found[0])
        return real(selector=selector, cafile=str(DATA / "ca.pem"), **kwargs)

    monkeypatch.setattr(sslcontext, "system_context", system_context)
    return asked


def _get(url, ctx):
    with urllib.request.urlopen(url, context=ctx, timeout=5) as resp:
        return resp.read().decode()


def test_a_server_asking_for_a_certificate_gets_one_from_the_store(mtls_server, store_with_one_identity):
    assert _get(mtls_server, syshttp_tls.new_os_context()) == "client-rsa"
    assert store_with_one_identity == [None], "sslcontext's default selector, not one of syshttp's"


def test_client_certificates_off_offers_none(mtls_server, store_with_one_identity):
    with pytest.raises((urllib.error.URLError, ssl.SSLError, ConnectionError)):
        _get(mtls_server, syshttp_tls.new_os_context(client_certificates=False))
    assert store_with_one_identity == [False]


def test_a_ca_file_replaces_the_system_context(store_with_one_identity):
    ctx = syshttp_tls.new_os_context(cafile=str(DATA / "ca.pem"))
    assert type(ctx) is ssl.SSLContext and store_with_one_identity == []

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


# -- client certificates and per-request verify -----------------------------


@pytest.fixture()
def trusting_os_context(monkeypatch):
    """The shared OS context, and the one built for a ``cert=``, replaced by
    plain contexts that trust the test CA (the real ones cannot, and on 3.10+
    the OS verifies). ``loaded`` records every context a certificate chain is
    loaded into."""
    from syshttp import session as session_module
    from syshttp import tls

    loaded = []
    real = ssl.SSLContext.load_cert_chain

    def spy(self, *args, **kwargs):
        loaded.append(self)
        return real(self, *args, **kwargs)

    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", spy)
    shared = _client(identity=False)
    loaded.clear()
    monkeypatch.setattr(tls, "_os_context", shared)
    monkeypatch.setattr(tls, "_os_context_at", __import__("time").monotonic())
    monkeypatch.setattr(session_module, "new_os_context", lambda *a, **k: _client(identity=False), raising=False)
    return shared, loaded


CERT = (str(DATA / "client-rsa.pem"), str(DATA / "client-rsa.key"))


def test_a_cert_argument_never_reaches_the_shared_context(mtls_server, trusting_os_context):
    import requests

    shared, loaded = trusting_os_context
    resp = new_session(retries=0).get(mtls_server, cert=CERT, timeout=5)
    assert resp.text.split()[0] == "client-rsa"
    assert shared not in loaded, "the certificate went into the context every session shares"
    with pytest.raises(requests.exceptions.RequestException):
        new_session(retries=0).get(mtls_server, timeout=5)


def test_a_cert_argument_beside_the_callers_context_is_refused(mtls_server):
    import requests

    ctx = _client(identity=False)
    session = new_session(retries=0, ssl_context=ctx)
    with pytest.raises(ValueError, match="load the client certificate into the ssl_context"):
        session.get(mtls_server, cert=CERT, timeout=5)
    with pytest.raises(requests.exceptions.RequestException):
        new_session(retries=0, ssl_context=ctx).get(mtls_server, timeout=5)


@pytest.mark.parametrize("verify", [False, str(DATA / "ca.pem")])
def test_a_per_request_verify_beside_the_callers_context_is_refused(mtls_server, verify):
    session = new_session(retries=0, ssl_context=_client())
    with pytest.raises(ValueError, match="ssl_context"):
        session.get(mtls_server, verify=verify, timeout=5)


@pytest.mark.parametrize("variable", ["CA_BUNDLE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"])
def test_a_bundle_from_the_environment_is_not_a_per_request_verify(mtls_server, monkeypatch, variable):
    monkeypatch.setenv(variable, str(DATA / "ca.pem"))
    resp = new_session(retries=0, ssl_context=_client()).get(mtls_server, timeout=5)
    assert resp.status_code == 200


def test_ca_bundle_is_read_through_the_prefixes_and_requests_own_variables_are_not(monkeypatch):
    from syshttp import HTTPEnv

    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/requests.pem")
    monkeypatch.setenv("CURL_CA_BUNDLE", "/curl.pem")

    def verify(session, asked=True):
        return session.merge_environment_settings("https://h/", {}, None, asked, None)["verify"]

    assert verify(new_session()) is True
    environ = {"APP_CA_BUNDLE": "/app.pem", "CA_BUNDLE": "/default.pem"}
    assert verify(new_session(env=HTTPEnv("APP_:", environ=environ))) == "/app.pem"
    assert verify(new_session(env=HTTPEnv(environ=environ))) == "/default.pem"
    assert verify(new_session(env=HTTPEnv(environ=environ)), asked=False) is False
    assert verify(new_session(env=HTTPEnv(environ=environ)), asked="/mine.pem") == "/mine.pem"
    assert verify(new_session(env=HTTPEnv(environ=environ), verify="/session.pem"), asked=None) == "/session.pem"


def test_the_fetch_helpers_refuse_a_verify_beside_the_callers_context(mtls_server):
    from syshttp.fetch import request_text

    session = new_session(retries=0, ssl_context=_client())
    with pytest.raises(ValueError, match="ssl_context"):
        request_text(session, "GET", mtls_server, verify=False)

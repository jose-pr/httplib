"""The client's TLS: the system's verifier by default, a CA bundle from the
`CA_BUNDLE` setting or `verify=`, the caller's `ssl.SSLContext` used as given
(mutual TLS, a pinned protocol version), and a context of its own for an
`https://` proxy or gateway.

The server is a loopback HTTPS server that requires a client certificate from
the test CA in tests/data (test material, never real credentials) and answers
with the client certificate's common name and the protocol version."""

import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import sslcontext
from sslcontext.testing import software_identity

from syshttp import HTTPEnv
from syshttp import tls as syshttp_tls
from syshttp.client import HTTPClient
from syshttp.exceptions import ConfigurationError, SysHTTPError

DATA = Path(__file__).parent / "data"
CA = str(DATA / "ca.pem")


class _WhoAmI(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

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
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _WhoAmI)
    httpd.socket = server_ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield "https://127.0.0.1:%d/" % httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def _client(identity=True):
    ctx = ssl.create_default_context(cafile=CA)
    if identity:
        ctx.load_cert_chain(DATA / "client-rsa.pem", DATA / "client-rsa.key")
    return ctx


def fetch(client, url):
    with client:
        return client.request("GET", url, timeout=5)


# -- the caller's context ---------------------------------------------------


def test_the_callers_context_presents_its_client_certificate(mtls_server):
    resp = fetch(HTTPClient(ssl_context=_client()), mtls_server)
    assert resp.status == 200 and resp.text().split()[0] == "client-rsa"


def test_without_a_client_certificate_the_server_refuses(mtls_server):
    with pytest.raises((ssl.SSLError, ConnectionError)):
        fetch(HTTPClient(ssl_context=_client(identity=False)), mtls_server)


def test_the_contexts_own_settings_reach_the_handshake(mtls_server):
    ctx = _client()
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    assert fetch(HTTPClient(ssl_context=ctx), mtls_server).text() == "client-rsa TLSv1.2"


def test_the_context_comes_back_unchanged(mtls_server):
    ctx = _client()
    before = (ctx.verify_mode, ctx.check_hostname)
    fetch(HTTPClient(ssl_context=ctx), mtls_server)
    assert (ctx.verify_mode, ctx.check_hostname) == before


def test_the_os_trust_store_does_not_know_the_test_ca(mtls_server):
    """Without the caller's context the client verifies against the OS
    store, which does not trust the test CA: the context is what made the
    other tests pass."""
    with pytest.raises(ssl.SSLCertVerificationError):
        fetch(HTTPClient(), mtls_server)


def test_verify_and_a_context_contradict():
    with pytest.raises(ValueError, match="ssl_context") as caught:
        HTTPClient(ssl_context=_client(), verify=False)
    assert not isinstance(caught.value, SysHTTPError)
    with pytest.raises(ValueError, match="ssl_context"):
        HTTPClient(ssl_context=_client(), verify=CA)
    with pytest.raises(TypeError, match="ssl.SSLContext"):
        HTTPClient(ssl_context="ca.pem")
    with pytest.raises(TypeError, match="ssl.SSLContext"):
        HTTPClient(proxy_ssl_context="ca.pem")
    with pytest.raises(TypeError, match="verify"):
        HTTPClient(verify=1.5)


# -- verification off, and a CA bundle ------------------------------------------


def test_verify_false_accepts_any_certificate(tls_server):
    assert fetch(HTTPClient(verify=False), tls_server).text() == "ok"


@pytest.mark.parametrize("variable", ["REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"])
def test_requests_own_bundle_variables_are_not_read(mtls_server, monkeypatch, variable):
    monkeypatch.setenv(variable, CA)
    with pytest.raises(ssl.SSLCertVerificationError):
        fetch(HTTPClient(), mtls_server)


def test_a_bundle_from_the_environment_is_ignored_beside_the_callers_context(mtls_server, monkeypatch):
    monkeypatch.setenv("CA_BUNDLE", "/nowhere/ca.pem")
    assert fetch(HTTPClient(ssl_context=_client()), mtls_server).status == 200


class _Plain(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


@pytest.fixture()
def tls_server():
    """A loopback HTTPS server that asks for no client certificate."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(DATA / "server.pem", DATA / "server.key")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Plain)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield "https://127.0.0.1:%d/" % httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_a_bundle_named_by_the_setting_is_trusted(tls_server):
    env = HTTPEnv(environ={"CA_BUNDLE": CA})
    assert fetch(HTTPClient(env=env), tls_server).text() == "ok"


def test_the_setting_is_read_through_the_prefixes_first_one_first(tls_server):
    environ = {"APP_CA_BUNDLE": CA, "CA_BUNDLE": "/nowhere/ca.pem"}
    assert fetch(HTTPClient(env=HTTPEnv("APP_:", environ=environ)), tls_server).text() == "ok"
    with pytest.raises(ConfigurationError, match=r"\bCA_BUNDLE\b"):
        fetch(HTTPClient(env=HTTPEnv(environ=environ)), tls_server)


def test_the_setting_is_read_at_each_connection(tls_server):
    environ = {}
    client = HTTPClient(env=HTTPEnv(environ=environ))
    with client:
        with pytest.raises(ssl.SSLCertVerificationError):
            client.request("GET", tls_server, timeout=5)
        environ["CA_BUNDLE"] = CA
        assert client.request("GET", tls_server, timeout=5).text() == "ok"


def test_verify_names_a_bundle_and_beats_the_setting(tls_server):
    env = HTTPEnv(environ={"CA_BUNDLE": "/nowhere/ca.pem"})
    assert fetch(HTTPClient(env=env, verify=CA), tls_server).text() == "ok"
    assert fetch(HTTPClient(env=env, verify=Path(CA)), tls_server).text() == "ok"


def test_a_bundle_that_cannot_be_read_is_a_configuration_error_naming_where_it_came_from(tls_server, tmp_path):
    broken = tmp_path / "broken.pem"
    broken.write_text("not a certificate", encoding="ascii")
    for env, name in ((HTTPEnv(environ={"CA_BUNDLE": str(broken)}), "CA_BUNDLE"), (HTTPEnv(environ={}), "verify")):
        client = HTTPClient(env=env, verify=str(broken) if name == "verify" else True)
        with pytest.raises(ConfigurationError, match=name):
            fetch(client, tls_server)


def test_a_bundle_is_reloaded_when_the_file_changes(tls_server, tmp_path):
    bundle = tmp_path / "ca.pem"
    bundle.write_text((DATA / "ca.pem").read_text(encoding="ascii"), encoding="ascii")
    env = HTTPEnv(environ={"CA_BUNDLE": str(bundle)})
    client = HTTPClient(env=env)
    with client:
        assert client.request("GET", tls_server, timeout=5).text() == "ok"
        client.transport.close()  # connections are made again
        bundle.write_text("", encoding="ascii")
        os.utime(bundle, (1, 1))
        with pytest.raises((ConfigurationError, ssl.SSLError)):
            client.request("GET", tls_server, timeout=5)


# -- the system's context ------------------------------------------------------


@pytest.fixture()
def store_with_one_identity(monkeypatch):
    """``sslcontext.system_context`` trusting the test CA and offering the test
    client identity from its store, as the OS would."""
    real = sslcontext.system_context
    identity = software_identity((DATA / "client-rsa.pem").read_bytes(), (DATA / "client-rsa.key").read_bytes())

    def system_context(*, selector=None, **kwargs):
        if selector is None:
            selector = sslcontext.ClientCertificateSelector([identity], choose=lambda request, found: found[0])
        return real(selector=selector, cafile=CA, **kwargs)

    monkeypatch.setattr(sslcontext, "system_context", system_context)
    monkeypatch.setattr("syshttp.tls._os_context", None)


def test_the_default_verifies_with_the_system_context_and_offers_its_certificate(mtls_server, store_with_one_identity):
    assert fetch(HTTPClient(), mtls_server).text().split()[0] == "client-rsa"


def test_the_os_context_is_shared_then_renewed(monkeypatch):
    first = syshttp_tls.os_ssl_context()
    assert isinstance(first, ssl.SSLContext) and first.verify_mode == ssl.CERT_REQUIRED
    assert syshttp_tls.os_ssl_context() is first
    monkeypatch.setattr(syshttp_tls, "_os_context_at", 0.0)
    monkeypatch.setattr(syshttp_tls.time, "monotonic", lambda: syshttp_tls.OS_CONTEXT_MAX_AGE + 1.0)
    assert syshttp_tls.os_ssl_context() is not first, "renewed after its lifetime"


def test_the_os_context_is_the_os_verifier_where_truststore_runs():
    import sys

    ctx = syshttp_tls.new_os_context()
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    expected = "truststore" if sys.version_info >= (3, 10) else "ssl"
    assert type(ctx).__module__.split(".")[0] == expected


def test_a_ca_file_replaces_the_os_store():
    ctx = syshttp_tls.new_os_context(cafile=CA)
    assert type(ctx) is ssl.SSLContext, "a plain context trusting only the given CA"
    assert [c["subject"] for c in ctx.get_ca_certs()] == [((("commonName", "sslcontext test CA"),),)]

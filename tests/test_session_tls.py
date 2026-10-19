"""syshttp sessions verify TLS through the OS trust store, never a certifi
bundle: `verify=True` pools get the shared OS `SSLContext` and no CA file;
`verify=False` and an explicit bundle stay requests' business. No network.
"""

import ssl

import pytest

requests = pytest.importorskip("requests")

from syshttp import session as syshttp_session  # noqa: E402
from syshttp import tls as syshttp_tls  # noqa: E402


def _adapter():
    return syshttp_session.new_session(retries=0).get_adapter("https://example.com/")


def _prepared(url):
    return requests.Request("GET", url).prepare()


def test_verify_true_https_pools_get_the_os_context():
    adapter = _adapter()
    _host, kwargs = adapter.build_connection_pool_key_attributes(_prepared("https://example.com/"), True, None)
    assert kwargs["ssl_context"] is syshttp_session.os_ssl_context()
    assert kwargs["cert_reqs"] == "CERT_REQUIRED"
    assert "ca_certs" not in kwargs and "ca_cert_dir" not in kwargs


@pytest.mark.parametrize("verify", [False, "/some/bundle.pem"])
def test_other_verify_values_never_share_the_os_context(verify):
    """urllib3 writes a pool's cert_reqs into its context: a verify=False pool
    sharing it would switch verification off for every other pool."""
    adapter = _adapter()
    _host, kwargs = adapter.build_connection_pool_key_attributes(_prepared("https://example.com/"), verify, None)
    assert kwargs.get("ssl_context") is not syshttp_session.os_ssl_context()


def test_cert_verify_names_no_ca_file_even_when_certifi_has_none(monkeypatch):
    """requests set conn.ca_certs = certifi.where() and raised on None."""
    monkeypatch.setattr(requests.adapters, "DEFAULT_CA_BUNDLE_PATH", None)

    class Conn:
        cert_reqs = ca_certs = ca_cert_dir = cert_file = key_file = None

    conn = Conn()
    _adapter().cert_verify(conn, "https://example.com/", True, None)
    assert conn.cert_reqs == "CERT_REQUIRED"
    assert conn.ca_certs is None and conn.ca_cert_dir is None


def test_an_explicit_bundle_is_still_honoured(tmp_path):
    bundle = tmp_path / "ca.pem"
    bundle.write_text("x", encoding="ascii")

    class Conn:
        cert_reqs = ca_certs = ca_cert_dir = cert_file = key_file = None

    conn = Conn()
    _adapter().cert_verify(conn, "https://example.com/", str(bundle), None)
    assert conn.ca_certs == str(bundle)


def test_the_os_context_is_shared_then_renewed(monkeypatch):
    from syshttp import tls as syshttp_tls

    first = syshttp_session.os_ssl_context()
    assert isinstance(first, ssl.SSLContext) and first.verify_mode == ssl.CERT_REQUIRED
    assert syshttp_session.os_ssl_context() is first, "shared: pools are keyed by it"
    assert syshttp_tls.os_ssl_context() is first, "one context: the session's is syshttp.tls's"
    monkeypatch.setattr(syshttp_tls, "_os_context_at", 0.0)
    monkeypatch.setattr(syshttp_tls.time, "monotonic", lambda: syshttp_tls.OS_CONTEXT_MAX_AGE + 1.0)
    assert syshttp_session.os_ssl_context() is not first, "renewed after its lifetime"


def test_the_session_retries_what_curl_calls_transient():
    """One list: the session's Retry and the curl fallback's --retry."""
    from syshttp.retry import TRANSIENT_STATUSES

    retry = _adapter().max_retries
    assert set(retry.status_forcelist) == set(TRANSIENT_STATUSES) and 408 in TRANSIENT_STATUSES


def test_the_os_context_is_the_os_verifier_where_truststore_runs():
    import sys

    ctx = syshttp_tls.new_os_context()
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    expected = "truststore" if sys.version_info >= (3, 10) else "ssl"
    assert type(ctx).__module__.split(".")[0] == expected


def test_a_ca_file_replaces_the_os_store(tmp_path):
    from pathlib import Path

    ca = Path(__file__).parent / "data" / "ca.pem"
    ctx = syshttp_tls.new_os_context(cafile=str(ca))
    assert type(ctx) is ssl.SSLContext, "a plain context trusting only the given CA"
    assert [c["subject"] for c in ctx.get_ca_certs()] == [((("commonName", "sslcontext test CA"),),)]


def test_a_prefix_gateway_is_spoken_to_with_the_proxy_context_not_the_origins():
    from syshttp.env import HTTPEnv

    origin_ctx, proxy_ctx = ssl.create_default_context(), ssl.create_default_context()
    env = HTTPEnv(environ={"SYSHTTP_PROXY": "https://127.0.0.1:9", "SYSHTTP_PROXY_TYPE": "prefix:/fetch/"})
    session = syshttp_session.new_session(env=env, retries=0, ssl_context=origin_ctx, proxy_ssl_context=proxy_ctx)
    adapter = session.get_adapter("http://x/")
    seen = []
    original = type(adapter).build_connection_pool_key_attributes

    def spy(self, request, verify, cert=None):
        host, pool = original(self, request, verify, cert)
        seen.append((host["host"], pool.get("ssl_context"), pool.get("cert_file")))
        return host, pool

    type(adapter).build_connection_pool_key_attributes = spy
    try:
        with pytest.raises(requests.exceptions.ConnectionError):
            session.get("http://plain-origin.example/x", timeout=2)
    finally:
        type(adapter).build_connection_pool_key_attributes = original
    assert seen == [("127.0.0.1", proxy_ctx, None)]

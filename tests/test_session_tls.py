"""httplib sessions verify TLS through the OS trust store, never a certifi
bundle: `verify=True` pools get the shared OS `SSLContext` and no CA file;
`verify=False` and an explicit bundle stay requests' business. No network.
"""
import ssl

import pytest

requests = pytest.importorskip("requests")

from httplib import session as httplib_session  # noqa: E402


def _adapter():
    return httplib_session.new_session(retries=0).get_adapter("https://example.com/")


def _prepared(url):
    return requests.Request("GET", url).prepare()


def test_verify_true_https_pools_get_the_os_context():
    adapter = _adapter()
    if not hasattr(requests.adapters.HTTPAdapter, "build_connection_pool_key_attributes"):
        pytest.skip("requests < 2.32.2 builds its pools without this hook")
    _host, kwargs = adapter.build_connection_pool_key_attributes(
        _prepared("https://example.com/"), True, None
    )
    assert kwargs["ssl_context"] is httplib_session.os_ssl_context()
    assert kwargs["cert_reqs"] == "CERT_REQUIRED"
    assert "ca_certs" not in kwargs and "ca_cert_dir" not in kwargs


@pytest.mark.parametrize("verify", [False, "/some/bundle.pem"])
def test_other_verify_values_never_share_the_os_context(verify):
    """urllib3 writes a pool's cert_reqs into its context: a verify=False pool
    sharing it would switch verification off for every other pool."""
    adapter = _adapter()
    if not hasattr(requests.adapters.HTTPAdapter, "build_connection_pool_key_attributes"):
        pytest.skip("requests < 2.32.2 builds its pools without this hook")
    _host, kwargs = adapter.build_connection_pool_key_attributes(
        _prepared("https://example.com/"), verify, None
    )
    assert kwargs.get("ssl_context") is not httplib_session.os_ssl_context()


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
    from httplib import tls as httplib_tls

    first = httplib_session.os_ssl_context()
    assert isinstance(first, ssl.SSLContext) and first.verify_mode == ssl.CERT_REQUIRED
    assert httplib_session.os_ssl_context() is first, "shared: pools are keyed by it"
    assert httplib_tls.os_ssl_context() is first, "one context: the session's is httplib.tls's"
    monkeypatch.setattr(httplib_tls, "_os_context_at", 0.0)
    monkeypatch.setattr(httplib_tls.time, "monotonic", lambda: httplib_tls.OS_CONTEXT_MAX_AGE + 1.0)
    assert httplib_session.os_ssl_context() is not first, "renewed after its lifetime"


def test_the_session_retries_what_curl_calls_transient():
    """One list: the session's Retry and the curl fallback's --retry."""
    from httplib.retry import TRANSIENT_STATUSES

    retry = _adapter().max_retries
    assert set(retry.status_forcelist) == set(TRANSIENT_STATUSES) and 408 in TRANSIENT_STATUSES

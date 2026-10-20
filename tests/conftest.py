import os

import pytest


@pytest.fixture(autouse=True)
def _no_ambient_settings(monkeypatch):
    """No test sees an SYSHTTP_* or CA_BUNDLE variable of the machine running
    it -- SYSHTTP_PREFIX included, which would rename every other setting -- nor the
    machine's system proxy configuration, nor its certificate store and smart
    cards when a server asks for a client certificate (tests that need one
    fake it). The OS still verifies servers."""
    for name in list(os.environ):
        if name.startswith("SYSHTTP_") or name == "CA_BUNDLE":
            monkeypatch.delenv(name)
    import proxylib

    from syshttp import proxy

    monkeypatch.setattr(proxy, "system_map", lambda: None)
    # proxylib's bad-proxy marks are process-wide: one test's dead port is
    # another's live one.
    proxylib.clear_caches()
    import sslcontext

    real = sslcontext.system_context

    def system_context(*, selector=None, **kwargs):
        if selector is None or selector is True:
            selector = sslcontext.ClientCertificateSelector([])
        return real(selector=selector, **kwargs)

    monkeypatch.setattr(sslcontext, "system_context", system_context)
    monkeypatch.setattr("syshttp.tls._os_context", None)


@pytest.fixture
def http_transport():
    """A default transport, closed after the test."""
    from syshttp.client import HTTPTransport

    with HTTPTransport() as transport:
        yield transport

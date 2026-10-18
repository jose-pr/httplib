import os

import pytest


@pytest.fixture(autouse=True)
def _no_ambient_settings(monkeypatch):
    """No test sees an SYSHTTP_* variable of the machine running it --
    SYSHTTP_PREFIX included, which would rename every other setting -- nor the
    machine's system proxy configuration (tests that need one fake it)."""
    for name in list(os.environ):
        if name.startswith("SYSHTTP_"):
            monkeypatch.delenv(name)
    from syshttp import proxy

    monkeypatch.setattr(proxy, "system_proxy_map", lambda: None)

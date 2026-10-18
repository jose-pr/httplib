import os

import pytest


@pytest.fixture(autouse=True)
def _no_ambient_settings(monkeypatch):
    """No test sees an HTTPLIB_* variable of the machine running it --
    HTTPLIB_PREFIX included, which would rename every other setting."""
    for name in list(os.environ):
        if name.startswith("HTTPLIB_"):
            monkeypatch.delenv(name)

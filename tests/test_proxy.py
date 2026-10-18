"""httplib.proxy: AGENTS_PROXY wins, then HTTPS/HTTP/ALL_PROXY (either case).

No network. Run: `PYTHONPATH=src python -m pytest overlays/net/tests/`.
"""
import importlib

from httplib import proxy as _proxy_module  # noqa: E402  (via conftest lib path)

# All proxy env vars proxy_url() consults, so a test can clear them wholesale.
_ALL_VARS = [
    "AGENTS_PROXY",
    "HTTPS_PROXY", "https_proxy",
    "HTTP_PROXY", "http_proxy",
    "ALL_PROXY", "all_proxy",
]


def _clear(monkeypatch):
    for v in _ALL_VARS:
        monkeypatch.delenv(v, raising=False)


def test_agents_proxy_wins_over_everything(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("AGENTS_PROXY", "http://agent:1/")
    monkeypatch.setenv("HTTPS_PROXY", "http://https:2/")
    monkeypatch.setenv("HTTP_PROXY", "http://http:3/")
    monkeypatch.setenv("ALL_PROXY", "http://all:4/")
    importlib.reload(_proxy_module)
    assert _proxy_module.proxy_url() == "http://agent:1/"


def test_fallback_order_https_before_http_before_all(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("HTTP_PROXY", "http://http:3/")
    monkeypatch.setenv("ALL_PROXY", "http://all:4/")
    monkeypatch.setenv("HTTPS_PROXY", "http://https:2/")
    assert _proxy_module.proxy_url() == "http://https:2/"

    monkeypatch.delenv("HTTPS_PROXY")
    assert _proxy_module.proxy_url() == "http://http:3/"

    monkeypatch.delenv("HTTP_PROXY")
    assert _proxy_module.proxy_url() == "http://all:4/"


def test_lowercase_fallback_recognized(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("https_proxy", "http://lower:9/")
    assert _proxy_module.proxy_url() == "http://lower:9/"


def test_none_when_unset(monkeypatch):
    _clear(monkeypatch)
    assert _proxy_module.proxy_url() is None
    assert _proxy_module.proxies_from_env() is None


def test_proxies_dict_shape(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("AGENTS_PROXY", "http://p:1/")
    assert _proxy_module.proxies_from_env() == {"http": "http://p:1/", "https": "http://p:1/"}

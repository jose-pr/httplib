"""The system's proxy configuration as the last source: after <P>_PROXY and
the *_PROXY variables, per URL, always connect, NO_PROXY first, switched off
by <P>_SYSTEM_PROXY=0, and never a failed request when it cannot be read."""

import pytest

from httplib import HTTPEnv, proxy


class _Proxy:
    def __init__(self, url):
        self.url = url


class _FakeSystem:
    """A proxylib ProxyMap: host -> proxy URL (None = DIRECT); KeyError for
    no opinion."""

    def __init__(self, routes):
        self.routes = routes
        self.asked = []

    def __getitem__(self, url):
        self.asked.append(url)
        host = url.split("/")[2]
        if host not in self.routes:
            raise KeyError(url)
        route = self.routes[host]
        return [None] if route is None else [_Proxy(route), None]


@pytest.fixture()
def system(monkeypatch):
    fake = _FakeSystem({"a.example": "http://pac-a:3128", "b.example": "http://pac-b:8080", "c.example": None})
    monkeypatch.setattr(proxy, "system_proxy_map", lambda: fake)
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    return fake


def test_the_system_answers_per_url_and_always_connect(system, monkeypatch):
    monkeypatch.setenv("HTTPLIB_PROXY_TYPE", "prefix:/fetch/")  # describes HTTPLIB_PROXY, not the system's
    a = proxy.plan(url="https://a.example/x")
    b = proxy.plan(url="https://b.example/y")
    assert (a.proxy, a.endpoint) == ("http://pac-a:3128", None)
    assert (b.proxy, b.endpoint) == ("http://pac-b:8080", None)


def test_direct_and_no_opinion_are_direct(system):
    assert proxy.plan(url="https://c.example/") is None, "DIRECT"
    assert proxy.plan(url="https://unknown.example/") is None, "KeyError: no opinion"


def test_a_variable_wins_over_the_system(system, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://env:1")
    assert proxy.plan(url="https://a.example/").proxy == "http://env:1"
    monkeypatch.setenv("HTTPLIB_PROXY", "http://mine:2")
    assert proxy.plan(url="https://a.example/").proxy == "http://mine:2"
    assert system.asked == [], "the system is not asked when a variable answers"


def test_no_proxy_is_checked_before_the_system(system, monkeypatch):
    monkeypatch.setenv("NO_PROXY", "a.example")
    assert proxy.plan(url="https://a.example/") is None
    assert system.asked == []


def test_the_configured_credential_goes_to_the_systems_proxy(system, monkeypatch):
    monkeypatch.setenv("HTTPLIB_PROXY_AUTH", "Bearer t")
    assert proxy.plan(url="https://a.example/").authorization == "Bearer t"


def test_without_a_url_the_system_is_not_asked(system):
    assert proxy.proxy_url() is None and system.asked == []
    assert proxy.proxy_url(url="https://a.example/") == "http://pac-a:3128"


def test_system_proxy_switch(system, monkeypatch):
    for off in ("0", "false", "No", "OFF"):
        monkeypatch.setenv("HTTPLIB_SYSTEM_PROXY", off)
        assert proxy.plan(url="https://a.example/") is None
    for on in ("1", "true", "YES", "on", ""):
        monkeypatch.setenv("HTTPLIB_SYSTEM_PROXY", on)
        assert proxy.plan(url="https://a.example/").proxy == "http://pac-a:3128"
    monkeypatch.setenv("HTTPLIB_SYSTEM_PROXY", "maybe")
    with pytest.raises(ValueError, match="HTTPLIB_SYSTEM_PROXY"):
        proxy.plan(url="https://a.example/")
    assert proxy.system_proxy_enabled(env=HTTPEnv("MYTOOL", environ={"MYTOOL_SYSTEM_PROXY": "0"})) is False


def test_a_failing_system_lookup_is_direct(monkeypatch):
    class _Broken:
        def __getitem__(self, url):
            raise OSError("WinHttpGetProxyForUrl failed")

    monkeypatch.setattr(proxy, "system_proxy_map", lambda: _Broken())
    assert proxy.system_proxy("https://a.example/") is None


def test_the_system_map_is_read_once_then_renewed(monkeypatch):
    import proxylib

    monkeypatch.undo()  # the real system_proxy_map, without the conftest's stub
    calls = []

    def fake_system_proxy(provider):
        calls.append(provider)
        return proxylib.SimpleProxyMap("http://sys:3128")

    monkeypatch.setattr(proxylib, "system_proxy", fake_system_proxy)
    monkeypatch.setattr(proxy, "_system_map_at", 0.0)
    first = proxy.system_proxy_map()
    assert proxy.system_proxy_map() is first and calls == ["system"], "the OS engine, read once"
    assert proxy.system_proxy("https://x.example/", env=HTTPEnv(environ={})) == "http://sys:3128"
    monkeypatch.setattr(proxy, "_system_map_at", -proxy.SYSTEM_PROXY_MAX_AGE - 1.0)
    proxy.system_proxy_map()
    assert calls == ["system", "system"], "read again after its lifetime"


def test_an_unreadable_configuration_is_no_proxy(monkeypatch):
    import proxylib

    monkeypatch.undo()

    def broken(provider):
        raise OSError("no WinHTTP")

    monkeypatch.setattr(proxylib, "system_proxy", broken)
    monkeypatch.setattr(proxy, "_system_map_at", 0.0)
    assert proxy.system_proxy_map() is None
    assert proxy.system_proxy("https://x.example/", env=HTTPEnv(environ={})) is None


def _answering_proxy(name, seen):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((name, self.path, self.headers.get("Proxy-Authorization")))
            body = name.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def test_one_session_routes_each_url_by_the_systems_answer(monkeypatch):
    pytest.importorskip("requests")
    from httplib.session import new_session

    seen = []
    a, b = _answering_proxy("proxy-a", seen), _answering_proxy("proxy-b", seen)
    try:
        fake = _FakeSystem(
            {
                "a.example": "http://127.0.0.1:%d" % a.server_address[1],
                "b.example": "http://127.0.0.1:%d" % b.server_address[1],
            }
        )
        monkeypatch.setattr(proxy, "system_proxy_map", lambda: fake)
        monkeypatch.setenv("HTTPLIB_PROXY_AUTH", "Bearer t")
        session = new_session(retries=0)
        assert session.get("http://a.example/x", timeout=5).text == "proxy-a"
        assert session.get("http://b.example/y", timeout=5).text == "proxy-b"
        assert seen == [("proxy-a", "http://a.example/x", "Bearer t"), ("proxy-b", "http://b.example/y", "Bearer t")]
    finally:
        for httpd in (a, b):
            httpd.shutdown()
            httpd.server_close()


def test_the_credential_reaches_a_proxy_named_in_upper_case(monkeypatch):
    pytest.importorskip("requests")
    from httplib.session import new_session

    seen = []
    p = _answering_proxy("proxy", seen)
    try:
        monkeypatch.setenv("HTTPLIB_PROXY", "http://LOCALHOST:%d" % p.server_address[1])
        monkeypatch.setenv("HTTPLIB_PROXY_AUTH", "Bearer t")
        assert new_session(retries=0).get("http://origin.example/", timeout=5).text == "proxy"
        assert seen[-1][2] == "Bearer t", "requests lower-cases the proxy URL it asks about"
    finally:
        p.shutdown()
        p.server_close()

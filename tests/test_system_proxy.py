"""The system's proxy configuration as the last source: after <P>_PROXY and
the *_PROXY variables, per URL, NO_PROXY first, switched off by
<P>_SYSTEM_PROXY=0, never a failed request when it cannot be read; its list
tried in order by the client, and probed for a client that sends once."""

import proxylib
import pytest

from syshttp import HTTPEnv, proxy


class _FakeSystem:
    """A proxylib ProxyMap: host -> PAC result; KeyError for no opinion."""

    def __init__(self, routes):
        self.routes = routes
        self.asked = []

    def __getitem__(self, url):
        self.asked.append(url)
        host = url.split("/")[2]
        if host not in self.routes:
            raise KeyError(url)
        return proxylib.Proxy.parse_pac_result(self.routes[host])


@pytest.fixture()
def system(monkeypatch):
    fake = _FakeSystem(
        {"a.example": "PROXY pac-a:3128; DIRECT", "b.example": "PROXY pac-b:8080", "c.example": "DIRECT"}
    )
    monkeypatch.setattr(proxy, "system_map", lambda: fake)
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    return fake


def _answer(url, **kwargs):
    return tuple(None if e is None else e.uri() for e in proxylib.lookup(proxy.proxy_map(**kwargs), url))


def test_the_system_answers_per_url(system, monkeypatch):
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "prefix:/fetch/")  # describes SYSHTTP_PROXY, not the system's
    assert _answer("https://a.example/x") == ("http://pac-a:3128", None)
    assert _answer("https://b.example/y") == ("http://pac-b:8080",)


def test_direct_and_no_opinion_are_direct(system):
    assert _answer("https://c.example/") == (None,), "DIRECT"
    assert _answer("https://unknown.example/") == (None,), "KeyError: no opinion"


def test_a_variable_wins_over_the_system(system, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://env:1")
    assert _answer("https://a.example/") == ("http://env:1",)
    monkeypatch.setenv("SYSHTTP_PROXY", "http://mine:2")
    assert _answer("https://a.example/") == ("http://mine:2",)
    assert system.asked == [], "the system is not asked when a variable answers"


def test_no_proxy_is_checked_before_the_system(system, monkeypatch):
    monkeypatch.setenv("NO_PROXY", "a.example")
    assert _answer("https://a.example/") == (None,)
    assert system.asked == []


def test_the_machine_credential_goes_to_the_systems_proxy_and_the_tools_does_not(system, monkeypatch):
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", "Bearer tool")
    entry, direct = proxylib.lookup(proxy.proxy_map(), "https://a.example/")
    assert entry.headers == {} and direct is None
    monkeypatch.setenv("HTTP_PROXY_AUTH", "Bearer machine")
    entry, direct = proxylib.lookup(proxy.proxy_map(), "https://a.example/")
    assert entry.headers == {"Proxy-Authorization": "Bearer machine"} and direct is None


def test_system_proxy_switch(system, monkeypatch):
    for off in ("0", "false", "No", "OFF"):
        monkeypatch.setenv("SYSHTTP_SYSTEM_PROXY", off)
        assert _answer("https://a.example/") == (None,)
    for on in ("1", "true", "YES", "on", ""):
        monkeypatch.setenv("SYSHTTP_SYSTEM_PROXY", on)
        assert _answer("https://a.example/")[0] == "http://pac-a:3128"
    monkeypatch.setenv("SYSHTTP_SYSTEM_PROXY", "maybe")
    with pytest.raises(ValueError, match="SYSHTTP_SYSTEM_PROXY"):
        _answer("https://a.example/")
    assert proxy.system_proxy_enabled(env=HTTPEnv("MYTOOL_", environ={"MYTOOL_SYSHTTP_SYSTEM_PROXY": "0"})) is False


def test_the_system_map_is_read_once_then_renewed_and_its_failures_are_direct(monkeypatch):
    monkeypatch.undo()  # the real system_map, without the conftest's stub
    calls = []

    class _Flaky:
        def __getitem__(self, url):
            if "broken" in url:
                raise OSError("WinHttpGetProxyForUrl failed")
            return (proxylib.Proxy.parse("http://sys:3128"),)

    def fake_auto_proxy(**kwargs):
        calls.append(kwargs)
        return _Flaky()

    monkeypatch.setattr(proxylib, "auto_proxy", fake_auto_proxy)
    monkeypatch.setattr(proxy, "_system_at", 0.0)
    first = proxy.system_map()
    assert proxy.system_map() is first and calls == [{"environ": {}}], "the OS alone, read once"
    env = HTTPEnv(environ={})
    assert proxylib.lookup(proxy.proxy_map(env=env), "https://x.example/")[0].url == "http://sys:3128"
    assert proxylib.lookup(proxy.proxy_map(env=env), "https://broken.example/") == (None,)
    monkeypatch.setattr(proxy, "_system_at", -proxy.SYSTEM_PROXY_MAX_AGE - 1.0)
    proxy.system_map()
    assert len(calls) == 2, "read again after its lifetime"


def test_an_unreadable_configuration_is_no_proxy(monkeypatch):
    monkeypatch.undo()

    def broken(**kwargs):
        raise OSError("no WinHTTP")

    monkeypatch.setattr(proxylib, "auto_proxy", broken)
    monkeypatch.setattr(proxy, "_system_at", 0.0)
    assert proxy.system_map() is None
    assert proxylib.lookup(proxy.proxy_map(env=HTTPEnv(environ={})), "https://x.example/") == (None,)


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


def _dead_port():
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _get(url):
    from syshttp.client import HTTPClient

    with HTTPClient() as client:
        return client.request("GET", url, timeout=5).text()


def test_one_client_routes_each_url_by_the_systems_answer(system, monkeypatch):
    from syshttp.client import HTTPClient

    seen = []
    a, b = _answering_proxy("proxy-a", seen), _answering_proxy("proxy-b", seen)
    try:
        system.routes.update(
            {
                "a.example": "PROXY 127.0.0.1:%d" % a.server_address[1],
                "b.example": "PROXY 127.0.0.1:%d" % b.server_address[1],
            }
        )
        monkeypatch.setenv("HTTP_PROXY_AUTH", "Bearer t")
        with HTTPClient() as client:
            assert client.request("GET", "http://a.example/x", timeout=5).text() == "proxy-a"
            assert client.request("GET", "http://b.example/y", timeout=5).text() == "proxy-b"
        assert seen == [("proxy-a", "http://a.example/x", "Bearer t"), ("proxy-b", "http://b.example/y", "Bearer t")]
    finally:
        for httpd in (a, b):
            httpd.shutdown()
            httpd.server_close()


def test_the_credential_reaches_a_proxy_named_in_upper_case(monkeypatch):
    seen = []
    p = _answering_proxy("proxy", seen)
    try:
        monkeypatch.setenv("SYSHTTP_PROXY", "http://LOCALHOST:%d" % p.server_address[1])
        monkeypatch.setenv("SYSHTTP_PROXY_AUTH", "Bearer t")
        assert _get("http://origin.example/") == "proxy"
        assert seen[-1][2] == "Bearer t"
    finally:
        p.shutdown()
        p.server_close()


def test_the_client_fails_over_to_the_next_proxy_of_the_list(system):
    seen = []
    live = _answering_proxy("live", seen)
    try:
        dead = _dead_port()
        system.routes["a.example"] = "PROXY 127.0.0.1:%d; PROXY 127.0.0.1:%d" % (dead, live.server_address[1])
        assert _get("http://a.example/x") == "live"
    finally:
        live.shutdown()
        live.server_close()


def test_the_client_goes_direct_when_direct_follows_a_dead_proxy(system):
    seen = []
    origin = _answering_proxy("origin", seen)
    try:
        host = "127.0.0.1:%d" % origin.server_address[1]
        system.routes[host] = "PROXY 127.0.0.1:%d; DIRECT" % _dead_port()
        assert _get("http://%s/x" % host) == "origin"
        assert seen == [("origin", "/x", None)]
    finally:
        origin.shutdown()
        origin.server_close()


def test_no_reachable_proxy_and_no_direct_is_an_error(system):
    dead = _dead_port()
    system.routes["a.example"] = "PROXY 127.0.0.1:%d" % dead
    with pytest.raises(proxy.NoReachableProxyError):
        _get("http://a.example/")
    with pytest.raises(proxy.NoReachableProxyError):
        proxylib.lookup(proxylib.Probed(proxy.proxy_map(), timeout=1.0), "http://a.example/")

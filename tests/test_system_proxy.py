"""The system's proxy configuration as the last source: after <P>_PROXY and
the *_PROXY variables, per URL, always connect, NO_PROXY first, switched off
by <P>_SYSTEM_PROXY=0, and never a failed request when it cannot be read."""

import pytest

from syshttp import HTTPEnv, proxy


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
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "prefix:/fetch/")  # describes SYSHTTP_PROXY, not the system's
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
    monkeypatch.setenv("SYSHTTP_PROXY", "http://mine:2")
    assert proxy.plan(url="https://a.example/").proxy == "http://mine:2"
    assert system.asked == [], "the system is not asked when a variable answers"


def test_no_proxy_is_checked_before_the_system(system, monkeypatch):
    monkeypatch.setenv("NO_PROXY", "a.example")
    assert proxy.plan(url="https://a.example/") is None
    assert system.asked == []


def test_the_configured_credential_goes_to_the_systems_proxy(system, monkeypatch):
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", "Bearer t")
    assert proxy.plan(url="https://a.example/").authorization == "Bearer t"


def test_without_a_url_the_system_is_not_asked(system):
    assert proxy.proxy_url() is None and system.asked == []
    assert proxy.proxy_url(url="https://a.example/") == "http://pac-a:3128"


def test_system_proxy_switch(system, monkeypatch):
    for off in ("0", "false", "No", "OFF"):
        monkeypatch.setenv("SYSHTTP_SYSTEM_PROXY", off)
        assert proxy.plan(url="https://a.example/") is None
    for on in ("1", "true", "YES", "on", ""):
        monkeypatch.setenv("SYSHTTP_SYSTEM_PROXY", on)
        assert proxy.plan(url="https://a.example/").proxy == "http://pac-a:3128"
    monkeypatch.setenv("SYSHTTP_SYSTEM_PROXY", "maybe")
    with pytest.raises(ValueError, match="SYSHTTP_SYSTEM_PROXY"):
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
    monkeypatch.setattr(proxy, "first_reachable", lambda answer: answer[0])  # sys:3128 is not probed
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
    from syshttp.session import new_session

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
        monkeypatch.setenv("SYSHTTP_PROXY_AUTH", "Bearer t")
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
    from syshttp.session import new_session

    seen = []
    p = _answering_proxy("proxy", seen)
    try:
        monkeypatch.setenv("SYSHTTP_PROXY", "http://LOCALHOST:%d" % p.server_address[1])
        monkeypatch.setenv("SYSHTTP_PROXY_AUTH", "Bearer t")
        assert new_session(retries=0).get("http://origin.example/", timeout=5).text == "proxy"
        assert seen[-1][2] == "Bearer t", "requests lower-cases the proxy URL it asks about"
    finally:
        p.shutdown()
        p.server_close()


# The real probe, before conftest stubs it for every other test.
_REAL_FIRST_REACHABLE = proxy.first_reachable


@pytest.fixture()
def probing(monkeypatch):
    """The system answers a list of loopback proxies; proxylib really probes
    them. ``live`` listens, ``dead`` refuses."""
    import socket

    import proxylib

    proxylib.netutils.clear_circuit_breaker()
    monkeypatch.setattr(proxy, "first_reachable", _REAL_FIRST_REACHABLE)
    live = socket.socket()
    live.bind(("127.0.0.1", 0))
    live.listen(8)
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    dead = closed.getsockname()[1]
    closed.close()
    answers = {}

    class _Map:
        def __getitem__(self, url):
            return proxylib.SimpleProxyMap(answers["now"])[url]

    monkeypatch.setattr(proxy, "system_proxy_map", lambda: _Map())
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    try:
        yield answers, live.getsockname()[1], dead
    finally:
        live.close()
        proxylib.netutils.clear_circuit_breaker()


def test_the_first_reachable_proxy_of_the_systems_list_is_used(probing):
    answers, live, dead = probing
    answers["now"] = "PROXY 127.0.0.1:%d; PROXY 127.0.0.1:%d" % (dead, live)
    assert proxy.system_proxy("http://a.example/") == "http://127.0.0.1:%d" % live


def test_direct_in_the_list_is_direct_when_no_proxy_answers(probing):
    answers, _live, dead = probing
    answers["now"] = "PROXY 127.0.0.1:%d; DIRECT" % dead
    assert proxy.system_proxy("http://a.example/") is None


def test_no_reachable_proxy_and_no_direct_is_an_error(probing):
    answers, _live, dead = probing
    answers["now"] = "PROXY 127.0.0.1:%d" % dead
    with pytest.raises(proxy.NoReachableProxyError) as caught:
        proxy.plan(url="http://a.example/")
    assert caught.value.proxies == ("127.0.0.1:%d" % dead,)
    assert isinstance(caught.value, ConnectionError)


def test_the_pick_is_reused_then_probed_again(probing, monkeypatch):
    answers, live, _dead = probing
    answers["now"] = "PROXY 127.0.0.1:%d" % live
    probes = []
    monkeypatch.setattr(proxy, "first_reachable", lambda answer: probes.append(answer) or answer[0])
    proxy.system_proxy("http://a.example/")
    proxy.system_proxy("http://b.example/")
    assert len(probes) == 1, "one list, probed once"
    monkeypatch.setattr(proxy.time, "monotonic", lambda: 10.0**9)
    proxy.system_proxy("http://a.example/")
    assert len(probes) == 2, "probed again after PROBE_MAX_AGE"


def test_a_session_reports_no_reachable_proxy_as_a_proxy_error(probing):
    requests = pytest.importorskip("requests")
    from syshttp.session import new_session

    answers, _live, dead = probing
    answers["now"] = "PROXY 127.0.0.1:%d" % dead
    with pytest.raises(requests.exceptions.ProxyError, match="127.0.0.1:%d" % dead):
        new_session(retries=0).get("http://a.example/", timeout=5)

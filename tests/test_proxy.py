"""syshttp.proxy.proxy_map: SYSHTTP_PROXY wins, then the *_PROXY variables by
the request's scheme (lowercase first), then the system (stubbed off here),
then DIRECT. No network."""

import proxylib
import pytest

from syshttp import HTTPEnv
from syshttp import proxy as agent_proxy


def _urls(url, environ, **kwargs):
    """The answer's entries as proxy URLs (credentials included), None for DIRECT."""
    answer = proxylib.lookup(agent_proxy.proxy_map(env=HTTPEnv(environ=environ), **kwargs), url)
    return [None if entry is None else entry.uri() for entry in answer]


def test_syshttp_proxy_wins_over_everything():
    environ = {
        "SYSHTTP_PROXY": "http://agent:1/",
        "HTTPS_PROXY": "http://https:2/",
        "HTTP_PROXY": "http://http:3/",
        "ALL_PROXY": "http://all:4/",
    }
    assert _urls("https://example.com/", environ) == ["http://agent:1"]
    assert _urls("http://example.com/", environ) == ["http://agent:1"]


def test_each_scheme_takes_its_own_variable():
    environ = {"HTTPS_PROXY": "http://tls-proxy:1", "HTTP_PROXY": "http://plain-proxy:2"}
    assert _urls("https://example.com/", environ) == ["http://tls-proxy:1"]
    assert _urls("http://example.com/", environ) == ["http://plain-proxy:2"]


def test_all_proxy_is_the_fallback_and_a_scheme_without_one_is_direct():
    assert _urls("ftp://example.com/", {"ALL_PROXY": "http://all:4"}) == ["http://all:4"]
    assert _urls("http://example.com/", {"HTTPS_PROXY": "http://tls:1"}) == [None]


def test_lowercase_wins_over_uppercase():
    environ = {"https_proxy": "http://lower:9", "HTTPS_PROXY": "http://upper:8"}
    assert _urls("https://example.com/", environ) == ["http://lower:9"]


def test_direct_when_nothing_is_set():
    assert _urls("https://example.com/", {}) == [None]


def test_httpoxy_an_uppercase_http_proxy_under_cgi_is_ignored():
    environ = {"REQUEST_METHOD": "GET", "HTTP_PROXY": "http://attacker:8080", "SYSHTTP_PROXY_AUTH": "Bearer x"}
    assert _urls("http://example.com/", environ) == [None]


def test_a_pac_result_in_a_variable_is_a_list_to_try():
    environ = {"HTTPS_PROXY": "PROXY a.example:3128; PROXY b.example:3128; DIRECT"}
    assert _urls("https://example.com/", environ) == ["http://a.example:3128", "http://b.example:3128", None]


def test_the_system_answers_when_no_variable_is_set(monkeypatch):
    monkeypatch.setattr(agent_proxy, "system_map", lambda: proxylib.SimpleProxyMap("PROXY sys.example:8080"))
    assert _urls("https://example.com/", {}) == ["http://sys.example:8080"]
    assert _urls("https://example.com/", {"SYSHTTP_SYSTEM_PROXY": "0"}) == [None]
    assert _urls("https://example.com/", {"HTTP_PROXY": "http://plain:2"}) == [None], "a variable set: env alone"


def test_a_system_that_fails_is_direct(monkeypatch):
    class Broken:
        def __getitem__(self, url):
            raise RuntimeError("PAC died")

    monkeypatch.setattr(agent_proxy, "system_map", lambda: agent_proxy._Quiet(Broken()))
    assert _urls("https://example.com/", {}) == [None]


def test_a_bad_system_proxy_setting_names_the_variable():
    with pytest.raises(ValueError, match="SYSHTTP_SYSTEM_PROXY"):
        _urls("https://example.com/", {"SYSHTTP_SYSTEM_PROXY": "maybe"})

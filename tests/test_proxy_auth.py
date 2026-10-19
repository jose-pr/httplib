"""Proxy credentials, kind and bypass, end to end: syshttp.proxy and the
requests session.

No external network: a fake authenticating forward proxy, a fake prefix gateway
and a plain target server run on 127.0.0.1. The proxy answers 407 without the
right Proxy-Authorization and never forwards -- a body of ``via-proxy`` proves
the request went through it with the credential, ``via-gateway`` that it went to
the prefix gateway, ``hello`` that it went direct.
"""

import base64
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from syshttp import proxy as agent_proxy

_ALL_VARS = [
    "SYSHTTP_PROXY",
    "SYSHTTP_PROXY_AUTH",
    "SYSHTTP_PROXY_TYPE",
    "HTTP_PROXY_AUTH",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
]

BASIC = "Basic " + base64.b64encode(b"agent:s3cret").decode()
BEARER = "Bearer eyJ0b2tlbiI6ICJhZ2VudCJ9"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for v in _ALL_VARS:
        monkeypatch.delenv(v, raising=False)


class _Target(BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):
        _Target.seen.append((self.path, self.headers.get("Proxy-Authorization")))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"hello"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _Proxy(BaseHTTPRequestHandler):
    """A forward proxy that only checks the credential, then answers itself."""

    expected = BASIC
    seen = []

    def do_GET(self):
        _Proxy.seen.append((self.path, self.headers.get("Proxy-Authorization")))
        if self.headers.get("Proxy-Authorization") == _Proxy.expected and self.path.endswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", self.path[: -len("/redirect")] + "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.headers.get("Proxy-Authorization") != _Proxy.expected:
            self.send_response(407)
            self.send_header("Proxy-Authenticate", 'Basic realm="agent"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"via-proxy"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _Gateway(BaseHTTPRequestHandler):
    """A prefix gateway: records the path it was asked for and the header."""

    seen = []

    def do_GET(self):
        _Gateway.seen.append((self.path, self.headers.get("Proxy-Authorization")))
        if self.path.endswith("/redirect"):
            # A gateway relaying the origin's redirect verbatim: an absolute
            # origin URL the client must wrap again.
            self.send_response(302)
            self.send_header("Location", self.path.split("/", 2)[2][: -len("/redirect")] + "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"via-gateway"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve(handler):
    httpd = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


@pytest.fixture()
def target():
    _Target.seen = []
    httpd = _serve(_Target)
    try:
        yield "http://127.0.0.1:%d" % httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture()
def proxy():
    _Proxy.seen, _Proxy.expected = [], BASIC
    httpd = _serve(_Proxy)
    try:
        yield "127.0.0.1:%d" % httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture()
def gateway():
    _Gateway.seen = []
    httpd = _serve(_Gateway)
    try:
        yield "http://127.0.0.1:%d" % httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


# --------------------------------------------------------------------------
# syshttp.proxy: the credential, its sources, kind, bypass
# --------------------------------------------------------------------------


def _answer(url="https://api.example.com/", **kwargs):
    import proxylib

    return proxylib.lookup(agent_proxy.proxy_map(**kwargs), url)


def _only(url="https://api.example.com/", **kwargs):
    (entry,) = _answer(url, **kwargs)
    return entry


def test_syshttp_proxy_auth_is_the_header_value_verbatim(monkeypatch):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://proxy.example:3128")
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    entry = _only()
    assert entry.url == "http://proxy.example:3128" and entry.headers == {"Proxy-Authorization": BEARER}


def test_http_proxy_auth_belongs_to_the_machine_proxy_only(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://machine.example:3128")
    monkeypatch.setenv("HTTP_PROXY_AUTH", BASIC)
    assert _only().headers == {"Proxy-Authorization": BASIC}
    monkeypatch.setenv("SYSHTTP_PROXY", "http://me:mine@tool-proxy.example:1")
    entry = _only()
    assert entry.headers == {} and (entry.username, entry.password) == ("me", "mine"), "not the tool proxy's"


def test_url_userinfo_is_the_credential_when_no_header_is_configured(monkeypatch):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://agent:s3cret@proxy.example:3128")
    entry = _only()
    assert (entry.username, entry.password, entry.headers) == ("agent", "s3cret", {})


def test_configured_header_beats_url_userinfo(monkeypatch):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://agent:s3cret@proxy.example:3128")
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    entry = _only()
    assert entry.username is None and entry.headers == {"Proxy-Authorization": BEARER}


def test_reserved_characters_in_userinfo_are_decoded(monkeypatch):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://dom%5Cuser:p%40ss%3Aw%2Frd@proxy.example:3128")
    entry = _only()
    assert (entry.username, entry.password) == ("dom\\user", "p@ss:w/rd")


def test_a_bare_host_port_is_http(monkeypatch):
    monkeypatch.setenv("SYSHTTP_PROXY", "proxy.example:3128")
    assert _only().uri() == "http://proxy.example:3128"


def test_repr_hides_the_secrets(monkeypatch):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://agent:s3cret@proxy.example:3128")
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    assert BEARER not in repr(_only()) and "s3cret" not in repr(_only())
    monkeypatch.delenv("SYSHTTP_PROXY_AUTH")
    monkeypatch.setenv("SYSHTTP_PROXY", "http://ghp_TOKEN@proxy.example:3128")
    assert "ghp_TOKEN" not in _only().url


def test_proxy_type_parsing(monkeypatch):
    assert agent_proxy.proxy_type() == ("connect", None)
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "connect")
    assert agent_proxy.proxy_type() == ("connect", None)
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "prefix")
    assert agent_proxy.proxy_type() == ("prefix", "/")
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "prefix:/fetch/")
    assert agent_proxy.proxy_type() == ("prefix", "/fetch/")
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "prefix:fetch")
    assert agent_proxy.proxy_type() == ("prefix", "/fetch")
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "socks5")
    with pytest.raises(ValueError):
        agent_proxy.proxy_type()


def test_a_prefix_gateway_is_asked_for_proxy_endpoint_url(monkeypatch):
    monkeypatch.setenv("SYSHTTP_PROXY", "https://agent:s3cret@gw.example/")
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "prefix:/fetch/")
    entry = _only()
    assert entry.is_gateway
    assert (
        entry.gateway_url("https://api.example.com/x?q=1") == "https://gw.example/fetch/https://api.example.com/x?q=1"
    )
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "prefix")
    assert _only().gateway_url("https://api.example.com/x") == "https://gw.example/https://api.example.com/x"


def test_no_proxy_bypass(monkeypatch):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://proxy.example:3128")
    monkeypatch.setenv("NO_PROXY", "localhost,.internal.example,127.0.0.1:8080,10.0.0.0/8")
    assert _answer("http://localhost/x") == (None,)
    assert _answer("https://db.internal.example/") == (None,)
    assert _answer("http://127.0.0.1:8080/") == (None,)
    assert _answer("http://10.1.2.3/") == (None,), "CIDR"
    assert _answer("http://[::1]/") == (None,), "loopback, unlisted"
    assert _answer("https://api.example.com/") != (None,)
    # Lowercase form (on Windows the two names are one variable, so clear first).
    monkeypatch.delenv("NO_PROXY")
    monkeypatch.setenv("no_proxy", "*")
    assert _answer("https://api.example.com/") == (None,)


def test_noproxy_replaces_no_proxy(monkeypatch):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://proxy.example:3128")
    monkeypatch.setenv("NO_PROXY", "api.example.com")
    assert _answer(noproxy="other.example") != (None,)
    assert _answer("https://other.example/", noproxy="other.example") == (None,)


# --------------------------------------------------------------------------
# requests session: same credential, same kind, same bypass
# --------------------------------------------------------------------------


def test_session_sends_the_configured_header_to_the_proxy(target, proxy, monkeypatch):
    pytest.importorskip("requests")
    from syshttp.session import new_session

    _Proxy.expected = BEARER
    monkeypatch.setenv("SYSHTTP_PROXY", "http://" + proxy)
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    resp = new_session(retries=0).get(target + "/x", timeout=5)
    assert resp.status_code == 200 and resp.text == "via-proxy"
    assert _Proxy.seen[-1][1] == BEARER


def test_session_url_userinfo_authenticates(target, proxy, monkeypatch):
    pytest.importorskip("requests")
    from syshttp.session import new_session

    monkeypatch.setenv("SYSHTTP_PROXY", "http://agent:s3cret@" + proxy)
    resp = new_session(retries=0).get(target + "/x", timeout=5)
    assert resp.text == "via-proxy" and _Proxy.seen[-1][1] == BASIC


def test_session_adapter_routes_with_the_credential_on_the_proxy_entry(monkeypatch):
    """https goes through CONNECT: the credential rides on the proxy entry,
    which proxylib's adapter sends to that proxy only (a session header would
    reach the origin inside the tunnel instead)."""
    pytest.importorskip("requests")
    from syshttp.session import new_session

    monkeypatch.setenv("SYSHTTP_PROXY", "http://proxy.example:3128")
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    session = new_session()
    (entry,) = session.get_adapter("https://api.example.com/").route("https://api.example.com/")
    assert entry.url == "http://proxy.example:3128" and entry.headers == {"Proxy-Authorization": BEARER}
    assert "Proxy-Authorization" not in session.headers


def test_session_honours_no_proxy(target, proxy, monkeypatch):
    pytest.importorskip("requests")
    from syshttp.session import new_session

    monkeypatch.setenv("SYSHTTP_PROXY", "http://agent:s3cret@" + proxy)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    resp = new_session(retries=0).get(target + "/x", timeout=5)
    assert resp.text == "hello" and _Proxy.seen == []


def test_session_prefix_gateway(target, gateway, monkeypatch):
    pytest.importorskip("requests")
    from syshttp.session import new_session

    monkeypatch.setenv("SYSHTTP_PROXY", gateway)
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "prefix:/fetch/")
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    session = new_session(retries=0)
    assert not session.proxies, "a prefix gateway is the destination, not a proxy"
    resp = session.get(target + "/x", timeout=5)
    assert resp.text == "via-gateway"
    assert _Gateway.seen[-1] == ("/fetch/" + target + "/x", BEARER)
    assert resp.url == target + "/x", "the caller's URL, not the gateway's, is what the response reports"
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    assert session.get(target + "/x", timeout=5).text == "hello"


# --------------------------------------------------------------------------
# A bad SYSHTTP_PROXY_TYPE is a configuration error, reported as such
# --------------------------------------------------------------------------


def test_bad_type_is_harmless_without_a_proxy(monkeypatch):
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "socks5")
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH_HEADER", "bad name")
    assert _answer() == (None,)


def test_bad_type_with_a_proxy(monkeypatch):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://proxy.example:3128")
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "socks5")
    with pytest.raises(ValueError, match="SYSHTTP_PROXY_TYPE"):
        _answer()
    # A proxy the caller names is always connect: the configured type is not consulted.
    assert not _only(proxy="http://mine:1").is_gateway


def test_an_explicit_proxy_never_gets_the_configured_credential(monkeypatch):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://corp.example:1")
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH_HEADER", "bad name")
    entry = _only(proxy="http://u:p@other.example:3128")
    assert (entry.username, entry.password, entry.headers) == ("u", "p", {})
    assert _answer(proxy="") == (None,), "curl's -x '' is direct"


def test_proxy_user_replaces_the_credential(monkeypatch):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://corp.example:1")
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    entry = _only(proxy_user="me:pw")
    assert (entry.username, entry.password, entry.headers) == ("me", "pw", {})


# --------------------------------------------------------------------------
# Redirects: every hop is re-decided; the credential never reaches an origin
# --------------------------------------------------------------------------


def test_session_redirect_hop_stays_on_the_proxy_and_bypass_is_per_hop(target, proxy, monkeypatch):
    pytest.importorskip("requests")
    from syshttp.session import new_session

    monkeypatch.setenv("SYSHTTP_PROXY", "http://" + proxy)
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BASIC)
    resp = new_session(retries=0).get(target + "/redirect", timeout=5)
    assert resp.text == "via-proxy" and [p for p, _ in _Proxy.seen] == [target + "/redirect", target + "/final"]
    assert _Target.seen == []
    # A bare session.send() and a redirect hop both go through the adapter.
    session = new_session(retries=0)
    prepared = session.prepare_request(__import__("requests").Request("GET", target + "/x"))
    assert session.send(prepared, timeout=5).text == "via-proxy"


def test_session_prefix_redirect_is_wrapped_again_and_the_caller_request_is_untouched(target, gateway, monkeypatch):
    pytest.importorskip("requests")
    import requests
    from syshttp.session import new_session

    monkeypatch.setenv("SYSHTTP_PROXY", gateway)
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "prefix:/fetch/")
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    session = new_session(retries=0)
    prepared = session.prepare_request(requests.Request("GET", target + "/redirect"))
    resp = session.send(prepared, timeout=5)
    assert resp.text == "via-gateway" and resp.url == target + "/final"
    assert [p for p, _ in _Gateway.seen] == ["/fetch/" + target + "/redirect", "/fetch/" + target + "/final"]
    assert prepared.url == target + "/redirect" and "Proxy-Authorization" not in prepared.headers


def test_session_global_proxy_vars_never_win_over_the_agent_proxy(target, proxy, monkeypatch):
    """requests merges HTTP_PROXY from the environment over session.proxies;
    the adapter passes the agent proxy explicitly so it cannot -- and the
    credential is added for the agent proxy only."""
    pytest.importorskip("requests")
    from syshttp.session import new_session

    monkeypatch.setenv("SYSHTTP_PROXY", "http://" + proxy)
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BASIC)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")  # nothing listens there
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    resp = new_session(retries=0).get(target + "/x", timeout=5)
    assert resp.text == "via-proxy"


def test_session_caller_proxies_do_not_get_the_agent_credential(target, proxy, monkeypatch):
    pytest.importorskip("requests")
    from syshttp.session import new_session

    monkeypatch.setenv("SYSHTTP_PROXY", "http://" + proxy)
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BASIC)
    resp = new_session(retries=0, proxies={"http": "http://" + proxy}).get(target + "/x", timeout=5)
    assert resp.status_code == 407, "proxies= are requests' own: no credential of syshttp's is added"
    resp = new_session(retries=0, proxies={"http": "http://agent:s3cret@" + proxy}).get(target + "/x", timeout=5)
    assert resp.text == "via-proxy"

"""Cookies and tokens under the agent proxy, both kinds: the session picks
them by the ORIGIN host (the URL the caller asked for), never by the proxy's
or the gateway's, applies the token as a per-request Authorization header,
and files what comes back under the origin again.

Loopback only: the origin listens on 127.0.0.1, the proxy and the gateway on
127.0.0.2 (``localhost`` where that is not routed), so a jar keyed by host
can tell them apart.
"""

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from test_proxy_auth import BEARER, _clean_env  # noqa: F401  (autouse fixture reused)
from syshttp.cookies import CookieSpec
from syshttp.jar import MemoryCookieJar, MemoryTokenJar


def _other_host():
    """A second loopback name for the proxy and the gateway: 127.0.0.2 where
    the system routes it (Linux, Windows), else ``localhost`` -- macOS has no
    loopback alias beyond 127.0.0.1 unless one is configured."""
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.2", 0))
        return "127.0.0.2"
    except OSError:
        return "localhost"
    finally:
        probe.close()


ORIGIN_HOST, OTHER_HOST = "127.0.0.1", _other_host()
#: What each name binds: ``localhost`` is served on 127.0.0.1.
_BIND = {"localhost": "127.0.0.1"}


def _answer(handler, body, cookie=True):
    handler.send_response(200)
    if cookie:
        handler.send_header("Set-Cookie", "sid=abc; Path=/")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class _Origin(BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):
        _Origin.seen.append((self.path, dict(self.headers)))
        if self.path.endswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        _answer(self, b"origin")

    def log_message(self, *a):
        pass


class _Proxy(BaseHTTPRequestHandler):
    """A connect proxy that checks the credential and answers for the origin."""

    seen = []

    def do_GET(self):
        _Proxy.seen.append((self.path, dict(self.headers)))
        if self.headers.get("Proxy-Authorization") != BEARER:
            self.send_response(407)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        _answer(self, b"proxy")

    def log_message(self, *a):
        pass


class _Gateway(BaseHTTPRequestHandler):
    """A prefix gateway (/fetch/<url>) relaying the origin's answer verbatim,
    including a redirect to an absolute origin URL."""

    seen = []

    def do_GET(self):
        _Gateway.seen.append((self.path, dict(self.headers)))
        inner = self.path.split("/", 2)[2]
        if inner.endswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", inner[: -len("/redirect")] + "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        _answer(self, b"gateway")

    def log_message(self, *a):
        pass


class _Server(HTTPServer):
    """HTTPServer without the reverse lookup `server_bind` does on the bound
    address (`socket.getfqdn`): on Windows that takes ~5 s for 127.0.0.2,
    which has no reverse record, per fixture."""

    def server_bind(self):
        import socketserver

        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "localhost", self.server_address[1]


def _serve(handler, host):
    handler.seen = []
    httpd = _Server((_BIND.get(host, host), 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


@pytest.fixture()
def origin():
    httpd = _serve(_Origin, ORIGIN_HOST)
    try:
        yield "http://%s:%d" % (ORIGIN_HOST, httpd.server_address[1])
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture()
def proxy(monkeypatch):
    httpd = _serve(_Proxy, OTHER_HOST)
    monkeypatch.setenv("SYSHTTP_PROXY", "http://%s:%d" % (OTHER_HOST, httpd.server_address[1]))
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    try:
        yield
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture()
def gateway(monkeypatch):
    httpd = _serve(_Gateway, OTHER_HOST)
    monkeypatch.setenv("SYSHTTP_PROXY", "http://%s:%d" % (OTHER_HOST, httpd.server_address[1]))
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "prefix:/fetch/")
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    try:
        yield
    finally:
        httpd.shutdown()
        httpd.server_close()


def _jars(token="tok123"):
    cookies = MemoryCookieJar(
        {
            ORIGIN_HOST: [
                CookieSpec(domain=ORIGIN_HOST, path="/", secure=False, expires=None, name="pre", value="1"),
            ]
        }
    )
    tokens = MemoryTokenJar({ORIGIN_HOST: token, OTHER_HOST: "never-this-one"})
    return cookies, tokens


def _client(cookies, tokens):
    from syshttp.client import HTTPClient

    return HTTPClient(retries=0, cookies=cookies, tokens=tokens)


def _names(specs):
    return sorted(c.name for c in specs)


# --------------------------------------------------------------------------
# the client
# --------------------------------------------------------------------------


def test_connect_proxy_carries_the_origin_cookie_and_token(origin, proxy):
    cookies, tokens = _jars()
    client = _client(cookies, tokens)
    resp = client.request("GET", origin + "/x", timeout=5)
    assert resp.text() == "proxy"
    path, headers = _Proxy.seen[-1]
    assert headers.get("Cookie") == "pre=1"
    assert headers.get("Authorization") == "Bearer tok123", "the ORIGIN's token, as a bearer"
    assert headers.get("Proxy-Authorization") == BEARER
    assert "Authorization" not in client.headers, "per request, never on the client"
    # What came back is the origin's: in the client, in the jar.
    assert _names(cookies[ORIGIN_HOST]) == ["pre", "sid"]
    assert OTHER_HOST not in cookies
    assert client.request("GET", origin + "/y", timeout=5).text() == "proxy"
    assert _Proxy.seen[-1][1].get("Cookie") in ("pre=1; sid=abc", "sid=abc; pre=1")


def test_prefix_gateway_picks_by_the_origin_host_not_the_gateway(origin, gateway):
    cookies, tokens = _jars()
    client = _client(cookies, tokens)
    resp = client.request("GET", origin + "/x", timeout=5)
    assert resp.text() == "gateway"
    path, headers = _Gateway.seen[-1]
    assert path == "/fetch/" + origin + "/x"
    assert headers.get("Cookie") == "pre=1"
    assert headers.get("Authorization") == "Bearer tok123", "the origin's token, not the gateway host's"
    assert headers.get("Proxy-Authorization") == BEARER
    assert resp.url == origin + "/x"
    assert _names(cookies[ORIGIN_HOST]) == ["pre", "sid"]
    assert OTHER_HOST not in cookies, "nothing is filed under the gateway"


def test_prefix_gateway_without_a_token_for_the_origin_sends_none(origin, gateway):
    cookies = MemoryCookieJar()
    tokens = MemoryTokenJar({OTHER_HOST: "gateway-host-token"})
    _client(cookies, tokens).request("GET", origin + "/x", timeout=5)
    assert "Authorization" not in _Gateway.seen[-1][1]


def test_prefix_redirect_keeps_the_origin_token_on_the_next_hop(origin, gateway):
    """Every hop through the gateway names the gateway's host on the wire, and
    the origin's on the response: the token stays with the origin."""
    cookies, tokens = _jars()
    client = _client(cookies, tokens)
    resp = client.request("GET", origin + "/redirect", timeout=5)
    assert resp.text() == "gateway" and resp.url == origin + "/final"
    paths = [p for p, _ in _Gateway.seen]
    assert paths == ["/fetch/" + origin + "/redirect", "/fetch/" + origin + "/final"]
    assert _Gateway.seen[-1][1].get("Authorization") == "Bearer tok123"
    assert _Gateway.seen[-1][1].get("Cookie") == "pre=1"


def test_explicit_authorization_and_a_scheme_bearing_token(origin, gateway):
    cookies, tokens = _jars(token="token abc123")
    client = _client(cookies, tokens)
    client.request("GET", origin + "/x", timeout=5)
    assert _Gateway.seen[-1][1].get("Authorization") == "token abc123", "a scheme is kept verbatim"
    client.request("GET", origin + "/x", headers={"Authorization": "Basic explicit"}, timeout=5)
    assert _Gateway.seen[-1][1].get("Authorization") == "Basic explicit", "the caller's header wins"
    client.request("GET", origin + "/x", auth="Bearer given", timeout=5)
    assert _Gateway.seen[-1][1].get("Authorization") == "Bearer given", "so does auth="

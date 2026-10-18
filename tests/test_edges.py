"""Edges of the jars, the Netscape reader and the hooks: flags that must
survive a round trip, file names every filesystem takes, and a failing hook
that names its variable."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from httplib import hooks


class _SetCookie(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Set-Cookie", "sid=abc; Path=/; HttpOnly; Max-Age=3600")
        self.send_header("Set-Cookie", "flash=1; Path=/")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


@pytest.fixture()
def origin():
    httpd = HTTPServer(("127.0.0.1", 0), _SetCookie)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield "http://127.0.0.1:%d" % httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_secure_jar_rows_stay_secure_in_the_session():
    pytest.importorskip("requests")
    import requests

    from httplib.cookies import CookieSpec, apply_to_session

    session = requests.Session()
    apply_to_session(
        session,
        [
            CookieSpec(domain="h.example", path="/", secure=True, expires=None, name="s", value="1"),
            CookieSpec(domain="h.example", path="/", secure=False, expires=4102444800, name="p", value="2"),
        ],
    )
    flags = {c.name: (c.secure, c.expires) for c in session.cookies}
    assert flags["s"] == (True, None) and flags["p"] == (False, 4102444800)


def test_jar_file_names_are_filesystem_safe(tmp_path):
    from httplib.jar import FileCookieJar, FileTokenJar, safe_name

    assert safe_name("::1") == "__1" and safe_name("a/b") == "a_b" and safe_name("h.example") == "h.example"
    assert FileCookieJar(tmp_path)._path("::1").name == "__1.txt"
    assert FileTokenJar(tmp_path)._path("[::1]").name == "[__1].token"


def test_netscape_loader_reads_httponly_rows(tmp_path):
    from httplib.cookies import load_netscape

    p = tmp_path / "c.txt"
    row = ["#HttpOnly_h.example", "FALSE", "/", "FALSE", "0", "a", "1"]
    p.write_text("# comment\n" + "\t".join(row) + "\n", encoding="utf-8")
    (spec,) = load_netscape(p)
    assert spec.domain == "h.example" and spec.name == "a"


def _boom(session, method, url, kwargs):
    raise KeyError("no such token")


def test_a_failing_py_hook_names_its_variable(monkeypatch):
    monkeypatch.setenv("HTTPLIB_HOOKS_BROKEN", ".")
    monkeypatch.setenv("HTTPLIB_HOOKS_BROKEN_PY", "test_edges:_boom")
    with pytest.raises(
        RuntimeError, match=r"HTTPLIB_HOOKS_BROKEN_PY \(test_edges:_boom\) failed for GET https://h/x: 'no such token'"
    ):
        hooks.call_py_hooks(None, "GET", "https://h/x", {})


def test_a_hosts_cookie_file_holds_that_hosts_cookies_only(origin):
    pytest.importorskip("requests")
    from httplib.jar import MemoryCookieJar
    from httplib.session import new_session

    jar = MemoryCookieJar()
    session = new_session(retries=0, cookies=jar)
    session.cookies.set("elsewhere", "1", domain="other.example", path="/")
    session.get(origin + "/setcookie", timeout=5)
    names = sorted(c.name for c in jar["127.0.0.1"])
    assert names == ["flash", "sid"], "other.example's cookie is not written under 127.0.0.1"
    assert "other.example" not in jar

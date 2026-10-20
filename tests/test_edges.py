"""Edges of the jars, the Netscape reader and the hooks: flags that must
survive a round trip, file names every filesystem takes, and a failing hook
that names its variable."""

import pytest

from syshttp import hooks
from test_cookies import _client, _get, _jar, web  # noqa: F401  (web is a fixture)


def test_secure_jar_rows_stay_secure_in_the_client(web):  # noqa: F811
    from syshttp.cookies import CookieSpec
    from syshttp.jar import MemoryCookieJar

    jar = MemoryCookieJar(
        {
            "h.example": [
                CookieSpec(domain="h.example", path="/", secure=True, expires=None, name="s", value="1"),
                CookieSpec(domain="h.example", path="/", secure=False, expires=4102444800, name="p", value="2"),
            ]
        }
    )
    client = _client(web, cookies=jar)
    assert _get(client, "http://h.example/") == "p=2", "a Secure row is not sent over http"
    flags = {c.name: (c.secure, c.expires) for c in client._cookies._rows.values()}
    assert flags["s"] == (True, None) and flags["p"] == (False, 4102444800)
    assert _jar(client) == [("p", "h.example", "/", "2"), ("s", "h.example", "/", "1")]


def test_jar_file_names_are_filesystem_safe(tmp_path):
    from syshttp.jar import FileCookieJar, FileTokenJar, safe_name

    assert safe_name("::1") == "__1" and safe_name("a/b") == "a_b" and safe_name("h.example") == "h.example"
    assert FileCookieJar(tmp_path)._path("::1").name == "__1.txt"
    assert FileTokenJar(tmp_path)._path("[::1]").name == "[__1].token"


def test_netscape_loader_reads_httponly_rows(tmp_path):
    from syshttp.cookies import load_netscape

    p = tmp_path / "c.txt"
    row = ["#HttpOnly_h.example", "FALSE", "/", "FALSE", "0", "a", "1"]
    p.write_text("# comment\n" + "\t".join(row) + "\n", encoding="utf-8")
    (spec,) = load_netscape(p)
    assert spec.domain == "h.example" and spec.name == "a"


def _boom(session, method, url, kwargs):
    raise KeyError("no such token")


def test_a_failing_py_hook_names_its_variable(monkeypatch):
    monkeypatch.setenv("SYSHTTP_HOOKS_BROKEN", ".")
    monkeypatch.setenv("SYSHTTP_HOOKS_BROKEN_PY", "test_edges:_boom")
    with pytest.raises(
        RuntimeError, match=r"SYSHTTP_HOOKS_BROKEN_PY \(test_edges:_boom\) failed for GET https://h/x: 'no such token'"
    ):
        hooks.call_py_hooks(None, "GET", "https://h/x", {})


def test_a_hosts_cookie_file_holds_that_hosts_cookies_only(web):  # noqa: F811
    from syshttp.jar import MemoryCookieJar

    jar = MemoryCookieJar()
    client = _client(web, cookies=jar)
    _get(client, "http://elsewhere.example/", "other=1; Path=/")
    _get(client, "http://origin.example/", "sid=abc; Path=/", "flash=1; Path=/")
    assert sorted(c.name for c in jar["origin.example"]) == ["flash", "sid"]
    assert [c.name for c in jar["elsewhere.example"]] == ["other"]

"""Set-Cookie handling to RFC 6265 and the jar rows that carry it: the
domain rules, the parser, the session's single copy of each cookie, and the
reload of host-only rows."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit

import pytest

from syshttp.cookies import CookieSpec, cookie_applies, load_netscape, save_netscape, set_cookie_specs
from syshttp.env import HTTPEnv
from syshttp.jar import FileCookieJar
from syshttp.retry import retry_after

NOW = 1_000_000_000.0


def one(header, host="www.example.com", **kwargs):
    specs = set_cookie_specs([header], host, **{"now": NOW, **kwargs})
    return specs[0] if specs else None


# -- domain rules -----------------------------------------------------------


def test_a_foreign_domain_is_dropped_on_set_and_on_delete():
    assert one("sid=evil; Domain=bank.example", host="evil.example") is None
    assert one("sid=; Max-Age=0; Domain=bank.example", host="evil.example") is None


def test_a_public_suffix_domain_is_dropped():
    assert one("sid=1; Domain=com", host="example.com") is None
    assert one("sid=1; Domain=.co.uk", host="shop.co.uk") is None
    assert one("sid=1; Domain=test", host="a.test") is None


def test_a_domain_equal_to_a_single_label_host_is_host_only():
    spec, gone = one("k=v; Domain=localhost", host="localhost")
    assert (spec.domain, spec.subdomains, gone) == ("localhost", False, False)
    spec, _ = one("k=v; Domain=wiki", host="wiki")
    assert (spec.domain, spec.subdomains) == ("wiki", False)


def test_an_ip_host_takes_only_a_host_only_cookie():
    assert one("k=v; Domain=1.2.3.4", host="9.9.9.9") is None
    spec, _ = one("k=v; Domain=1.2.3.4", host="1.2.3.4")
    assert (spec.domain, spec.subdomains) == ("1.2.3.4", False)
    assert one("k=v; Domain=3.4", host="1.2.3.4") is None


def test_a_domain_without_a_dot_covers_subdomains():
    spec, gone = one("sid=1; Domain=example.com", host="www.example.com")
    assert (spec.domain, spec.subdomains, gone) == ("example.com", True, False)
    assert cookie_applies(spec, "http://login.example.com/", now=NOW)
    assert cookie_applies(spec, "http://example.com/", now=NOW)
    spec, _ = one("sid=1; Domain=.example.com", host="www.example.com")
    assert (spec.domain, spec.subdomains) == ("example.com", True)


def test_a_cookie_without_domain_is_host_only():
    spec, _ = one("sid=1")
    assert (spec.domain, spec.subdomains) == ("www.example.com", False)
    assert not cookie_applies(spec, "http://sub.www.example.com/", now=NOW)


def test_a_sibling_host_cannot_set_the_domain():
    assert one("sid=1; Domain=api.example.com", host="www.example.com") is None


# -- parsing ----------------------------------------------------------------


def test_the_default_path_is_the_request_directory():
    assert one("a=1")[0].path == "/"
    assert one("a=1", request_path="/app/login")[0].path == "/app"
    assert one("a=1", request_path="/app/")[0].path == "/app"
    assert one("a=1", request_path="/login?x=/y")[0].path == "/"
    assert one("a=1; Path=/x", request_path="/app/login")[0].path == "/x"
    assert one("a=1; Path=relative", request_path="/app/login")[0].path == "/app"


def test_unknown_attributes_and_partitioned_are_ignored():
    assert [s.name for s, _ in set_cookie_specs(["sid=1; Path=/; Priority=High"], "h", now=NOW)] == ["sid"]
    spec, _ = one("sid=1; Partitioned; SameSite=Lax; Foo=bar")
    assert (spec.name, spec.value, spec.path) == ("sid", "1", "/")


def test_a_value_may_hold_spaces_and_json():
    assert one("sid=a b; Path=/")[0].value == "a b"
    assert one('sid={"a":1}; Path=/')[0].value == '{"a":1}'
    assert one("sid=a=b")[0].value == "a=b"


def test_a_header_without_a_pair_is_skipped():
    assert set_cookie_specs(["; Path=/", "novalue", "=x", ""], "h", now=NOW) == []


def test_attribute_names_are_case_insensitive_and_flags_are_read():
    spec, _ = one("sid=1; SECURE; httponly; PATH=/p; max-age=60")
    assert (spec.secure, spec.http_only, spec.path, spec.expires) == (True, True, "/p", int(NOW) + 60)


def test_max_age_beats_expires_in_either_order():
    date = "Expires=Sun, 06 Nov 2033 08:49:37 GMT"
    assert one("a=1; Max-Age=60; " + date)[0].expires == int(NOW) + 60
    assert one("a=1; " + date + "; Max-Age=60")[0].expires == int(NOW) + 60
    assert one("a=1; " + date + "; Max-Age=0")[1] is True
    assert one("a=1; Max-Age=-5")[1] is True


@pytest.mark.parametrize(
    "date", ["Sun, 06 Nov 2001 08:49:37 GMT", "Sunday, 06-Nov-01 08:49:37 GMT", "Sun Nov  6 08:49:37 2001"]
)
def test_every_http_date_form_is_read_as_utc(date):
    spec, gone = one("a=1; Expires=" + date, now=1.5e9)
    assert (spec.expires, gone) == (1005036577, True)


def test_a_superscript_digit_is_not_a_number():
    assert one("a=1; Max-Age=²")[0].expires is None
    assert retry_after([("Retry-After", "²")]) is None


def test_an_expiry_is_cut_to_400_days():
    spec, _ = one("a=1; Max-Age=99999999999")
    assert spec.expires == int(NOW) + 400 * 24 * 3600


def test_an_expired_or_empty_cookie_is_gone():
    assert one("a=; Path=/")[1] is True
    assert one("a=1; Expires=Thu, 01 Jan 1970 00:00:01 GMT")[1] is True


def test_retry_after_dates_are_utc():
    when = 784111777.0  # Sun, 06 Nov 1994 08:49:37 GMT
    for value in ("Sun, 06 Nov 1994 08:49:37 GMT", "Sunday, 06-Nov-94 08:49:37 GMT", "Sun Nov  6 08:49:37 1994"):
        assert retry_after([("Retry-After", value)], now=when - 3600) == 3600.0


# -- Netscape rows ----------------------------------------------------------


def test_load_netscape_keeps_an_empty_valued_row_and_reads_a_bad_expiry(tmp_path):
    path = tmp_path / "jar.txt"
    path.write_bytes(
        b"# Netscape HTTP Cookie File\n"
        b"h.example\tFALSE\t/\tFALSE\t0\tempty\t\n"
        b"h.example\tFALSE\t/\tFALSE\t0\ttrimmed\n"
        b"h.example\tFALSE\t/\tFALSE\t\xc2\xb2\tbad\tv\n"
        b"h.example\tFALSE\t/\tFALSE\t0\tok\tv\n"
    )
    rows = {c.name: c for c in load_netscape(path)}
    assert set(rows) == {"empty", "trimmed", "bad", "ok"}
    assert rows["empty"].value == "" and rows["bad"].expires is None


def test_httponly_and_the_include_subdomains_flag_round_trip_through_the_file_jar(tmp_path):
    jar = FileCookieJar(tmp_path)
    jar["h.example"] = [CookieSpec("h.example", "/", True, 2_000_000_000, "a", "1", http_only=True, subdomains=True)]
    text = (tmp_path / "cookies" / "h.example.txt").read_text(encoding="utf-8")
    assert "#HttpOnly_h.example\tTRUE\t/\tTRUE\t2000000000\ta\t1" in text
    assert jar["h.example"] == [
        CookieSpec("h.example", "/", True, 2_000_000_000, "a", "1", http_only=True, subdomains=True)
    ]


def test_save_netscape_accepts_specs_directly(tmp_path):
    path = tmp_path / "jar.txt"
    save_netscape([CookieSpec("h", "/", False, None, "a", "1")], path)
    assert load_netscape(path) == [CookieSpec("h", "/", False, None, "a", "1")]


# -- the client -------------------------------------------------------------


class _Origin(BaseHTTPRequestHandler):
    """A proxy that answers for any host in an absolute-form request URL:
    ``?c=<Set-Cookie>`` is sent back, ``Cookie`` is echoed in the body."""

    protocol_version = "HTTP/1.1"

    def do_GET(self):
        url = urlsplit(self.path)
        body = (self.headers.get("Cookie") or "").encode()
        self.send_response(200)
        for header in parse_qs(url.query).get("c", []):
            self.send_header("Set-Cookie", header)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture()
def web():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Origin)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    env = HTTPEnv(environ={"SYSHTTP_PROXY": "http://127.0.0.1:%d" % server.server_address[1]})
    try:
        yield env
    finally:
        server.shutdown()
        server.server_close()


def _client(env, **options):
    from syshttp.client import HTTPClient

    return HTTPClient(env=env, retries=0, **options)


def _get(client, url, *set_cookies):
    query = "".join("&c=" + quote(c) for c in set_cookies)
    return client.request("GET", url + ("?" + query[1:] if query else ""), timeout=10).text()


def _jar(client):
    """The client's cookies as (name, domain, path, value): a domain cookie's
    domain with its leading dot."""
    rows = client._cookies._rows.values()
    return sorted((c.name, ("." if c.subdomains else "") + c.domain, c.path, c.value) for c in rows)


def test_a_foreign_host_cannot_set_or_delete_a_cookie_in_the_client_or_the_file(web, tmp_path):
    client = _client(web, cookies=FileCookieJar(tmp_path))
    _get(client, "http://bank.test/", "real=bank-session; Path=/")
    _get(client, "http://evil.test/", "sid=attacker; Domain=bank.test; Path=/")
    _get(client, "http://evil.test/", "real=; Max-Age=0; Domain=bank.test; Path=/")
    _get(client, "http://evil.test/", "tld=1; Domain=test")
    assert _get(client, "http://bank.test/") == "real=bank-session"
    assert _jar(client) == [("real", "bank.test", "/", "bank-session")]
    saved = (tmp_path / "cookies" / "bank.test.txt").read_text(encoding="utf-8")
    assert "real" in saved and "attacker" not in saved


def test_one_copy_per_cookie_with_the_default_path(web):
    client = _client(web)
    _get(client, "http://bank.test/app/login", "dir=1")
    assert _jar(client) == [("dir", "bank.test", "/app", "1")]
    _get(client, "http://www.example.test/", "sso=1; Domain=example.test; Path=/")
    assert _jar(client)[-1][:2] == ("sso", ".example.test")
    assert len(_jar(client)) == 2
    assert _get(client, "http://api.example.test/") == "sso=1"


def test_a_deletion_that_names_the_domain_differently_is_applied(web):
    from syshttp.jar import MemoryCookieJar

    client = _client(web, cookies=MemoryCookieJar())
    _get(client, "http://bank.test/", "k=1; Path=/")
    assert _jar(client) == [("k", "bank.test", "/", "1")]
    _get(client, "http://bank.test/", "k=; Max-Age=0; Domain=bank.test; Path=/")
    assert _jar(client) == []
    _get(client, "http://bank.test/", "e=1; Path=/")
    _get(client, "http://bank.test/", "e=; Path=/")
    assert _jar(client) == []


def test_a_host_only_cookie_does_not_reach_a_subdomain(web):
    client = _client(web)
    _get(client, "http://example.test/", "own=1; Path=/")
    _get(client, "http://example.test/", "wide=1; Domain=example.test; Path=/")
    assert sorted(_get(client, "http://example.test/").split("; ")) == ["own=1", "wide=1"]
    assert _get(client, "http://sub.example.test/") == "wide=1"


def test_a_single_label_host_survives_a_reload(web, tmp_path):
    first = _client(web, cookies=FileCookieJar(tmp_path))
    _get(first, "http://localhost/", "k=v; Path=/")
    _get(first, "http://wiki/", "w=1; Path=/")
    assert (tmp_path / "cookies" / "localhost.txt").read_text(encoding="utf-8").splitlines()[1] == (
        "localhost\tFALSE\t/\tFALSE\t0\tk\tv"
    )
    second = _client(web, cookies=FileCookieJar(tmp_path))
    assert _get(second, "http://localhost/") == "k=v"
    assert _get(second, "http://wiki/") == "w=1"


def test_httponly_reaches_the_file(web, tmp_path):
    client = _client(web, cookies=FileCookieJar(tmp_path))
    _get(client, "http://bank.test/", "sid=abc; HttpOnly; Path=/")
    _get(client, "http://bank.test/", "wide=1; Domain=bank.test; Path=/")
    rows = (tmp_path / "cookies" / "bank.test.txt").read_text(encoding="utf-8").splitlines()[1:]
    assert "#HttpOnly_bank.test\tFALSE\t/\tFALSE\t0\tsid\tabc" in rows
    assert "bank.test\tTRUE\t/\tFALSE\t0\twide\t1" in rows


def test_a_parent_domain_cookie_reaches_the_hosts_file(web, tmp_path):
    client = _client(web, cookies=FileCookieJar(tmp_path))
    _get(client, "http://www.example.test/", "sso=1; Domain=example.test; Path=/")
    rows = (tmp_path / "cookies" / "www.example.test.txt").read_text(encoding="utf-8").splitlines()[1:]
    assert rows == ["example.test\tTRUE\t/\tFALSE\t0\tsso\t1"]
    again = _client(web, cookies=FileCookieJar(tmp_path))
    assert _get(again, "http://www.example.test/") == "sso=1"


def test_a_loaded_host_only_row_stays_on_its_host(web):
    from syshttp.jar import MemoryCookieJar

    jar = MemoryCookieJar({"example.test": [CookieSpec("example.test", "/", False, None, "hostonly", "1")]})
    client = _client(web, cookies=jar)
    assert _get(client, "http://example.test/") == "hostonly=1"
    assert _get(client, "http://sub.example.test/") == ""


def test_a_loaded_domain_row_reaches_subdomains_and_a_dotted_one_is_the_same(web):
    from syshttp.jar import MemoryCookieJar

    rows = [
        CookieSpec(".example.test", "/", False, None, "dot", "1"),
        CookieSpec("example.test", "/", False, None, "flag", "2", subdomains=True),
    ]
    client = _client(web, cookies=MemoryCookieJar({"example.test": rows, "sub.example.test": []}))
    assert sorted(_get(client, "http://example.test/").split("; ")) == ["dot=1", "flag=2"]
    assert _jar(client) == [("dot", ".example.test", "/", "1"), ("flag", ".example.test", "/", "2")]
    assert sorted(_get(client, "http://sub.example.test/").split("; ")) == ["dot=1", "flag=2"]


def test_a_path_cookie_is_sent_to_its_path_only_and_longer_paths_come_first(web):
    client = _client(web)
    _get(client, "http://bank.test/", "all=1; Path=/")
    _get(client, "http://bank.test/", "app=2; Path=/app")
    assert _get(client, "http://bank.test/other") == "all=1"
    assert _get(client, "http://bank.test/app/x") == "app=2; all=1"


def test_a_secure_cookie_goes_over_https_only_and_an_expired_one_goes_nowhere(web):
    client = _client(web)
    _get(
        client,
        "http://bank.test/",
        "s=1; Secure; Path=/",
        "gone=1; Max-Age=0; Path=/",
        "past=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/",
    )
    assert _get(client, "http://bank.test/") == ""
    assert _jar(client) == [("s", "bank.test", "/", "1")]


# -- domain_covers -----------------------------


@pytest.mark.parametrize(
    "domain, host, covers",
    [
        ("example.com", "example.com", True),
        ("example.com", "www.example.com", False),
        (".example.com", "www.example.com", True),
        (".example.com", "example.com", True),
        (".example.com", "badexample.com", False),
        (".Example.COM", "WWW.example.com", True),
        ("", "example.com", False),
        (".example.com", "", False),
    ],
)
def test_domain_covers(domain, host, covers):
    from syshttp.cookies import domain_covers

    assert domain_covers(domain, host) is covers

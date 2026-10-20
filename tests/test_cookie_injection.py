"""A Set-Cookie value cannot end a row of a jar file and start another for a
domain it has no right to: a header with a control character is ignored, a
jar file is read at newlines only, a by-host file gives a host the rows that
cover it, and a row with a control character or a tab is not written."""

import pytest

from client_fakes import Script
from client_wire import Wire, response
from syshttp import HTTPEnv
from syshttp.client import HTTPClient
from syshttp.cookies import CookieSpec, load_netscape, save_netscape, set_cookie_specs

CONTROLS = ["\x00", "\x01", "\x08", "\x0b", "\x0c", "\x0d", "\x1c", "\x1d", "\x1e", "\x1f", "\x7f"]
# What str.splitlines() ends a line at, besides the newlines.
SEPARATORS = ["\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", chr(0x2028), chr(0x2029)]


def planted(sep):
    """A cookie value that, written to a jar file and read by splitlines(), is a whole row for .bank.example."""
    return "x" + sep + ".bank.example\tTRUE\t/\tFALSE\t0\tsession\tattacker"


# -- a Set-Cookie value cannot plant a cookie for another domain -----------------


@pytest.mark.parametrize("control", CONTROLS)
def test_a_set_cookie_with_a_control_character_is_ignored_whole(control):
    for header in ("a=b%sc" % control, "a%s=b" % control, "a=b; Path=/x%s" % control, "a=b; Domain=h%s" % control):
        assert set_cookie_specs([header], "h.example", now=0) == [], repr(header)


def test_a_tab_is_allowed_in_a_value_where_the_rfc_allows_it():
    ((spec, gone),) = set_cookie_specs(["a=b\tc"], "h.example", now=0)
    assert (spec.name, spec.value, gone) == ("a", "b\tc", False)


@pytest.mark.parametrize("sep", SEPARATORS)
def test_a_value_cannot_end_a_jar_row_and_start_one_for_another_domain(sep, tmp_path):
    env = HTTPEnv(environ={"SYSHTTP_HOME": str(tmp_path)})
    evil = Script({"https://evil.example/": (200, [("Set-Cookie", "a=" + planted(sep))])})
    with HTTPClient(evil, cookies="shared", env=env) as client:
        client.request("GET", "https://evil.example/")
    bank = Script()
    with HTTPClient(bank, cookies="shared", env=env) as client:
        client.request("GET", "https://bank.example/")
    assert "Cookie" not in bank.sent[0][2], "no row for .bank.example came out of evil.example's cookie"
    shared = tmp_path / "cookies" / "shared.txt"
    assert ".bank.example" not in (shared.read_text(encoding="utf-8") if shared.exists() else "")


@pytest.mark.parametrize("sep", SEPARATORS)
def test_the_same_by_host_files_keep_the_planted_row_out_too(sep, tmp_path):
    env = HTTPEnv(environ={"SYSHTTP_HOME": str(tmp_path)})
    evil = Script({"https://evil.example/": (200, [("Set-Cookie", "a=" + planted(sep))])})
    with HTTPClient(evil, cookies=True, env=env) as client:
        client.request("GET", "https://evil.example/")
    bank = Script()
    with HTTPClient(bank, cookies=True, env=env) as client:
        client.request("GET", "https://evil.example/")
        client.request("GET", "https://bank.example/")
    assert "Cookie" not in bank.sent[1][2]


def test_a_planted_row_on_the_wire_reaches_no_other_host(tmp_path):
    """The whole path with a real server: the header goes through http.client
    as sent, and the cookie it carries is dropped."""
    header = "a=" + planted("\x0c")

    def script(request):
        if request.target.startswith("http://evil.example"):
            return response(200, {"Set-Cookie": header})
        return response(body=(request.header("Cookie") or "-").encode())

    env = HTTPEnv(environ={"SYSHTTP_HOME": str(tmp_path)})
    with Wire(script) as proxy:
        for _ in range(2):  # the second client reads the file the first wrote
            with HTTPClient(proxymap="127.0.0.1:%d" % proxy.port, cookies="shared", env=env) as client:
                client.request("GET", "http://evil.example/")
                assert client.request("GET", "http://bank.example/").text() == "-"


def test_a_file_that_holds_a_row_for_another_domain_gives_it_to_that_domain_only(tmp_path):
    """A file written before the fix, or by hand: by-host files give a host
    the rows that cover it (or its group) and nothing else."""
    jar_dir = tmp_path / "cookies"
    jar_dir.mkdir()
    (jar_dir / "evil.example.txt").write_text(
        "# Netscape HTTP Cookie File\n"
        "evil.example\tFALSE\t/\tFALSE\t0\town\t1\n"
        ".bank.example\tTRUE\t/\tFALSE\t0\tsession\tattacker\n",
        encoding="utf-8",
    )
    env = HTTPEnv(environ={"SYSHTTP_HOME": str(tmp_path)})
    script = Script()
    with HTTPClient(script, cookies=True, env=env) as client:
        client.request("GET", "https://evil.example/")
        client.request("GET", "https://bank.example/")
    assert script.sent[0][2].get("Cookie") == "own=1"
    assert "Cookie" not in script.sent[1][2]


def test_a_named_jar_file_keeps_every_row_it_holds(tmp_path):
    (tmp_path / "cookies").mkdir()
    (tmp_path / "cookies" / "shared.txt").write_text(
        "# Netscape HTTP Cookie File\nbank.example\tFALSE\t/\tFALSE\t0\tk\tv\n", encoding="utf-8"
    )
    script = Script()
    with HTTPClient(script, cookies="shared", env=HTTPEnv(environ={"SYSHTTP_HOME": str(tmp_path)})) as client:
        client.request("GET", "https://bank.example/")
    assert script.sent[0][2]["Cookie"] == "k=v"


def test_a_host_group_loads_the_rows_of_every_member_from_the_first_hosts_file(tmp_path):
    (tmp_path / "cookies").mkdir()
    (tmp_path / "cookies" / "app.example.com.txt").write_text(
        "# Netscape HTTP Cookie File\n"
        "app.example.com\tFALSE\t/\tFALSE\t0\tfirst\t1\n"
        "app.example.net\tFALSE\t/\tFALSE\t0\tsecond\t2\n"
        "other.example\tFALSE\t/\tFALSE\t0\tstray\t3\n",
        encoding="utf-8",
    )
    script = Script()
    env = HTTPEnv(environ={"SYSHTTP_HOME": str(tmp_path)})
    with HTTPClient(script, cookies=True, env=env, cookie_hosts=[["app.example.com", "app.example.net"]]) as client:
        client.request("GET", "https://app.example.net/")
    assert sorted(script.sent[0][2]["Cookie"].split("; ")) == ["first=1", "second=2"]


@pytest.mark.parametrize("sep", SEPARATORS)
def test_a_jar_file_is_split_at_newlines_only(sep, tmp_path):
    path = tmp_path / "jar.txt"
    value = "v" + sep + "w"
    path.write_text(
        "# c\n.bank.example\tTRUE\t/\tFALSE\t0\tk\t%s\nother.example\tFALSE\t/\tFALSE\t0\tn\t1\n" % value,
        encoding="utf-8",
    )
    rows = load_netscape(path)
    if sep in CONTROLS:
        assert [r.name for r in rows] == ["n"], "a row holding a control character is skipped"
    else:
        assert [(r.name, r.value) for r in rows] == [("k", value), ("n", "1")]


def test_a_jar_file_with_crlf_ends_reads_as_lf_ends(tmp_path):
    path = tmp_path / "jar.txt"
    path.write_bytes(b"# c\r\nh.example\tFALSE\t/\tFALSE\t0\tk\tv\r\n")
    assert [(r.name, r.value) for r in load_netscape(path)] == [("k", "v")]


def test_a_row_with_a_control_character_or_a_tab_is_not_written(tmp_path):
    path = tmp_path / "jar.txt"
    rows = [
        CookieSpec("h.example", "/", False, None, "good", "1"),
        CookieSpec("h.example", "/", False, None, "ctl", "a\x0cb"),
        CookieSpec("h.example", "/", False, None, "tab", "a\tb"),
        CookieSpec("h.example", "/x\x0b", False, None, "path", "1"),
        CookieSpec("h.example\x1c.bank.example", "/", False, None, "domain", "1"),
        CookieSpec("h.example", "/", False, None, "n\ram", "1"),
    ]
    save_netscape(rows, path)
    assert path.read_text(encoding="utf-8").splitlines()[1:] == ["h.example\tFALSE\t/\tFALSE\t0\tgood\t1"]

"""HTTPEnv: every setting a full name read as <PREFIX><NAME> for each prefix
of the argument, else SYSHTTP_PREFIX (a :-list), else the empty prefix."""

import subprocess
import sys
from pathlib import Path

import pytest

import proxylib

from syshttp import HTTPEnv, hooks, jar, proxy

SRC = Path(__file__).resolve().parents[1] / "src"


def _entry(env=None, url="https://api.example.com/"):
    (entry,) = proxylib.lookup(proxy.proxy_map(env=env), url)
    return entry


def test_the_default_is_the_empty_prefix(monkeypatch):
    env = HTTPEnv()
    assert env.prefixes == ("",) and env.name("SYSHTTP_PROXY") == "SYSHTTP_PROXY"
    monkeypatch.setenv("SYSHTTP_PROXY", "http://mine:1")
    assert _entry().url == "http://mine:1"


def test_a_prefix_is_used_literally_on_every_name(monkeypatch):
    monkeypatch.setenv("SYSHTTP_PREFIX", "MYTOOL_")
    monkeypatch.setenv("SYSHTTP_PROXY", "http://ignored:1")
    monkeypatch.setenv("MYTOOL_SYSHTTP_PROXY", "http://mytool:1")
    monkeypatch.setenv("MYTOOL_SYSHTTP_PROXY_AUTH", "Bearer t")
    entry = _entry()
    assert (entry.url, entry.headers) == ("http://mytool:1", {"Proxy-Authorization": "Bearer t"})
    # Read at each lookup, not at import or construction.
    env = HTTPEnv()
    monkeypatch.setenv("SYSHTTP_PREFIX", "OTHER_")
    assert env.prefixes == ("OTHER_",)


def test_a_prefix_without_the_empty_entry_opts_out_of_the_defaults(monkeypatch):
    monkeypatch.setenv("SYSHTTP_PREFIX", "MYTOOL_")
    monkeypatch.setenv("HTTPS_PROXY", "http://machine:1")
    monkeypatch.setenv("MYTOOL_HTTPS_PROXY", "http://mytool:1")
    assert _entry().url == "http://mytool:1"
    monkeypatch.delenv("MYTOOL_HTTPS_PROXY")
    assert _entry() is None


def test_the_prefixes_are_tried_in_order_each_name_on_its_own(monkeypatch):
    environ = {
        "SYSHTTP_PREFIX": "A_:B_:",
        "B_SYSHTTP_HOME": "/b",
        "SYSHTTP_HOME": "/default",
        "A_CA_BUNDLE": "/a.pem",
        "CA_BUNDLE": "/default.pem",
        "SYSHTTP_HOOK_SKIP": "X",
    }
    env = HTTPEnv(environ=environ)
    assert env.prefixes == ("A_", "B_", "")
    assert env.find("SYSHTTP_HOME") == ("B_SYSHTTP_HOME", "/b")
    assert env.get("CA_BUNDLE") == "/a.pem"
    assert env.find("SYSHTTP_HOOK_SKIP") == ("SYSHTTP_HOOK_SKIP", "X")
    assert env.name("SYSHTTP_HOME") == "A_SYSHTTP_HOME"


def test_every_spelling_is_tried_under_a_prefix_before_the_next_prefix():
    env = HTTPEnv("A_:", environ={"A_HTTPS_PROXY": "http://upper:1", "https_proxy": "http://lower:1"})
    assert env.find("https_proxy", "HTTPS_PROXY") == ("A_HTTPS_PROXY", "http://upper:1")


@pytest.mark.parametrize("blank", ["", "  "])
def test_a_blank_syshttp_prefix_is_the_empty_prefix(blank, monkeypatch):
    monkeypatch.setenv("SYSHTTP_PREFIX", blank)
    assert HTTPEnv().prefixes == ("",)


def test_the_argument_wins_over_syshttp_prefix(monkeypatch):
    monkeypatch.setenv("SYSHTTP_PREFIX", "MYTOOL_")
    monkeypatch.setenv("ARG_SYSHTTP_PROXY", "http://arg:1")
    monkeypatch.setenv("MYTOOL_SYSHTTP_PROXY", "http://mytool:1")
    assert _entry(HTTPEnv("ARG_")).url == "http://arg:1"
    assert _entry(HTTPEnv(["ARG_"])).url == "http://arg:1"


def test_prefixes_are_upper_case_and_listed_once():
    env = HTTPEnv("my_tool_:MY_TOOL_: ")
    assert env.prefixes == ("MY_TOOL_", "")
    assert env.name("SYSHTTP_HOME") == "MY_TOOL_SYSHTTP_HOME"


def test_an_empty_list_reads_nothing():
    env = HTTPEnv([], environ={"SYSHTTP_PROXY": "http://p:1"})
    assert env.get("SYSHTTP_PROXY") is None and env.name("SYSHTTP_PROXY") == "SYSHTTP_PROXY"


@pytest.mark.parametrize("bad", ["A B", "A-B", "A.B", "A=B"])
def test_a_malformed_prefix_is_a_value_error(bad, monkeypatch):
    with pytest.raises(ValueError, match="prefixes"):
        HTTPEnv(bad)
    monkeypatch.setenv("SYSHTTP_PREFIX", bad)
    env = HTTPEnv()  # constructing reads nothing
    with pytest.raises(ValueError, match="SYSHTTP_PREFIX"):
        env.prefixes


def test_two_instances_are_isolated():
    environ = {"A_SYSHTTP_PROXY": "http://a:1", "B_SYSHTTP_PROXY": "http://b:1"}
    assert _entry(HTTPEnv("A_", environ=environ)).url == "http://a:1"
    assert _entry(HTTPEnv("B_", environ=environ)).url == "http://b:1"


def test_a_message_names_the_variable_that_was_set():
    environ = {"MYTOOL_SYSHTTP_PROXY": "http://p:1", "SYSHTTP_PROXY_TYPE": "socks5"}
    with pytest.raises(ValueError, match="'SYSHTTP_PROXY_TYPE'|SYSHTTP_PROXY_TYPE must"):
        _entry(HTTPEnv("MYTOOL_:", environ=environ))


def test_jar_root(tmp_path):
    assert jar.store_root(env=HTTPEnv(environ={"SYSHTTP_HOME": str(tmp_path)})) == tmp_path
    assert jar.store_root(env=HTTPEnv("AGENTS_", environ={"AGENTS_SYSHTTP_HOME": str(tmp_path)})) == tmp_path
    default = jar.store_root(env=HTTPEnv(environ={}))
    assert default.name == "syshttp" and default == jar.default_root(env=HTTPEnv(environ={}))
    if sys.platform not in ("win32", "darwin"):
        # An OS path, read as written whatever the prefixes.
        env = HTTPEnv("AGENTS_", environ={"XDG_STATE_HOME": str(tmp_path)})
        assert jar.default_root(env=env) == tmp_path / "syshttp"


def test_wrapper_environment_names_follow_the_first_prefix():
    env = HTTPEnv("MYTOOL_:", environ={"SYSHTTP_HOOK_SKIP": "Z"})
    got = hooks.wrapper_environment(hooks.Hook("K", None, "c", None), "https://h/", "/bin/curl", env=env)
    assert got == {
        "MYTOOL_SYSHTTP_HOOK_URL": "https://h/",
        "MYTOOL_SYSHTTP_HOOK_KEY": "K",
        "MYTOOL_SYSHTTP_HOOK_CURL": "/bin/curl",
        "MYTOOL_SYSHTTP_HOOK_SKIP": "K,Z",
    }


def test_hooks_are_read_under_every_prefix_the_first_winning_per_variable():
    environ = {
        "A_SYSHTTP_HOOKS_X": "one",
        "SYSHTTP_HOOKS_X": "ignored",
        "SYSHTTP_HOOKS_x_PY": "m:f",
        "SYSHTTP_HOOKS_Y": "two",
        "SYSHTTP_HOOKS_Y_CURL": "c",
    }
    found = hooks.hooks_from_env(env=HTTPEnv("A_:", environ=environ))
    assert [(h.key, h.pattern.pattern, h.variable) for h in found] == [
        ("X", "one", "A_SYSHTTP_HOOKS_X"),
        ("Y", "two", "SYSHTTP_HOOKS_Y"),
    ]


def test_session_reads_through_its_env(monkeypatch):
    pytest.importorskip("requests")
    from syshttp.session import new_session

    monkeypatch.setenv("SYSHTTP_PROXY", "http://ignored:1")
    environ = {"MYTOOL_SYSHTTP_PROXY": "http://mytool:3128", "MYTOOL_SYSHTTP_PROXY_AUTH": "Bearer t"}
    adapter = new_session(env=HTTPEnv("MYTOOL_", environ=environ)).get_adapter("https://api.example.com/")
    (entry,) = adapter.route("https://api.example.com/")
    assert (entry.url, entry.headers) == ("http://mytool:3128", {"Proxy-Authorization": "Bearer t"})


def test_importing_reads_no_variable():
    """A malformed SYSHTTP_PREFIX fails the first lookup; importing every
    module must not be one."""
    code = (
        "import sys; sys.path.insert(0, %r); "
        "import syshttp, syshttp.env, syshttp.proxy, syshttp.jar, syshttp.hooks, syshttp.cookies, "
        "syshttp.tls, syshttp.retry, syshttp.session, syshttp.fetch; print('ok')" % str(SRC)
    )
    run = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env={"SYSHTTP_PREFIX": "not a prefix", "SYSTEMROOT": "C:\\Windows", "PATH": ""},
    )
    assert run.stdout.strip() == "ok", run.stderr


def test_family_strips_values_and_skips_blank_ones():
    env = HTTPEnv(environ={"SYSHTTP_HOOKS_A": "  x  ", "SYSHTTP_HOOKS_B": "   ", "SYSHTTP_HOOKS_C": ""})
    assert list(env.family("SYSHTTP_HOOKS_")) == [("A", "x", "SYSHTTP_HOOKS_A")]

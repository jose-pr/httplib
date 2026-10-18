"""HTTPEnv: the prefix every setting is read under -- the argument, else
HTTPLIB_PREFIX, else HTTPLIB -- and the conventional variables read under
any prefix."""

import subprocess
import sys
from pathlib import Path

import pytest

from httplib import HTTPEnv, hooks, jar, proxy

SRC = Path(__file__).resolve().parents[1] / "src"


def test_default_prefix_is_httplib(monkeypatch):
    env = HTTPEnv()
    assert env.prefix == "HTTPLIB" and env.name("PROXY") == "HTTPLIB_PROXY"
    monkeypatch.setenv("HTTPLIB_PROXY", "http://mine:1")
    assert proxy.proxy_url() == "http://mine:1"


def test_httplib_prefix_renames_every_setting(monkeypatch):
    monkeypatch.setenv("HTTPLIB_PREFIX", "MYTOOL")
    monkeypatch.setenv("HTTPLIB_PROXY", "http://ignored:1")
    monkeypatch.setenv("MYTOOL_PROXY", "http://mytool:1")
    monkeypatch.setenv("MYTOOL_PROXY_AUTH", "Bearer t")
    assert proxy.resolve() == ("http://mytool:1", "Bearer t")
    # Read at each lookup, not at import or construction.
    env = HTTPEnv()
    monkeypatch.setenv("HTTPLIB_PREFIX", "OTHER")
    assert env.prefix == "OTHER"


def test_an_empty_httplib_prefix_is_unset(monkeypatch):
    monkeypatch.setenv("HTTPLIB_PREFIX", "  ")
    assert HTTPEnv().prefix == "HTTPLIB"


def test_the_argument_wins_over_httplib_prefix(monkeypatch):
    monkeypatch.setenv("HTTPLIB_PREFIX", "MYTOOL")
    monkeypatch.setenv("ARG_PROXY", "http://arg:1")
    monkeypatch.setenv("MYTOOL_PROXY", "http://mytool:1")
    assert proxy.proxy_url(env=HTTPEnv("ARG")) == "http://arg:1"


def test_prefixes_are_upper_case():
    assert HTTPEnv("my_tool").name("PROXY") == "MY_TOOL_PROXY"


@pytest.mark.parametrize("bad", ["1X", "A__B", "A_", "_A", "A B", "A-B"])
def test_a_malformed_prefix_is_a_value_error(bad, monkeypatch):
    with pytest.raises(ValueError, match="prefix"):
        HTTPEnv(bad)
    monkeypatch.setenv("HTTPLIB_PREFIX", bad)
    env = HTTPEnv()  # constructing reads nothing
    with pytest.raises(ValueError, match="HTTPLIB_PREFIX"):
        env.prefix


def test_empty_prefix_reads_conventional_variables_only(monkeypatch):
    monkeypatch.setenv("HTTPLIB_PROXY", "http://ignored:1")
    monkeypatch.setenv("HTTPLIB_PROXY_TYPE", "prefix")
    monkeypatch.setenv("HTTPLIB_HOOKS_X", ".")
    monkeypatch.setenv("HTTPLIB_HOOKS_X_PY", "m:f")
    monkeypatch.setenv("HTTPS_PROXY", "http://machine:1")
    monkeypatch.setenv("HTTP_PROXY_AUTH", "Basic m")
    env = HTTPEnv("")
    assert env.name("PROXY") is None and env.get("PROXY") is None
    assert proxy.resolve(env=env) == ("http://machine:1", "Basic m")
    assert proxy.proxy_type(env=env) == ("connect", None)
    assert hooks.hooks_from_env(env=env) == []
    assert hooks.wrapper_environment(hooks.Hook("X", None, "c", None), "u", "e", env=env) == {}


def test_two_instances_are_isolated():
    a = HTTPEnv("A", environ={"A_PROXY": "http://a:1", "B_PROXY": "http://b:1"})
    b = HTTPEnv("B", environ={"A_PROXY": "http://a:1", "B_PROXY": "http://b:1"})
    assert proxy.proxy_url(env=a) == "http://a:1"
    assert proxy.proxy_url(env=b) == "http://b:1"


def test_a_message_names_the_prefixed_variable():
    env = HTTPEnv("MYTOOL", environ={"MYTOOL_PROXY": "http://p:1", "MYTOOL_PROXY_TYPE": "socks5"})
    with pytest.raises(ValueError, match="MYTOOL_PROXY_TYPE"):
        proxy.plan(env=env)


def test_jar_root(monkeypatch, tmp_path):
    assert jar.store_root(env=HTTPEnv(environ={"HTTPLIB_HOME": str(tmp_path)})) == tmp_path
    assert jar.store_root(env=HTTPEnv("AGENTS", environ={"AGENTS_HOME": str(tmp_path)})) == tmp_path
    default = jar.store_root(env=HTTPEnv(environ={}))
    assert default.name == "httplib" and default == jar.default_root(env=HTTPEnv(environ={}))
    if sys.platform not in ("win32", "darwin"):
        assert jar.default_root(env=HTTPEnv(environ={"XDG_STATE_HOME": str(tmp_path)})) == tmp_path / "httplib"


def test_wrapper_environment_names_follow_the_prefix():
    env = HTTPEnv("MYTOOL", environ={"MYTOOL_HOOK_SKIP": "Z"})
    got = hooks.wrapper_environment(hooks.Hook("K", None, "c", None), "https://h/", "/bin/curl", env=env)
    assert got == {
        "MYTOOL_HOOK_URL": "https://h/",
        "MYTOOL_HOOK_KEY": "K",
        "MYTOOL_HOOK_CURL": "/bin/curl",
        "MYTOOL_HOOK_SKIP": "K,Z",
    }


def test_session_reads_through_its_env(monkeypatch):
    pytest.importorskip("requests")
    from httplib.session import new_session

    monkeypatch.setenv("HTTPLIB_PROXY", "http://ignored:1")
    env = HTTPEnv("MYTOOL", environ={"MYTOOL_PROXY": "http://mytool:3128", "MYTOOL_PROXY_AUTH": "Bearer t"})
    adapter = new_session(env=env).get_adapter("https://api.example.com/")
    assert adapter.proxy == "http://mytool:3128"
    assert adapter.proxy_headers("http://mytool:3128") == {"Proxy-Authorization": "Bearer t"}


def test_importing_reads_no_variable():
    """A malformed HTTPLIB_PREFIX fails the first lookup; importing every
    module must not be one."""
    code = (
        "import sys; sys.path.insert(0, %r); "
        "import httplib, httplib.env, httplib.proxy, httplib.jar, httplib.hooks, httplib.cookies, "
        "httplib.tls, httplib.retry, httplib.session, httplib.fetch; print('ok')" % str(SRC)
    )
    run = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env={"HTTPLIB_PREFIX": "not a prefix", "SYSTEMROOT": "C:\\Windows", "PATH": ""},
    )
    assert run.stdout.strip() == "ok", run.stderr

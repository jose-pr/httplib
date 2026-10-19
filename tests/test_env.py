"""HTTPEnv: the prefix every setting is read under -- the argument, else
SYSHTTP_PREFIX, else SYSHTTP -- and the conventional variables read under
any prefix."""

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


def test_default_prefix_is_syshttp(monkeypatch):
    env = HTTPEnv()
    assert env.prefix == "SYSHTTP" and env.name("PROXY") == "SYSHTTP_PROXY"
    monkeypatch.setenv("SYSHTTP_PROXY", "http://mine:1")
    assert _entry().url == "http://mine:1"


def test_syshttp_prefix_renames_every_setting(monkeypatch):
    monkeypatch.setenv("SYSHTTP_PREFIX", "MYTOOL")
    monkeypatch.setenv("SYSHTTP_PROXY", "http://ignored:1")
    monkeypatch.setenv("MYTOOL_PROXY", "http://mytool:1")
    monkeypatch.setenv("MYTOOL_PROXY_AUTH", "Bearer t")
    entry = _entry()
    assert (entry.url, entry.headers) == ("http://mytool:1", {"Proxy-Authorization": "Bearer t"})
    # Read at each lookup, not at import or construction.
    env = HTTPEnv()
    monkeypatch.setenv("SYSHTTP_PREFIX", "OTHER")
    assert env.prefix == "OTHER"


def test_an_empty_syshttp_prefix_is_unset(monkeypatch):
    monkeypatch.setenv("SYSHTTP_PREFIX", "  ")
    assert HTTPEnv().prefix == "SYSHTTP"


def test_the_argument_wins_over_syshttp_prefix(monkeypatch):
    monkeypatch.setenv("SYSHTTP_PREFIX", "MYTOOL")
    monkeypatch.setenv("ARG_PROXY", "http://arg:1")
    monkeypatch.setenv("MYTOOL_PROXY", "http://mytool:1")
    assert _entry(HTTPEnv("ARG")).url == "http://arg:1"


def test_prefixes_are_upper_case():
    assert HTTPEnv("my_tool").name("PROXY") == "MY_TOOL_PROXY"


@pytest.mark.parametrize("bad", ["1X", "A__B", "A_", "_A", "A B", "A-B"])
def test_a_malformed_prefix_is_a_value_error(bad, monkeypatch):
    with pytest.raises(ValueError, match="prefix"):
        HTTPEnv(bad)
    monkeypatch.setenv("SYSHTTP_PREFIX", bad)
    env = HTTPEnv()  # constructing reads nothing
    with pytest.raises(ValueError, match="SYSHTTP_PREFIX"):
        env.prefix


def test_empty_prefix_reads_conventional_variables_only(monkeypatch):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://ignored:1")
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "prefix")
    monkeypatch.setenv("SYSHTTP_HOOKS_X", ".")
    monkeypatch.setenv("SYSHTTP_HOOKS_X_PY", "m:f")
    monkeypatch.setenv("HTTPS_PROXY", "http://machine:1")
    monkeypatch.setenv("HTTP_PROXY_AUTH", "Basic m")
    env = HTTPEnv("")
    assert env.name("PROXY") is None and env.get("PROXY") is None
    entry = _entry(env)
    assert (entry.url, entry.headers) == ("http://machine:1", {"Proxy-Authorization": "Basic m"})
    assert proxy.proxy_type(env=env) == ("connect", None)
    assert hooks.hooks_from_env(env=env) == []
    assert hooks.wrapper_environment(hooks.Hook("X", None, "c", None), "u", "e", env=env) == {}


def test_two_instances_are_isolated():
    a = HTTPEnv("A", environ={"A_PROXY": "http://a:1", "B_PROXY": "http://b:1"})
    b = HTTPEnv("B", environ={"A_PROXY": "http://a:1", "B_PROXY": "http://b:1"})
    assert _entry(a).url == "http://a:1"
    assert _entry(b).url == "http://b:1"


def test_a_message_names_the_prefixed_variable():
    env = HTTPEnv("MYTOOL", environ={"MYTOOL_PROXY": "http://p:1", "MYTOOL_PROXY_TYPE": "socks5"})
    with pytest.raises(ValueError, match="MYTOOL_PROXY_TYPE"):
        _entry(env)


def test_jar_root(monkeypatch, tmp_path):
    assert jar.store_root(env=HTTPEnv(environ={"SYSHTTP_HOME": str(tmp_path)})) == tmp_path
    assert jar.store_root(env=HTTPEnv("AGENTS", environ={"AGENTS_HOME": str(tmp_path)})) == tmp_path
    default = jar.store_root(env=HTTPEnv(environ={}))
    assert default.name == "syshttp" and default == jar.default_root(env=HTTPEnv(environ={}))
    if sys.platform not in ("win32", "darwin"):
        assert jar.default_root(env=HTTPEnv(environ={"XDG_STATE_HOME": str(tmp_path)})) == tmp_path / "syshttp"


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
    from syshttp.session import new_session

    monkeypatch.setenv("SYSHTTP_PROXY", "http://ignored:1")
    env = HTTPEnv("MYTOOL", environ={"MYTOOL_PROXY": "http://mytool:3128", "MYTOOL_PROXY_AUTH": "Bearer t"})
    adapter = new_session(env=env).get_adapter("https://api.example.com/")
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


@pytest.mark.parametrize("refused", ["HTTP", "http", "HTTP_X", "Http_y"])
def test_the_http_prefix_is_refused_because_cgi_exports_request_headers_under_it(refused, monkeypatch):
    with pytest.raises(ValueError, match="CGI"):
        HTTPEnv(refused)
    monkeypatch.setenv("SYSHTTP_PREFIX", refused)
    with pytest.raises(ValueError, match="SYSHTTP_PREFIX"):
        HTTPEnv().prefix


def test_a_prefix_that_only_starts_with_http_is_fine():
    assert HTTPEnv("HTTPX").name("PROXY") == "HTTPX_PROXY"
    assert HTTPEnv("HTTP2").prefix == "HTTP2"


def test_family_strips_values_and_skips_blank_ones():
    env = HTTPEnv(environ={"SYSHTTP_HOOKS_A": "  x  ", "SYSHTTP_HOOKS_B": "   ", "SYSHTTP_HOOKS_C": ""})
    assert list(env.family("HOOKS_")) == [("A", "x")]

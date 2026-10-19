"""URL hooks: SYSHTTP_HOOKS_<KEY> patterns matched on the caller's URL run a
Python callable with the session -- under a prefix gateway too, where the
wire URL is the gateway's and must not be what is matched. The ``_CURL``
target is parsed here and run by a curl front end.
"""

import json
import os
import sys
from pathlib import Path

import pytest

from syshttp import HTTPEnv, hooks
from test_jars_proxy import _Gateway, gateway, origin  # noqa: F401  (fixtures reused)
from test_proxy_auth import _clean_env  # noqa: F401  (autouse fixture reused)

CALLS = []


def record(session, method, url, kwargs):
    CALLS.append((method, url))
    headers = kwargs.setdefault("headers", {})
    headers["X-Hooked"] = "record"
    return None


def answer(session, method, url, kwargs):
    import requests

    resp = requests.Response()
    resp.status_code = 299
    resp._content = b"from-hook"
    resp.url = url
    return resp


def reentrant(session, method, url, kwargs):
    """A hook that itself uses the session (a login call): no hook must fire
    for that inner request."""
    CALLS.append(("inner-start", url))
    inner = session.get(url + "?login=1", timeout=5)
    CALLS.append(("inner-done", inner.status_code))
    kwargs.setdefault("headers", {})["X-Hooked"] = "reentrant"
    return None


@pytest.fixture(autouse=True)
def _no_calls():
    CALLS.clear()


# --------------------------------------------------------------------------
# the declaration
# --------------------------------------------------------------------------


def test_hooks_from_env_key_order_targets_and_skip():
    environ = {
        "SYSHTTP_HOOKS_B": r"^https://b\.example/",
        "SYSHTTP_HOOKS_B_PY": "m:f",
        "SYSHTTP_HOOKS_A": r"example",
        "SYSHTTP_HOOKS_A_CURL": "/usr/bin/wrap",
        "SYSHTTP_HOOKS_A_PY": "m:g",
        "SYSHTTP_HOOKS_NOTARGET": r".*",  # nothing to run: ignored
        "SYSHTTP_HOOKS_ORPHAN_CURL": "/x",  # no pattern: ignored
        "SYSHTTP_HOOKS_EMPTY": "",
        "SYSHTTP_HOOKS_EMPTY_PY": "m:f",
        # A hook run's own exports (singular SYSHTTP_HOOK_): a different prefix, not hooks.
        "SYSHTTP_HOOK_URL": "https://b.example/x",
        "SYSHTTP_HOOK_KEY": "A",
        "SYSHTTP_HOOK_SKIP": "",
    }
    env = HTTPEnv(environ=environ)
    found = hooks.hooks_from_env(env=env)
    assert [h.key for h in found] == ["A", "B"]
    assert found[0].curl == "/usr/bin/wrap" and found[0].py == "m:g" and found[1].curl is None
    url = "https://b.example/x"
    assert [h.key for h in hooks.matching(url, env=env)] == ["A", "B"]
    assert [h.key for h in hooks.matching(url, kind="curl", env=env)] == ["A"]
    assert [h.key for h in hooks.matching("https://c.example/", env=env)] == ["A"]
    environ["SYSHTTP_HOOK_SKIP"] = "A, Z"
    assert [h.key for h in hooks.matching(url, env=env)] == ["B"]
    bad = HTTPEnv(environ={"SYSHTTP_HOOKS_BAD": "(", "SYSHTTP_HOOKS_BAD_PY": "m:f"})
    with pytest.raises(ValueError, match="SYSHTTP_HOOKS_BAD"):
        hooks.hooks_from_env(env=bad)


def test_load_callable_module_and_file(tmp_path):
    assert hooks.load_callable("test_url_hooks:record") is record
    assert hooks.load_callable("os.path:join") is os.path.join
    f = tmp_path / "my hook.py"
    f.write_text("def go(session, method, url, kwargs):\n    return 'file-hook'\n", encoding="utf-8")
    assert hooks.load_callable(str(f) + ":go")(None, "GET", "u", {}) == "file-hook"
    with pytest.raises(ValueError):
        hooks.load_callable("nocolon")
    with pytest.raises(ValueError, match="not callable"):
        hooks.load_callable("os:sep")


def test_curl_command_is_a_shell_quoted_command_line(tmp_path):
    """`_CURL='cmd fetch --'` becomes `cmd fetch -- "$@"`: the command line
    split shell-style, the shim's argv appended by the caller."""
    cmd = lambda value, **kw: hooks.curl_command(hooks.Hook("K", None, value, None), **kw)
    assert cmd("cmd fetch --") == ["cmd", "fetch", "--"]
    assert cmd("wrap --flag 'a b' \"c d\"") == ["wrap", "--flag", "a b", "c d"]
    # Backslashes are literal on every platform: a Windows path as typed.
    assert cmd(r"C:\Tools\wrap.exe --x") == [r"C:\Tools\wrap.exe", "--x"]
    assert cmd(r"'C:\Program Files\wrap.exe' --x") == [r"C:\Program Files\wrap.exe", "--x"]
    assert cmd("wrap '#not' a # comment") == ["wrap", "#not", "a", "#", "comment"]
    # A bare path to a file, spaces and all, is that one program; a .py first
    # word runs under the shim's interpreter.
    script = tmp_path / "my wrap.py"
    script.write_text("", encoding="utf-8")
    assert cmd(str(script), python="py3") == ["py3", str(script)]
    assert cmd("'%s' fetch --" % script, python="py3") == ["py3", str(script), "fetch", "--"]
    exe = tmp_path / "wrap"
    exe.write_text("", encoding="utf-8")
    assert cmd(str(exe)) == [str(exe)]
    with pytest.raises(ValueError):
        cmd("   ")


# --------------------------------------------------------------------------
# syshttp
# --------------------------------------------------------------------------


def _session():
    pytest.importorskip("requests")
    from syshttp.session import new_session

    return new_session(retries=0)


def test_py_hook_runs_on_the_origin_url_under_a_prefix_gateway(origin, gateway, monkeypatch):
    monkeypatch.setenv("SYSHTTP_HOOKS_T", "^" + origin.replace(".", r"\."))
    monkeypatch.setenv("SYSHTTP_HOOKS_T_PY", "test_url_hooks:record")
    resp = _session().get(origin + "/x", timeout=5)
    assert resp.text == "gateway"
    assert CALLS == [("GET", origin + "/x")], "the caller's URL, not /fetch/<url> on the gateway"
    assert _Gateway.seen[-1][1].get("X-Hooked") == "record", "headers the hook set went out"
    # A URL the pattern does not cover: untouched.
    CALLS.clear()
    monkeypatch.setenv("SYSHTTP_HOOKS_T", "^https://nowhere[.]example/")
    _session().get(origin + "/z", timeout=5)
    assert CALLS == [] and "X-Hooked" not in _Gateway.seen[-1][1]


def test_py_hook_can_answer_instead(origin, gateway, monkeypatch):
    monkeypatch.setenv("SYSHTTP_HOOKS_T", "/answered$")
    monkeypatch.setenv("SYSHTTP_HOOKS_T_PY", "test_url_hooks:answer")
    session = _session()
    before = len(_Gateway.seen)
    resp = session.get(origin + "/answered", timeout=5)
    assert resp.status_code == 299 and resp.text == "from-hook"
    assert len(_Gateway.seen) == before, "nothing went on the wire"
    assert session.get(origin + "/real", timeout=5).text == "gateway"


def test_py_hook_requests_do_not_re_trigger_hooks(origin, gateway, monkeypatch):
    monkeypatch.setenv("SYSHTTP_HOOKS_T", ".")
    monkeypatch.setenv("SYSHTTP_HOOKS_T_PY", "test_url_hooks:reentrant")
    resp = _session().get(origin + "/x", timeout=5)
    assert resp.text == "gateway"
    assert CALLS == [("inner-start", origin + "/x"), ("inner-done", 200)]
    assert _Gateway.seen[-1][1].get("X-Hooked") == "reentrant"
    assert "X-Hooked" not in _Gateway.seen[-2][1], "the login call carried no hook header"


def test_py_hooks_run_in_key_order_first_answer_wins(origin, gateway, monkeypatch):
    monkeypatch.setenv("SYSHTTP_HOOKS_A", ".")
    monkeypatch.setenv("SYSHTTP_HOOKS_A_PY", "test_url_hooks:record")
    monkeypatch.setenv("SYSHTTP_HOOKS_B", ".")
    monkeypatch.setenv("SYSHTTP_HOOKS_B_PY", "test_url_hooks:answer")
    monkeypatch.setenv("SYSHTTP_HOOKS_C", ".")
    monkeypatch.setenv("SYSHTTP_HOOKS_C_PY", "test_url_hooks:reentrant")
    resp = _session().get(origin + "/x", timeout=5)
    assert resp.text == "from-hook" and CALLS == [("GET", origin + "/x")]


def test_a_blank_hook_target_is_ignored():
    env = HTTPEnv(environ={"SYSHTTP_HOOKS_W": ".", "SYSHTTP_HOOKS_W_PY": "   "})
    assert hooks.hooks_from_env(env=env) == []
    assert hooks.call_py_hooks(None, "GET", "https://h/", {}, env=env) is None


def test_hook_keys_are_compared_without_regard_to_case():
    environ = {
        "SYSHTTP_HOOKS_mykey": ".",
        "SYSHTTP_HOOKS_mykey_PY": "test_url_hooks:record",
        "SYSHTTP_HOOK_SKIP": "MyKey",
    }
    env = HTTPEnv(environ=environ)
    found = hooks.hooks_from_env(env=env)
    assert [h.key for h in found] == ["MYKEY"] and found[0].py == "test_url_hooks:record"
    assert found[0].variable == "SYSHTTP_HOOKS_mykey", "a message names the variable as it is set"
    assert hooks.skipped(env=env) == {"MYKEY"}
    assert hooks.matching("https://h/", env=env) == []
    del environ["SYSHTTP_HOOK_SKIP"]
    assert [h.key for h in hooks.matching("https://h/", env=env)] == ["MYKEY"]
    assert hooks.wrapper_environment(found[0], "https://h/", "pycurl", env=env)["SYSHTTP_HOOK_SKIP"] == "MYKEY"


def test_a_file_hook_runs_its_module_body_once(tmp_path):
    hits = tmp_path / "hits"
    f = tmp_path / "counting.py"
    f.write_text(
        "with open(%r, 'a') as handle:\n"
        "    handle.write('x')\n"
        "STATE = []\n"
        "def go(session, method, url, kwargs):\n"
        "    STATE.append(url)\n"
        "    return len(STATE)\n" % str(hits),
        encoding="utf-8",
    )
    env = HTTPEnv(environ={"SYSHTTP_HOOKS_F": ".", "SYSHTTP_HOOKS_F_PY": str(f) + ":go"})
    answers = [hooks.call_py_hooks(None, "GET", "https://h/%d" % i, {}, env=env) for i in range(3)]
    assert answers == [1, 2, 3], "module state lives on between requests"
    assert hits.read_text() == "x"


def test_two_hook_files_with_one_stem_are_two_modules(tmp_path):
    first, second = tmp_path / "a" / "hook.py", tmp_path / "b" / "hook.py"
    for path, name in ((first, "first"), (second, "second")):
        path.parent.mkdir()
        path.write_text("def go(session, method, url, kwargs):\n    return %r\n" % name, encoding="utf-8")
    assert hooks.load_callable(str(first) + ":go")(None, "GET", "u", {}) == "first"
    assert hooks.load_callable(str(second) + ":go")(None, "GET", "u", {}) == "second"
    assert hooks.load_callable(str(first) + ":go")(None, "GET", "u", {}) == "first"


def test_a_hook_failure_names_the_url_without_userinfo_or_query():
    env = HTTPEnv(environ={"SYSHTTP_HOOKS_B": ".", "SYSHTTP_HOOKS_B_PY": "nosuchmodule_xyz:f"})
    with pytest.raises(RuntimeError) as caught:
        hooks.call_py_hooks(None, "GET", "https://user:hunter2@h:8443/x?access_token=abc#frag", {}, env=env)
    message = str(caught.value)
    assert "SYSHTTP_HOOKS_B_PY" in message and "failed for GET https://h:8443/x:" in message
    assert "hunter2" not in message and "access_token" not in message and "frag" not in message


@pytest.mark.parametrize(
    "line, argv",
    [
        ("cmd fetch --", ["cmd", "fetch", "--"]),
        ("'my tool' --flag \"a b\"", ["my tool", "--flag", "a b"]),
        (r"C:\Tools\wrap.exe -x", [r"C:\Tools\wrap.exe", "-x"]),
        ("cmd #notacomment", ["cmd", "#notacomment"]),
        ("", []),
    ],
)
def test_split_command_groups_quotes_and_keeps_backslashes(line, argv):
    assert hooks.split_command(line) == argv


def test_split_command_refuses_an_unbalanced_quote():
    with pytest.raises(ValueError):
        hooks.split_command("cmd 'open")

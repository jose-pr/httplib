"""URL hooks: NET_HOOKS_<KEY> patterns matched on the caller's URL run a
Python callable with the session -- under a prefix gateway too, where the
wire URL is the gateway's and must not be what is matched. The ``_CURL``
target is parsed here and run by a curl front end.
"""

import json
import os
import sys
from pathlib import Path

import pytest

from httplib import hooks
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
def _no_ambient_hooks(monkeypatch):
    for name in list(os.environ):
        if name.startswith(hooks.PREFIX) or name == hooks.SKIP_ENV:
            monkeypatch.delenv(name)
    CALLS.clear()


# --------------------------------------------------------------------------
# the declaration
# --------------------------------------------------------------------------


def test_hooks_from_env_key_order_targets_and_skip():
    env = {
        "NET_HOOKS_B": r"^https://b\.example/",
        "NET_HOOKS_B_PY": "m:f",
        "NET_HOOKS_A": r"example",
        "NET_HOOKS_A_CURL": "/usr/bin/wrap",
        "NET_HOOKS_A_PY": "m:g",
        "NET_HOOKS_NOTARGET": r".*",  # nothing to run: ignored
        "NET_HOOKS_ORPHAN_CURL": "/x",  # no pattern: ignored
        "NET_HOOKS_EMPTY": "",
        "NET_HOOKS_EMPTY_PY": "m:f",
        # A hook run's own exports (singular NET_HOOK_): a different prefix, not hooks.
        "NET_HOOK_URL": "https://b.example/x",
        "NET_HOOK_KEY": "A",
        "NET_HOOK_SKIP": "",
    }
    found = hooks.hooks_from_env(env)
    assert [h.key for h in found] == ["A", "B"]
    assert found[0].curl == "/usr/bin/wrap" and found[0].py == "m:g" and found[1].curl is None
    url = "https://b.example/x"
    assert [h.key for h in hooks.matching(url, env)] == ["A", "B"]
    assert [h.key for h in hooks.matching(url, env, kind="curl")] == ["A"]
    assert [h.key for h in hooks.matching("https://c.example/", env)] == ["A"]
    env[hooks.SKIP_ENV] = "A, Z"
    assert [h.key for h in hooks.matching(url, env)] == ["B"]
    with pytest.raises(ValueError, match="NET_HOOKS_BAD"):
        hooks.hooks_from_env({"NET_HOOKS_BAD": "(", "NET_HOOKS_BAD_PY": "m:f"})


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
# httplib
# --------------------------------------------------------------------------


def _session():
    pytest.importorskip("requests")
    from httplib.session import new_session

    return new_session(retries=0)


def test_py_hook_runs_on_the_origin_url_under_a_prefix_gateway(origin, gateway, monkeypatch):
    monkeypatch.setenv("NET_HOOKS_T", "^" + origin.replace(".", r"\."))
    monkeypatch.setenv("NET_HOOKS_T_PY", "test_url_hooks:record")
    resp = _session().get(origin + "/x", timeout=5)
    assert resp.text == "gateway"
    assert CALLS == [("GET", origin + "/x")], "the caller's URL, not /fetch/<url> on the gateway"
    assert _Gateway.seen[-1][1].get("X-Hooked") == "record", "headers the hook set went out"
    # A URL the pattern does not cover: untouched.
    CALLS.clear()
    monkeypatch.setenv("NET_HOOKS_T", "^https://nowhere[.]example/")
    _session().get(origin + "/z", timeout=5)
    assert CALLS == [] and "X-Hooked" not in _Gateway.seen[-1][1]


def test_py_hook_can_answer_instead(origin, gateway, monkeypatch):
    monkeypatch.setenv("NET_HOOKS_T", "/answered$")
    monkeypatch.setenv("NET_HOOKS_T_PY", "test_url_hooks:answer")
    session = _session()
    before = len(_Gateway.seen)
    resp = session.get(origin + "/answered", timeout=5)
    assert resp.status_code == 299 and resp.text == "from-hook"
    assert len(_Gateway.seen) == before, "nothing went on the wire"
    assert session.get(origin + "/real", timeout=5).text == "gateway"


def test_py_hook_requests_do_not_re_trigger_hooks(origin, gateway, monkeypatch):
    monkeypatch.setenv("NET_HOOKS_T", ".")
    monkeypatch.setenv("NET_HOOKS_T_PY", "test_url_hooks:reentrant")
    resp = _session().get(origin + "/x", timeout=5)
    assert resp.text == "gateway"
    assert CALLS == [("inner-start", origin + "/x"), ("inner-done", 200)]
    assert _Gateway.seen[-1][1].get("X-Hooked") == "reentrant"
    assert "X-Hooked" not in _Gateway.seen[-2][1], "the login call carried no hook header"


def test_py_hooks_run_in_key_order_first_answer_wins(origin, gateway, monkeypatch):
    monkeypatch.setenv("NET_HOOKS_A", ".")
    monkeypatch.setenv("NET_HOOKS_A_PY", "test_url_hooks:record")
    monkeypatch.setenv("NET_HOOKS_B", ".")
    monkeypatch.setenv("NET_HOOKS_B_PY", "test_url_hooks:answer")
    monkeypatch.setenv("NET_HOOKS_C", ".")
    monkeypatch.setenv("NET_HOOKS_C_PY", "test_url_hooks:reentrant")
    resp = _session().get(origin + "/x", timeout=5)
    assert resp.text == "from-hook" and CALLS == [("GET", origin + "/x")]

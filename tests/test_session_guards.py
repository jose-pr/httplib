"""The session's own state and secrets: the User-Agent it was given, hooks in
one thread not switching them off in another, and credentials that would end
a header refused without echoing them."""

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytest.importorskip("requests")

from syshttp.env import HTTPEnv  # noqa: E402
from syshttp.jar import MemoryTokenJar  # noqa: E402
from syshttp.session import new_session  # noqa: E402


class _Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = ("%s|%s" % (self.headers.get("User-Agent"), self.headers.get("X-Signed"))).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture()
def echo():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield "http://127.0.0.1:%d/" % server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def test_the_given_user_agent_is_the_one_on_the_wire(echo):
    session = new_session(retries=0, user_agent="mytool/1.0", env=HTTPEnv(environ={}))
    assert session.get(echo, timeout=5).text.split("|")[0] == "mytool/1.0"


_hook_calls = []
_entered = threading.Event()
_release = threading.Event()


def _hook(session, method, url, kwargs):
    _hook_calls.append(threading.current_thread().name)
    if len(_hook_calls) == 1:
        _entered.set()
        _release.wait(10)
    else:
        _release.set()
    kwargs.setdefault("headers", {})["X-Signed"] = "yes"


def test_a_hook_in_one_thread_does_not_switch_hooks_off_in_another(echo):
    del _hook_calls[:]
    _entered.clear()
    _release.clear()
    env = HTTPEnv(environ={"SYSHTTP_HOOKS_X": ".", "SYSHTTP_HOOKS_X_PY": "test_session_guards:_hook"})
    session = new_session(retries=0, env=env)
    bodies = {}

    def get(name):
        bodies[name] = session.get(echo, timeout=15).text

    first = threading.Thread(target=get, args=("first",), name="first")
    first.start()
    assert _entered.wait(10)
    started = time.monotonic()
    get("second")
    first.join(15)
    assert len(_hook_calls) == 2 and time.monotonic() - started < 8
    assert bodies["first"].endswith("|yes") and bodies["second"].endswith("|yes")


def test_a_token_with_a_line_break_is_refused_without_echoing_it(echo):
    jar = MemoryTokenJar({"127.0.0.1": "SECRET-PART-1\nSECRET-PART-2"})
    session = new_session(retries=0, tokens=jar, env=HTTPEnv(environ={}))
    with pytest.raises(ValueError) as caught:
        session.get(echo, timeout=5)
    assert "SECRET" not in str(caught.value) and "127.0.0.1" in str(caught.value)


@pytest.mark.parametrize("value", ["SECRET-1\nSECRET-2", "SECRET-1\rSECRET-2", "SECRET-1\x00SECRET-2"])
def test_a_proxy_credential_with_a_line_break_names_the_variable_not_the_value(value):
    env = HTTPEnv(environ={"SYSHTTP_PROXY": "http://proxy.example:3128", "SYSHTTP_PROXY_AUTH": value})
    with pytest.raises(ValueError) as caught:
        new_session(env=env)
    assert "SYSHTTP_PROXY_AUTH" in str(caught.value) and "SECRET" not in str(caught.value)


def test_the_machine_proxy_credential_is_checked_too():
    import proxylib

    from syshttp import proxy

    env = HTTPEnv(environ={"HTTP_PROXY": "http://proxy.example:3128", "HTTP_PROXY_AUTH": "SECRET-1\nSECRET-2"})
    with pytest.raises(ValueError) as caught:
        proxylib.lookup(proxy.proxy_map(env=env), "http://a.example/")
    assert "HTTP_PROXY_AUTH" in str(caught.value) and "SECRET" not in str(caught.value)

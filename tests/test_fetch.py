"""The fetch helpers: the status comes back (never an exception for a status
outlasting the retries), and the ``*_auto`` helpers take ``new_session``'s
options and close the session they built."""

import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

requests = pytest.importorskip("requests")

from syshttp import fetch  # noqa: E402
from syshttp.env import HTTPEnv  # noqa: E402
from syshttp.session import new_session  # noqa: E402

DIRECT = HTTPEnv(environ={})


class _Script(BaseHTTPRequestHandler):
    """Answers ``statuses`` in order, then the last one forever."""

    statuses = [200]
    seen = 0
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        index = min(type(self).seen, len(self.statuses) - 1)
        type(self).seen += 1
        status = self.statuses[index]
        body = b'{"n": %d}' % status
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture()
def script():
    handler = type("Handler", (_Script,), {"statuses": [200], "seen": 0})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    handler.url = "http://127.0.0.1:%d/" % server.server_address[1]
    try:
        yield handler
    finally:
        server.shutdown()
        server.server_close()


def test_a_status_that_outlasts_the_retries_comes_back(script):
    script.statuses = [503]
    session = new_session(retries=1, backoff=0, env=DIRECT)
    assert fetch.request_text(session, "GET", script.url) == (503, '{"n": 503}')
    assert script.seen == 2, "one try and one retry"
    assert session.get(script.url, timeout=5).status_code == 503


def test_json_comes_back_with_the_status_too(script):
    script.statuses = [503]
    session = new_session(retries=1, backoff=0, env=DIRECT)
    assert fetch.request_json(session, "GET", script.url) == (503, {"n": 503})


def test_the_auto_helpers_retry_a_408_by_default(script):
    script.statuses = [408, 200]
    assert fetch.request_text_auto("GET", script.url, backoff=0, env=DIRECT) == (200, '{"n": 200}')
    assert script.seen == 2
    script.seen = 0
    script.statuses = [408, 200]
    assert fetch.request_json_auto("GET", script.url, backoff=0, env=DIRECT) == (200, {"n": 200})


def test_the_auto_helpers_forward_new_sessions_options(script, monkeypatch):
    seen = {}
    real = fetch.new_session

    def spy(**options):
        seen.update(options)
        return real(**options)

    monkeypatch.setattr(fetch, "new_session", spy)
    context = ssl.create_default_context()
    env = DIRECT
    fetch.request_text_auto("GET", script.url, env=env, ssl_context=context, retries=0, user_agent="t/1")
    assert seen == {"env": env, "ssl_context": context, "retries": 0, "user_agent": "t/1"}


def test_a_session_the_helper_built_is_closed_and_a_callers_is_not(script, monkeypatch):
    closed = []
    real = requests.Session.close

    def close(self):
        closed.append(self)
        return real(self)

    monkeypatch.setattr(requests.Session, "close", close)
    fetch.request_text_auto("GET", script.url, env=DIRECT)
    assert len(closed) == 1
    mine = new_session(env=DIRECT)
    fetch.request_text_auto("GET", script.url, session=mine)
    fetch.request_json_auto("GET", script.url, session=mine)
    assert len(closed) == 1 and mine not in closed
    fetch.request_json_auto("GET", script.url, env=DIRECT)
    assert len(closed) == 2


def test_the_helpers_accept_a_connect_read_timeout_pair(script):
    session = new_session(env=DIRECT)
    assert fetch.request_text(session, "GET", script.url, timeout=(5, 5))[0] == 200


def test_the_helpers_have_docstrings():
    for name in ("request_text", "request_json", "request_with_reauth", "request_text_auto", "request_json_auto"):
        assert (getattr(fetch, name).__doc__ or "").strip(), name

"""fetch(): one request, one response with its body read; a status is never an
exception (one that outlasts the retries comes back); the options of a new
client and its transport go through; a client the caller gives is left open,
one made for the call is closed; reauth runs once after a 401 or 403."""

import importlib
import ssl
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import syshttp
from client_fakes import FakeTransport, reply
from syshttp.client import HTTPClient, HTTPResponse, fetch, raise_for_status
from syshttp.client import _fetch as fetch_module
from syshttp.env import HTTPEnv

DIRECT = HTTPEnv(environ={})
SRC = Path(__file__).resolve().parents[1] / "src"


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


# -- the reply ----------------------------------------------------------------


def test_the_reply_is_an_http_response_with_its_body_read(script):
    response = fetch(script.url, env=DIRECT)
    assert isinstance(response, HTTPResponse) and response.status == 200
    assert response.content == b'{"n": 200}' and response.text() == '{"n": 200}' and response.json() == {"n": 200}
    assert response.headers["Content-Length"] == "10"


def test_a_status_that_outlasts_the_retries_comes_back(script):
    script.statuses = [503]
    response = fetch(script.url, retries=1, backoff=0, env=DIRECT)
    assert (response.status, response.text()) == (503, '{"n": 503}')
    assert script.seen == 2, "one try and one retry"
    assert response.json() == {"n": 503}


def test_a_408_is_retried_by_default(script):
    script.statuses = [408, 200]
    response = fetch(script.url, backoff=0, env=DIRECT)
    assert (response.status, response.json()) == (200, {"n": 200}) and script.seen == 2


def test_raise_for_status_is_the_callers_choice(script):
    script.statuses = [404]
    response = fetch(script.url, env=DIRECT)
    assert response.status == 404
    with pytest.raises(Exception, match="404"):
        raise_for_status(response)


def test_the_timeout_may_be_a_connect_read_pair(script):
    assert fetch(script.url, timeout=(5, 5), env=DIRECT).status == 200


def test_a_method_headers_and_a_body_are_sent():
    transport = FakeTransport(default=reply(201))
    response = fetch("http://h/x", "PUT", headers={"X-A": "1"}, data=b"abc", transport=transport, retries=0, env=DIRECT)
    (sent,) = transport.sent
    assert (sent.method, sent.url, sent.body) == ("PUT", "http://h/x", b"abc")
    assert sent.headers["X-A"] == "1" and response.status == 201


def test_json_is_sent_as_json_and_a_mapping_as_a_form():
    transport = FakeTransport(default=reply(200))
    fetch("http://h/x", "POST", json={"a": [1, "é"]}, transport=transport, env=DIRECT)
    fetch("http://h/x", "POST", data={"a": "1 2", "b": ["x", "y"]}, transport=transport, env=DIRECT)
    fetch("http://h/x", "POST", json=[], headers={"content-type": "application/vnd.api+json"}, transport=transport)
    first, second, third = transport.sent
    assert first.body == b'{"a": [1, "\\u00e9"]}' and first.headers["Content-Type"] == "application/json"
    assert second.body == b"a=1+2&b=x&b=y"
    assert second.headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert [k for k in third.headers if k.lower() == "content-type"] == ["content-type"]


def test_data_and_json_together_are_refused():
    with pytest.raises(ValueError, match="data and json"):
        fetch("http://h/x", "POST", data=b"x", json={}, transport=FakeTransport())


# -- the client and the transport -----------------------------------------------


def test_the_options_of_a_new_client_go_through(script, monkeypatch):
    seen = {}
    real = fetch_module.HTTPClient

    def spy(*args, **options):
        seen["args"], seen["options"] = args, options
        return real(*args, **options)

    monkeypatch.setattr(fetch_module, "HTTPClient", spy)
    context = ssl.create_default_context()
    fetch(script.url, env=DIRECT, ssl_context=context, retries=0, user_agent="t/1")
    assert seen["args"] == (None,)
    assert seen["options"] == {"env": DIRECT, "ssl_context": context, "retries": 0, "user_agent": "t/1"}


def test_a_transport_goes_to_the_client_that_is_made_and_stays_the_callers():
    transport = FakeTransport(default=reply(200, b"mine"))
    assert fetch("http://h/x", transport=transport, env=DIRECT).text() == "mine"
    assert transport.closed == 0 and len(transport.sent) == 1


def test_a_client_built_for_the_call_is_closed_and_a_callers_is_not(script, monkeypatch):
    closed = []
    real = HTTPClient.close

    def close(self):
        closed.append(self)
        return real(self)

    monkeypatch.setattr(HTTPClient, "close", close)
    fetch(script.url, env=DIRECT)
    assert len(closed) == 1
    mine = HTTPClient(env=DIRECT)
    fetch(script.url, client=mine)
    fetch(script.url, client=mine)
    assert len(closed) == 1 and mine not in closed
    fetch(script.url, env=DIRECT)
    assert len(closed) == 2


def test_a_client_beside_a_transport_or_client_options_is_refused(script):
    client = HTTPClient(FakeTransport(default=reply(200)))
    with pytest.raises(ValueError, match="already"):
        fetch("http://h/x", client=client, transport=FakeTransport())
    with pytest.raises(ValueError, match="already"):
        fetch("http://h/x", client=client, retries=0)
    with pytest.raises(ValueError, match="already"):
        fetch("http://h/x", client=client, env=DIRECT)
    assert fetch("http://h/x", client=client).status == 200


def test_the_body_is_read_before_a_one_off_client_is_closed(script):
    response = fetch(script.url, env=DIRECT)
    assert response.json() == {"n": 200}


# -- reauth ---------------------------------------------------------------------


class _Statuses:
    """Answers the statuses in order, then the last, and records the sends."""

    def __init__(self, *statuses):
        self.statuses = list(statuses)
        self.sent = []

    def send(self, method, url, *, headers, body=None, timeout, stream=False):
        self.sent.append((method, url, dict(headers), body))
        status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        return reply(status, b"s%d" % status, url=url)

    def close(self):
        pass


@pytest.mark.parametrize("status", [401, 403])
def test_reauth_runs_once_after_a_401_or_403_and_the_request_is_sent_again(status):
    transport = _Statuses(status, 200)
    calls = []
    response = fetch("http://h/x", "POST", data=b"body", reauth=lambda *a: calls.append(a), transport=transport)
    assert response.status == 200 and len(transport.sent) == 2 and transport.sent[1][3] == b"body"
    ((client, url),) = calls
    assert isinstance(client, HTTPClient) and url == "http://h/x"


def test_reauth_does_not_run_for_other_statuses_and_a_second_refusal_is_returned():
    transport = _Statuses(404)
    calls = []
    assert fetch("http://h/x", reauth=lambda *a: calls.append(a), transport=transport).status == 404
    assert calls == [] and len(transport.sent) == 1
    transport = _Statuses(401)
    response = fetch("http://h/x", reauth=lambda *a: calls.append(a), transport=transport)
    assert response.status == 401 and len(calls) == 1 and len(transport.sent) == 2


def test_an_auth_provider_is_called_through_ensure():
    seen = []

    class Provider:
        def ensure(self, client, url):
            seen.append(url)

    fetch("http://h/x", reauth=Provider(), transport=_Statuses(403, 200))
    assert seen == ["http://h/x"]


def test_the_errors_of_reauth_are_the_callers():
    def refuse(client, url):
        raise RuntimeError("login failed")

    with pytest.raises(RuntimeError, match="login failed"):
        fetch("http://h/x", reauth=refuse, transport=_Statuses(401, 200))


def test_reauth_needs_a_body_that_can_be_sent_twice():
    with pytest.raises(ValueError, match="reauth"):
        fetch("http://h/x", "PUT", data=iter([b"a"]), reauth=lambda *a: None, transport=_Statuses(200))


def test_a_client_given_to_fetch_carries_its_own_auth_provider():
    ensured = []

    class Provider:
        def ensure(self, client, url):
            ensured.append(url)

    client = HTTPClient(_Statuses(200), auth_provider=Provider())
    fetch("http://h/x", client=client)
    assert ensured == ["http://h/x"]


# -- where fetch lives ----------------------------------------------------------


def test_fetch_is_the_function_of_the_client_package_and_the_root_names_it():
    assert syshttp.fetch is fetch and "fetch" in syshttp.__all__
    assert (fetch.__doc__ or "").strip()


def test_there_is_no_fetch_module():
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("syshttp.fetch")


def test_the_root_loads_the_client_when_fetch_is_asked_for_not_before():
    code = (
        "import sys; sys.path.insert(0, %r); import syshttp; a = 'syshttp.client' in sys.modules; "
        "f = syshttp.fetch; print(a, 'syshttp.client' in sys.modules, f.__name__)" % str(SRC)
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout.strip()
    assert out == "False True fetch"

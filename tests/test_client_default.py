"""The client: the transport it sends with when it is not given one, what it
closes, what every request carries, the timeout, and the libraries it needs
(none beyond the standard library)."""

import base64
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import syshttp
import syshttp.client as client_module
from client_fakes import FakeTransport, reply
from client_wire import Hang, Wire
from syshttp.client import HTTPClient, HTTPTransport

SRC = Path(__file__).resolve().parents[1] / "src"


def test_without_a_transport_the_client_makes_an_http_transport_and_keeps_it():
    with HTTPClient() as client:
        first = client.transport
        assert type(first) is HTTPTransport
        assert client.transport is first


def test_a_closed_client_makes_a_new_transport_when_it_is_used_again():
    client = HTTPClient()
    first = client.transport
    client.close()
    assert client.transport is not first
    client.close()


@pytest.mark.parametrize("option", [{"proxymap": {}}, {"verify": False}, {"proxy_ssl_context": object()}])
def test_the_options_of_the_default_transport_are_refused_beside_one_of_your_own(option):
    with pytest.raises(ValueError, match="default transport"):
        HTTPClient(FakeTransport(), **option)


def test_a_client_closes_the_transport_it_built_and_not_one_it_was_given():
    given = FakeTransport(default=reply(200))
    client = HTTPClient(given)
    client.close()
    assert given.closed == 0

    built = HTTPClient()
    transport = built.transport
    closed = []
    transport.close = lambda: closed.append(True)
    built.close()
    built.close()
    assert closed == [True]


def test_a_transport_is_an_object_with_a_send_method():
    with pytest.raises(TypeError):
        HTTPClient(object())


def test_the_representation_of_a_client_shows_no_header():
    client = HTTPClient(headers={"Authorization": "Bearer SECRET"})
    assert "SECRET" not in repr(client) and "Authorization" not in repr(client)


# --- what every request carries -------------------------------------------------


def test_a_request_names_the_library_and_its_version_as_its_user_agent():
    transport = FakeTransport(default=reply(200))
    HTTPClient(transport).request("GET", "http://h/x")
    sent = transport.sent[0].headers
    assert sent["User-Agent"] == f"syshttp/{syshttp.__version__}"
    assert sent["Accept"] == "*/*"


def test_the_user_agent_can_be_named_by_the_caller_of_the_client():
    transport = FakeTransport(default=reply(200))
    client = HTTPClient(transport, user_agent="tool/1.2")
    assert client.user_agent == "tool/1.2"
    client.request("GET", "http://h/x")
    assert transport.sent[0].headers["User-Agent"] == "tool/1.2"


def test_headers_are_merged_by_name_the_call_over_the_client_over_the_base():
    transport = FakeTransport(default=reply(200))
    client = HTTPClient(transport, headers={"accept": "text/html", "X-A": "client"})
    client.request("GET", "http://h/x", headers={"x-a": "call", "X-B": "call"})
    sent = transport.sent[0].headers
    assert {k.lower(): v for k, v in sent.items()} == {
        "user-agent": f"syshttp/{syshttp.__version__}",
        "accept": "text/html",
        "x-a": "call",
        "x-b": "call",
    }
    assert len(sent) == 4


def test_a_header_set_to_none_in_the_call_is_not_sent():
    transport = FakeTransport(default=reply(200))
    HTTPClient(transport).request("GET", "http://h/x", headers={"Accept": None})
    assert "Accept" not in transport.sent[0].headers


def test_credentials_given_as_auth_are_sent_as_a_basic_authorization():
    transport = FakeTransport(default=reply(200))
    HTTPClient(transport).request("GET", "http://h/x", auth=("al@ice", "s3cr3t"))
    expected = "Basic " + base64.b64encode(b"al@ice:s3cr3t").decode("ascii")
    assert transport.sent[0].headers["Authorization"] == expected
    assert transport.sent[0].url == "http://h/x"


def test_a_string_given_as_auth_is_the_authorization_value():
    transport = FakeTransport(default=reply(200))
    HTTPClient(transport).request("GET", "http://h/x", auth="Bearer TOKEN")
    assert transport.sent[0].headers["Authorization"] == "Bearer TOKEN"


@pytest.mark.parametrize("where", ["client", "call"])
def test_an_authorization_header_wins_over_auth(where):
    transport = FakeTransport(default=reply(200))
    options = {"headers": {"authorization": "Bearer B"}}
    client = HTTPClient(transport, **(options if where == "client" else {}))
    client.request("GET", "http://h/x", auth=("alice", "pw"), **(options if where == "call" else {}))
    sent = transport.sent[0].headers
    assert [v for k, v in sent.items() if k.lower() == "authorization"] == ["Bearer B"]


def test_a_url_with_credentials_is_refused_before_anything_is_sent():
    transport = FakeTransport(default=reply(200))
    with pytest.raises(ValueError) as excinfo:
        HTTPClient(transport).request("GET", "http://alice:s3cr3t@h/x")
    assert "s3cr3t" not in str(excinfo.value)
    assert transport.sent == []


def test_a_header_or_url_with_a_line_break_is_refused_before_any_transport_call():
    transport = FakeTransport(default=reply(200))
    for headers in ({"X-A": "1\r\nX-B: 2"}, {"X-A": "1\n2"}):
        with pytest.raises(ValueError):
            HTTPClient(transport, headers=headers).request("GET", "http://h/x")
        with pytest.raises(ValueError):
            HTTPClient(transport).request("GET", "http://h/x", headers=headers)
    with pytest.raises(ValueError):
        HTTPClient(transport).request("GET", "http://h/x\r\nX-A: 1")
    assert transport.sent == []


def test_a_text_body_is_sent_as_utf_8():
    transport = FakeTransport(default=reply(200))
    HTTPClient(transport).request("PUT", "http://h/x", data="café")
    assert transport.sent[0].body == "café".encode("utf-8")


def test_a_reply_is_asked_for_streamed_whatever_the_caller_asked():
    transport = FakeTransport(default=reply(200, b"abc"))
    client = HTTPClient(transport)
    assert client.request("GET", "http://h/x").read() == b"abc"
    client.request("GET", "http://h/x", stream=True).close()
    assert [call.stream for call in transport.sent] == [True, True]


# --- the timeout -----------------------------------------------------------------


def test_a_request_without_a_timeout_gets_the_default():
    transport = FakeTransport()
    HTTPClient(transport).request("GET", "http://h/x")
    assert transport.sent[-1].timeout == (10, 60) == client_module.DEFAULT_TIMEOUT


@pytest.mark.parametrize("timeout", [5, None])
def test_a_timeout_of_the_client_or_the_call_wins(timeout):
    transport = FakeTransport()
    HTTPClient(transport, timeout=timeout).request("GET", "http://h/x")
    assert transport.sent[-1].timeout == timeout
    HTTPClient(transport).request("GET", "http://h/x", timeout=timeout)
    assert transport.sent[-1].timeout == timeout


def test_a_stalled_server_times_out_when_the_client_has_a_timeout():
    with Wire(lambda r: Hang()) as wire:
        with HTTPClient(timeout=(2, 0.5)) as client:
            with pytest.raises(TimeoutError):
                client.request("GET", wire.url + "/x")


# --- no third-party library ---------------------------------------------------

_CHILD = """
import sys

sys.path.insert(0, %r)
import syshttp

assert not {"ssl", "http.client"} & set(sys.modules), "the root loads no HTTP code"
sys.modules["requests"] = None
sys.modules["urllib3"] = None

import http.server, threading


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        body = b"hello"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()

from syshttp.client import HTTPClient

with HTTPClient() as client:
    reply = client.request("GET", "http://127.0.0.1:%%d/f" %% server.server_port)
    print(reply.status, reply.read())
print(sorted(m for m in ("requests", "urllib3") if sys.modules.get(m) is not None))
server.shutdown()
server.server_close()
"""


def test_a_request_works_with_requests_and_urllib3_hidden_and_the_root_loads_no_ssl():
    env = {k: v for k, v in os.environ.items() if not k.startswith("SYSHTTP_")}
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(_CHILD) % str(SRC)],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["200 b'hello'", "[]"]

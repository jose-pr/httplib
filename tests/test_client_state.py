"""What a client keeps and does around the transport: retries, cookies on every
hop, tokens that stay with their origin, the auth provider and the hooks."""

import io

import pytest

from client_fakes import FakeTransport, reply
from client_wire import Drop, Wire, response
from syshttp import HTTPEnv
from syshttp.client import HTTPClient, _client
from syshttp.exceptions import ConfigurationError, HookError
from syshttp.jar import MemoryCookieJar, MemoryTokenJar

DIRECT = HTTPEnv(environ={})


@pytest.fixture
def sleeps(monkeypatch):
    """The waits of the client's retries, not waited."""
    waited = []
    monkeypatch.setattr(_client._time, "sleep", waited.append)
    return waited


def statuses(*codes, **headers):
    """A transport answering the codes in order, then the last for ever."""
    queue = list(codes)

    def answer(method, url, headers=None, body=None):
        code = queue.pop(0) if len(queue) > 1 else queue[0]
        return reply(code, b"s%d" % code, headers=extra, url=url)

    extra = dict(headers)
    return FakeTransport(handler=answer)


# -- retries --------------------------------------------------------------------


def test_a_transient_status_is_retried_and_the_last_answer_comes_back(sleeps):
    transport = statuses(503, 503, 200)
    client = HTTPClient(transport, retries=3, backoff=1)
    assert client.request("GET", "http://h/x").status == 200
    assert len(transport.sent) == 3
    assert sleeps == [2], "none before the first retry, then backoff doubled"


def test_the_waits_double_each_time_and_are_capped(sleeps):
    transport = statuses(503)
    response_ = HTTPClient(transport, retries=5, backoff=1).request("GET", "http://h/x")
    assert response_.status == 503 and len(transport.sent) == 6
    assert sleeps == [2, 4, 8, 16]
    sleeps.clear()
    HTTPClient(statuses(503), retries=9, backoff=1000).request("GET", "http://h/x")
    assert max(sleeps) == _client.MAX_RETRY_WAIT


def test_retry_after_sets_the_least_wait(sleeps):
    transport = statuses(429, 200, **{"Retry-After": "7"})
    HTTPClient(transport, retries=2, backoff=0).request("GET", "http://h/x")
    assert sleeps == [7]


def test_only_a_method_that_is_safe_to_send_twice_is_retried(sleeps):
    for method, tries in (("GET", 3), ("PUT", 3), ("DELETE", 3), ("POST", 1), ("PATCH", 1)):
        transport = statuses(503)
        HTTPClient(transport, retries=2, backoff=0).request(method, "http://h/x")
        assert len(transport.sent) == tries, method


def test_a_body_that_cannot_be_sent_twice_is_not_retried(sleeps):
    transport = statuses(503)
    HTTPClient(transport, retries=2, backoff=0).request("PUT", "http://h/x", data=io.BytesIO(b"abc"))
    assert len(transport.sent) == 1
    transport = statuses(503)
    HTTPClient(transport, retries=2, backoff=0).request("PUT", "http://h/x", data=b"abc")
    assert len(transport.sent) == 3


def test_a_status_that_is_not_in_the_list_is_returned_at_once(sleeps):
    transport = statuses(404)
    assert HTTPClient(transport).request("GET", "http://h/x").status == 404 and len(transport.sent) == 1
    transport = statuses(404, 200)
    HTTPClient(transport, status_forcelist=[404], backoff=0).request("GET", "http://h/x")
    assert len(transport.sent) == 2


def test_retries_zero_sends_once(sleeps):
    transport = statuses(503)
    assert HTTPClient(transport, retries=0).request("GET", "http://h/x").status == 503
    assert len(transport.sent) == 1 and sleeps == []


def test_a_connection_that_never_succeeds_raises_after_the_retries(sleeps):
    class Refusing:
        sent = 0

        def send(self, method, url, **kwargs):
            Refusing.sent += 1
            raise ConnectionRefusedError("no")

    with pytest.raises(ConnectionRefusedError):
        HTTPClient(Refusing(), retries=2, backoff=0).request("GET", "http://h/x")
    assert Refusing.sent == 3
    Refusing.sent = 0
    with pytest.raises(ConnectionRefusedError):
        HTTPClient(Refusing(), retries=2).request("POST", "http://h/x")
    assert Refusing.sent == 1


def test_a_timeout_is_not_retried(sleeps):
    class Slow:
        sent = 0

        def send(self, method, url, **kwargs):
            Slow.sent += 1
            raise TimeoutError("slow")

    with pytest.raises(TimeoutError):
        HTTPClient(Slow(), retries=2).request("GET", "http://h/x")
    assert Slow.sent == 1


def test_the_deadline_bounds_the_retries():
    transport = statuses(503)
    client = HTTPClient(transport, retries=5, backoff=30, deadline=0.5)
    with pytest.raises(TimeoutError):
        client.request("GET", "http://h/x")
    assert len(transport.sent) < 6


def test_a_dropped_connection_on_the_wire_is_retried_for_a_get():
    first = {"n": 0}

    def script(request):
        first["n"] += 1
        return Drop() if first["n"] == 1 else response(body=b"second")

    with Wire(script) as wire:
        with HTTPClient(retries=2, backoff=0, env=DIRECT) as client:
            assert client.request("GET", wire.url + "/").text() == "second"


@pytest.mark.parametrize(
    "options", [{"retries": -1}, {"retries": 1.5}, {"retries": True}, {"backoff": -1}, {"backoff": "1"}]
)
def test_retries_and_backoff_are_checked(options):
    with pytest.raises(ValueError):
        HTTPClient(FakeTransport(), **options)


# -- cookies on every hop ----------------------------------------------------------


def test_a_cookie_set_by_a_redirect_goes_with_the_next_hop():
    def script(request):
        if request.target == "/login":
            return response(302, {"Location": "/home", "Set-Cookie": "sid=abc; Path=/"})
        return response(body=(request.header("Cookie") or "").encode())

    with Wire(script) as wire:
        with HTTPClient(env=DIRECT) as client:
            assert client.request("GET", wire.url + "/login").text() == "sid=abc"
            assert client.request("GET", wire.url + "/again").text() == "sid=abc"


def test_a_cookie_does_not_go_to_another_host_on_a_redirect():
    with Wire(lambda r: response(body=(r.header("Cookie") or "-").encode())) as other:

        def script(request):
            return response(302, {"Location": other.url.replace("127.0.0.1", "localhost") + "/x", "Set-Cookie": "k=1"})

        with Wire(script) as wire:
            with HTTPClient(env=DIRECT) as client:
                assert client.request("GET", wire.url + "/").text() == "-"


def test_a_cookie_header_the_caller_sends_replaces_the_jars():
    with Wire(
        lambda r: response(headers={"Set-Cookie": "k=1; Path=/"}, body=(r.header("Cookie") or "-").encode())
    ) as wire:
        with HTTPClient(env=DIRECT) as client:
            client.request("GET", wire.url + "/")
            assert client.request("GET", wire.url + "/", headers={"Cookie": "mine=2"}).text() == "mine=2"
            assert client.request("GET", wire.url + "/").text() == "k=1"


def test_redirect_carries_the_cookies_too():
    def script(request):
        if request.target == "/start":
            return response(302, {"Location": "/end", "Set-Cookie": "k=1; Path=/"})
        return response(body=(request.header("Cookie") or "-").encode())

    with Wire(script) as wire:
        with HTTPClient(env=DIRECT) as client:
            moved = client.request("GET", wire.url + "/start", allow_redirects=False)
            assert client.redirect("GET", wire.url + "/start", moved).text() == "k=1"


def test_cookies_true_lives_under_the_state_directory_by_host(tmp_path):
    environ = {"SYSHTTP_HOME": str(tmp_path)}
    with Wire(lambda r: response(headers={"Set-Cookie": "k=1; Path=/"})) as wire:
        with HTTPClient(cookies=True, env=HTTPEnv(environ=environ)) as client:
            client.request("GET", wire.url + "/")
    assert (tmp_path / "cookies" / "127.0.0.1.txt").read_text(encoding="utf-8").splitlines()[1].endswith("\tk\t1")


def test_a_named_cookie_key_is_one_jar_entry_for_every_host(tmp_path):
    with Wire(lambda r: response(headers={"Set-Cookie": "k=1; Path=/"})) as wire:
        with HTTPClient(cookies="work", env=HTTPEnv(environ={"SYSHTTP_HOME": str(tmp_path)})) as client:
            client.request("GET", wire.url + "/")
    assert sorted(path.name for path in (tmp_path / "cookies").iterdir()) == ["work.txt"]


def test_a_cookie_jar_object_is_used_as_given():
    jar = MemoryCookieJar()
    with Wire(lambda r: response(headers={"Set-Cookie": "k=1; Path=/"})) as wire:
        with HTTPClient(cookies=jar, env=DIRECT) as client:
            client.request("GET", wire.url + "/")
    assert [c.name for c in jar["127.0.0.1"]] == ["k"]


# -- tokens ---------------------------------------------------------------------


def test_a_token_goes_to_its_origin_as_a_bearer_and_to_no_other_on_a_redirect():
    with Wire(lambda r: response(body=b"ok")) as other:

        def script(request):
            return response(302, {"Location": other.url.replace("127.0.0.1", "localhost") + "/x"})

        with Wire(script) as wire:
            tokens = MemoryTokenJar({"127.0.0.1": "tok", "localhost": "wrong-host-token"})
            with HTTPClient(tokens=tokens, env=DIRECT) as client:
                assert client.request("GET", wire.url + "/").text() == "ok"
    assert wire.requests[0].header("Authorization") == "Bearer tok"
    assert other.requests[0].header("Authorization") is None, "not the token of another origin, nor the first's"


def test_a_token_that_names_its_scheme_is_sent_verbatim_and_a_named_key_serves_every_host(tmp_path):
    from syshttp.jar import FileTokenJar

    FileTokenJar(tmp_path)["service"] = "xyz"
    with Wire() as wire:
        with HTTPClient(tokens=MemoryTokenJar({"127.0.0.1": "token abc"}), env=DIRECT) as client:
            client.request("GET", wire.url + "/")
        with HTTPClient(tokens="service", env=HTTPEnv(environ={"SYSHTTP_HOME": str(tmp_path)})) as client:
            client.request("GET", wire.url + "/")
    assert [r.header("Authorization") for r in wire.requests] == ["token abc", "Bearer xyz"]


def test_a_token_file_is_read_at_each_request(tmp_path):
    from syshttp.jar import FileTokenJar

    jar = FileTokenJar(tmp_path)
    jar["127.0.0.1"] = "first"
    with Wire() as wire:
        with HTTPClient(tokens=jar, env=DIRECT) as client:
            client.request("GET", wire.url + "/")
            jar["127.0.0.1"] = "second"
            client.request("GET", wire.url + "/")
    assert [r.header("Authorization") for r in wire.requests] == ["Bearer first", "Bearer second"]


def test_tokens_true_reads_the_state_directory(tmp_path):
    from syshttp.jar import FileTokenJar

    FileTokenJar(tmp_path)["127.0.0.1"] = "stored"
    with Wire() as wire:
        with HTTPClient(tokens=True, env=HTTPEnv(environ={"SYSHTTP_HOME": str(tmp_path)})) as client:
            client.request("GET", wire.url + "/")
    assert wire.requests[0].header("Authorization") == "Bearer stored"


# -- the auth provider ------------------------------------------------------------


def test_the_auth_provider_runs_before_each_request_and_its_errors_are_swallowed():
    seen = []

    class Provider:
        def ensure(self, client, url):
            seen.append((client, url))
            raise RuntimeError("login is down")

    transport = FakeTransport(default=reply(200))
    client = HTTPClient(transport, auth_provider=Provider())
    assert client.request("GET", "http://h/a").status == 200
    client.request("GET", "http://h/b")
    assert [url for _, url in seen] == ["http://h/a", "http://h/b"] and seen[0][0] is client


def test_a_request_the_provider_makes_does_not_run_the_provider_again_in_that_thread():
    calls = []

    class Provider:
        def ensure(self, client, url):
            calls.append(url)
            client.request("GET", "http://h/login")

    transport = FakeTransport(default=reply(200))
    HTTPClient(transport, auth_provider=Provider()).request("GET", "http://h/a")
    assert calls == ["http://h/a"] and [s.url for s in transport.sent] == ["http://h/login", "http://h/a"]


# -- the hooks --------------------------------------------------------------------


def _signing_hook(client, method, url, kwargs):
    kwargs.setdefault("headers", {})["X-Signed"] = "yes"
    kwargs["timeout"] = 3


def _bad_option_hook(client, method, url, kwargs):
    kwargs["json"] = {}


def _failing_hook(client, method, url, kwargs):
    raise KeyError("no such token")


def test_a_hook_changes_the_headers_and_the_timeout_of_the_request():
    env = HTTPEnv(environ={"SYSHTTP_HOOKS_X": ".", "SYSHTTP_HOOKS_X_PY": "test_client_state:_signing_hook"})
    transport = FakeTransport(default=reply(200))
    HTTPClient(transport, env=env).request("GET", "http://h/x")
    (sent,) = transport.sent
    assert sent.headers["X-Signed"] == "yes" and sent.timeout == 3


def test_a_hook_sets_only_what_request_takes():
    env = HTTPEnv(environ={"SYSHTTP_HOOKS_X": ".", "SYSHTTP_HOOKS_X_PY": "test_client_state:_bad_option_hook"})
    transport = FakeTransport(default=reply(200))
    with pytest.raises(TypeError, match="json"):
        HTTPClient(transport, env=env).request("GET", "http://h/x")
    assert transport.sent == []


def test_a_failing_hook_is_a_hook_error():
    env = HTTPEnv(environ={"SYSHTTP_HOOKS_X": ".", "SYSHTTP_HOOKS_X_PY": "test_client_state:_failing_hook"})
    with pytest.raises(HookError, match="SYSHTTP_HOOKS_X_PY"):
        HTTPClient(FakeTransport(), env=env).request("GET", "http://h/x")


SEEN = []


def _spy_hook(client, method, url, kwargs):
    SEEN.append(dict(kwargs))


def test_the_hooks_see_only_what_the_call_gave():
    del SEEN[:]
    env = HTTPEnv(environ={"SYSHTTP_HOOKS_X": ".", "SYSHTTP_HOOKS_X_PY": "test_client_state:_spy_hook"})
    transport = FakeTransport(default=reply(200))
    client = HTTPClient(transport, env=env)
    client.request("GET", "http://h/x")
    client.request("POST", "http://h/x", data=b"d", stream=True, auth="Bearer t", timeout=5)
    assert SEEN == [{}, {"data": b"d", "stream": True, "auth": "Bearer t", "timeout": 5}]


def test_a_token_that_would_break_a_header_is_refused_naming_the_key_not_the_value():
    client = HTTPClient(FakeTransport(), tokens=MemoryTokenJar({"h": "SECRET\nTWO"}))
    with pytest.raises(ConfigurationError) as caught:
        client.request("GET", "http://h/x")
    assert "'h'" in str(caught.value) and "SECRET" not in str(caught.value)


def test_the_retry_list_is_the_one_the_curl_front_end_uses():
    from syshttp.retry import TRANSIENT_STATUSES

    assert HTTPClient(FakeTransport())._status_forcelist == frozenset(TRANSIENT_STATUSES) and 408 in TRANSIENT_STATUSES

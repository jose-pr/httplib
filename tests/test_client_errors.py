"""What a failed request raises: a status is the reply and `raise_for_status()`
turns it into an error that keeps it; a failed connection is an `OSError` of
the kinds the transport contract lists, with no cause that could quote a URL
or a header."""

import errno

import pytest

from client_fakes import FakeTransport, reply
from client_wire import Hang, Wire, refusing_port
from syshttp.client import HTTPClient, HTTPStatusError, raise_for_status


def test_a_status_of_400_or_more_is_the_reply_not_an_error():
    client = HTTPClient(FakeTransport({("GET", "http://h/x"): reply(404)}))
    assert client.request("GET", "http://h/x").status == 404


@pytest.mark.parametrize("status, raises", [(399, False), (400, True), (404, True), (500, True), (503, True)])
def test_raise_for_status_raises_for_400_and_above_and_keeps_the_reply(status, raises):
    answer = reply(status)
    if not raises:
        raise_for_status(answer)
        return
    with pytest.raises(HTTPStatusError) as excinfo:
        raise_for_status(answer)
    assert excinfo.value.response is answer
    assert str(status) in str(excinfo.value)


def test_a_refused_connection_is_a_connection_error():
    with HTTPClient() as client:
        with pytest.raises(ConnectionError) as excinfo:
            client.request("GET", f"http://127.0.0.1:{refusing_port()}/x")
    assert "127.0.0.1" not in str(excinfo.value)


def test_a_stalled_server_is_a_timeout_error_that_names_no_url():
    with Wire(lambda r: Hang()) as wire:
        url = wire.url + "/secret-path?token=abc"
        with HTTPClient(timeout=0.5) as client:
            with pytest.raises(TimeoutError) as excinfo:
                client.request("GET", url)
    shown = str(excinfo.value) + repr(excinfo.value)
    assert "secret-path" not in shown and "token=abc" not in shown
    assert excinfo.value.__cause__ is None or "secret-path" not in str(excinfo.value.__cause__)


def test_a_dropped_connection_is_a_connection_error():
    from client_wire import Drop

    with Wire(lambda r: Drop()) as wire:
        with HTTPClient() as client:
            with pytest.raises(ConnectionError):
                client.request("GET", wire.url + "/x")


def test_a_reply_that_is_not_http_is_oserror_eio():
    with Wire(lambda r: b"this is not http\r\n\r\n") as wire:
        with HTTPClient() as client:
            with pytest.raises(OSError) as excinfo:
                client.request("GET", wire.url + "/x")
    assert excinfo.value.errno == errno.EIO

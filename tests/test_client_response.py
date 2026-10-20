"""The accessors that read a reply whole: `content`, `text()` and `json()`."""

import json

import pytest

from client_fakes import FakeTransport, reply
from client_wire import Wire, response
from syshttp.client import HTTPClient, HTTPResponse
from syshttp.exceptions import ResponseError, SysHTTPError


def test_content_is_the_decoded_body_and_stays_the_same_when_asked_again():
    answer = reply(200, b"abc")
    assert answer.content == b"abc" == answer.content
    assert answer.text() == "abc"
    assert answer.json.__self__ is answer


def test_the_charset_of_the_content_type_decodes_the_text():
    body = "café".encode("latin-1")
    assert reply(200, body, {"Content-Type": 'text/plain; charset="ISO-8859-1"'}).text() == "café"
    assert reply(200, "café".encode("utf-8"), {"Content-Type": "text/plain"}).text() == "café"
    assert reply(200, body, {"Content-Type": "text/plain; charset=nonsense"}).text() == "caf�"
    assert reply(200, body).text("latin-1") == "café"
    with pytest.raises(UnicodeDecodeError):
        reply(200, body).text(errors="strict")


def test_json_parses_the_body_and_an_empty_body_is_none():
    assert reply(200, b'{"a": [1, 2]}').json() == {"a": [1, 2]}
    assert reply(200, '["é"]'.encode("utf-8")).json() == ["é"]
    assert reply(200, b"").json() is None
    assert reply(200, b"  \n").json() is None


def test_a_body_that_is_not_json_is_a_response_error_naming_the_status():
    with pytest.raises(ResponseError, match="HTTP 502") as excinfo:
        reply(502, b"<html>").json()
    assert isinstance(excinfo.value, (ValueError, SysHTTPError))
    assert "<html>" not in str(excinfo.value)


def test_the_accessors_read_what_the_transport_streams_and_close_it():
    with Wire(lambda r: response(200, {"Content-Type": "application/json"}, json.dumps({"n": 1}).encode())) as wire:
        with HTTPClient() as client:
            stream = client.request("GET", wire.url + "/", stream=True)
            assert stream.json() == {"n": 1}
            assert stream.content == b'{"n": 1}'
            assert stream.status == 200


def test_a_body_over_the_limit_is_oserror_efbig(monkeypatch):
    import errno

    import syshttp.client as client_module

    monkeypatch.setattr(client_module, "MAX_REPLY_BYTES", 10)
    with pytest.raises(OSError) as excinfo:
        reply(200, b"x" * 11).content
    assert excinfo.value.errno == errno.EFBIG
    assert reply(200, b"x" * 10).content == b"x" * 10


def test_a_response_built_by_a_hook_or_a_fake_transport_has_the_accessors():
    answer = HTTPResponse(299, "", {}, "http://h/", b'{"ok": true}')
    assert answer.json() == {"ok": True} and answer.text() == '{"ok": true}'
    assert FakeTransport(default=answer).send("GET", "http://h/", headers={}, timeout=1) is answer

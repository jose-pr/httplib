"""A reply a transport reads whole is held to MAX_REPLY_BYTES after decoding,
and a URL in a message is scheme, host, port and path."""

import errno
import gzip

import pytest

import syshttp.client as client_module
from client_wire import Wire, response
from syshttp import HTTPEnv
from syshttp.client import HTTPResponse, HTTPTransport

DIRECT = HTTPEnv(environ={})


# -- a reply a transport reads whole is bounded --------------------------------


@pytest.fixture
def bomb():
    return gzip.compress(bytes(1024 * 1024))  # a kilobyte or so on the wire


@pytest.fixture
def small_cap(monkeypatch):
    monkeypatch.setattr(client_module, "MAX_REPLY_BYTES", 64 * 1024)


def test_a_transport_reading_a_gzip_bomb_whole_stops_at_the_limit(bomb, small_cap):
    with Wire(lambda r: response(200, {"Content-Encoding": "gzip"}, bomb)) as wire:
        with HTTPTransport(env=DIRECT) as transport:
            url = wire.url + "/p?token=SECRET"
            with pytest.raises(OSError) as excinfo:
                transport.send("GET", url, headers={}, timeout=(5, 5))
    assert excinfo.value.errno == errno.EFBIG
    assert "SECRET" not in str(excinfo.value) and "/p" in str(excinfo.value)


def test_buffered_applies_the_limit_to_a_streamed_gzip_bomb(bomb, small_cap):
    with Wire(lambda r: response(200, {"Content-Encoding": "gzip"}, bomb)) as wire:
        with HTTPTransport(env=DIRECT) as transport:
            streamed = transport.send("GET", wire.url + "/", headers={}, timeout=(5, 5), stream=True)
            with pytest.raises(OSError) as excinfo:
                streamed.buffered()
    assert excinfo.value.errno == errno.EFBIG


def test_buffered_takes_a_limit_of_the_callers_own(bomb, small_cap):
    with Wire(lambda r: response(200, {"Content-Encoding": "gzip"}, bomb)) as wire:
        with HTTPTransport(env=DIRECT) as transport:
            streamed = transport.send("GET", wire.url + "/", headers={}, timeout=(5, 5), stream=True)
            assert len(streamed.buffered(limit=2 * 1024 * 1024).read()) == 1024 * 1024


def test_a_reply_within_the_limit_is_read_whole(small_cap):
    with Wire(lambda r: response(200, {}, b"x" * 1000)) as wire:
        with HTTPTransport(env=DIRECT) as transport:
            assert len(transport.send("GET", wire.url + "/", headers={}, timeout=(5, 5)).read()) == 1000


# -- a URL in a message is scheme, host, port and path --------------------------


def test_the_too_large_error_of_content_names_no_query_userinfo_or_fragment(monkeypatch):
    monkeypatch.setattr(client_module, "MAX_REPLY_BYTES", 10)
    for read in (lambda a: a.content, lambda a: a.text(), lambda a: a.json(), lambda a: a.buffered()):
        answer = HTTPResponse(200, "", {}, "http://user:pw@h.example:8080/p?token=SECRET#frag", b"x" * 11)
        with pytest.raises(OSError) as excinfo:
            read(answer)
        text = str(excinfo.value)
        assert excinfo.value.errno == errno.EFBIG and "http://h.example:8080/p" in text
        assert "SECRET" not in text and "pw" not in text and "frag" not in text and "user" not in text

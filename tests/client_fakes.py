"""Stand-ins for an HTTP transport, for tests that need no server: a
table-driven fake and a wrapper that records what a real one sends."""

from __future__ import annotations

import typing

from syshttp.client import HTTPResponse, HTTPTransport

_REASONS = {
    200: "OK",
    201: "Created",
    204: "No Content",
    207: "Multi-Status",
    301: "Moved Permanently",
    302: "Found",
    307: "Temporary Redirect",
    404: "Not Found",
    409: "Conflict",
    500: "Internal Server Error",
    502: "Bad Gateway",
}


def spy_on_sends(monkeypatch, project=lambda method, url, **kwargs: (method, url)):
    """A list that gains `project(method, url, **keywords)` for every request
    the default transport sends; the requests still go to the server."""
    log = []

    def spy(self, method, url, *args, _original=HTTPTransport.send, **kwargs):
        log.append(project(method, url, **kwargs))
        return _original(self, method, url, *args, **kwargs)

    monkeypatch.setattr(HTTPTransport, "send", spy)
    return log


class Sent(typing.NamedTuple):
    """One call of `send()`."""

    method: str
    url: str
    headers: dict
    body: object
    timeout: object
    stream: bool


def reply(status=200, content=b"", headers=None, reason=None, url=""):
    """An `HTTPResponse` of `status` holding `content`."""
    if reason is None:
        reason = _REASONS.get(status, "")
    return HTTPResponse(status, reason, headers or {}, url, content)


class FakeTransport:
    """Answers from `responses`, keyed `(method, url)`, or `(method, url,
    depth)` for a PROPFIND, and records every call in `sent`. A value is an
    `HTTPResponse` or a callable returning one; a call with no entry goes to
    `handler(method, url, headers=, body=)` when given, else gets `default`
    (a 404 unless given). `fail` is raised by the next call, if set."""

    def __init__(self, responses=None, default=None, handler=None):
        self.responses = dict(responses or {})
        self.default = default
        self.handler = handler
        self.sent: "list[Sent]" = []
        self.closed = 0
        self.fail: "BaseException | None" = None

    def send(self, method, url, *, headers, body=None, timeout, stream=False):
        self.sent.append(Sent(method, url, dict(headers), body, timeout, stream))
        if self.fail is not None:
            error, self.fail = self.fail, None
            raise error
        key = (method, url)
        if method == "PROPFIND":
            key = (method, url, headers.get("Depth"))
        found = self.responses.get(key, self.responses.get((method, url)))
        if found is None and self.handler is not None:
            found = self.handler(method, url, headers=headers, body=body)
        if found is None:
            found = self.default if self.default is not None else reply(404)
        response = found() if callable(found) else found
        if not response.url:
            response.url = url
        return response

    def close(self):
        self.closed += 1


class RecordingTransport:
    """Passes every call to `inner` and records it in `sent`."""

    def __init__(self, inner):
        self.inner = inner
        self.sent: "list[Sent]" = []

    def send(self, method, url, *, headers, body=None, timeout, stream=False):
        self.sent.append(Sent(method, url, dict(headers), body, timeout, stream))
        return self.inner.send(method, url, headers=headers, body=body, timeout=timeout, stream=stream)

    def close(self):
        self.inner.close()

    @property
    def methods(self):
        return [call.method for call in self.sent]

    def clear(self):
        self.sent.clear()


class Script:
    """A transport answering from a table of URL -> (status, header pairs),
    with an empty body, and recording `(method, url, headers)` of every send."""

    def __init__(self, answers=None):
        self.answers = answers or {}
        self.sent = []

    def send(self, method, url, *, headers, body=None, timeout, stream=False):
        self.sent.append((method, url, dict(headers)))
        status, pairs = self.answers.get(url, (200, []))
        return HTTPResponse(status, "", pairs, url, b"")

    def close(self):
        pass

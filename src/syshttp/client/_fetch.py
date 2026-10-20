"""`fetch()`: one request, one response, through a client made for the call or
one the caller keeps."""

from __future__ import annotations

import collections.abc as _abc
import json as _json
import typing as _ty
import urllib.parse as _urlparse

from ._client import DEFAULT_TIMEOUT, HTTPClient
from ._headers import has_header
from ._response import HTTPResponse

REAUTH_STATUSES = (401, 403)
"""The statuses after which `fetch(reauth=...)` runs `reauth` and sends again."""


def _body(data: _ty.Any, json: _ty.Any, headers: "_ty.Mapping[str, str] | None") -> "tuple[_ty.Any, dict[str, str]]":
    """`data` or `json` as the body to send, and `headers` with the
    `Content-Type` that goes with it unless they name one."""
    if data is not None and json is not None:
        raise ValueError("data and json are two bodies: give one")
    sent = dict(headers or {})
    if json is not None:
        body: _ty.Any = _json.dumps(json).encode("utf-8")
        kind = "application/json"
    elif isinstance(data, _abc.Mapping):
        body = _urlparse.urlencode(data, doseq=True).encode("ascii")
        kind = "application/x-www-form-urlencoded"
    else:
        return data, sent
    if not has_header(sent, "Content-Type"):
        sent["Content-Type"] = kind
    return body, sent


def _reauthenticate(reauth: _ty.Any, client: HTTPClient, url: str) -> None:
    ensure = getattr(reauth, "ensure", None)
    if callable(ensure):
        ensure(client, url)
    else:
        reauth(client, url)


def fetch(
    url: str,
    method: str = "GET",
    *,
    headers: "_ty.Mapping[str, str] | None" = None,
    data: _ty.Any = None,
    json: _ty.Any = None,
    timeout: "float | tuple | None" = DEFAULT_TIMEOUT,
    client: "HTTPClient | None" = None,
    transport: _ty.Any = None,
    reauth: _ty.Any = None,
    **client_options: _ty.Any,
) -> HTTPResponse:
    """Send `method` to `url` and return the response with its body read whole
    (`MAX_REPLY_BYTES` bounds it), so the caller takes what it needs from it:
    `.status`, `.headers`, `.content`, `.text()` or `.json()`. A status is never
    an exception: `raise_for_status()` is the caller's choice.

    `data` is bytes, text, a mapping (form-encoded) or a binary file; `json` a
    value sent as JSON (`None` sends none: use `data=b"null"` for that);
    giving both is `ValueError`. `timeout` is seconds or a `(connect, read)`
    pair. The request goes through `client` when given (left open), else
    through a new `HTTPClient(transport, **client_options)` closed after the
    call: `transport` is any object implementing the transport protocol (`None`:
    the `SYSHTTP_DEFAULT_TRANSPORT` setting's, else syshttp's own), and
    `client_options` are the other keywords of `HTTPClient` (`env`, `proxymap`,
    `ssl_context`, `retries`, ...). A `client` beside `transport` or
    `client_options` is `ValueError`: a given client already has them.

    `reauth` is called as `reauth(client, url)` (an object with
    `ensure(client, url)`, an `AuthProvider`, is called through that) once after
    a 401 or 403, and the request is sent one more time; its errors are the
    caller's. The body must then be one that can be sent twice (bytes, text, a
    mapping or `json`)."""
    if client is not None and (transport is not None or client_options):
        raise ValueError(
            "a client was given, and it has its transport and settings already: "
            "pass transport and client options to fetch() alone, or set them on the client"
        )
    body, sent = _body(data, json, headers)
    if reauth is not None and not (body is None or isinstance(body, (bytes, bytearray, memoryview, str))):
        raise ValueError("reauth sends the request twice: the body must be bytes, text, a mapping or json")
    own = client is None
    used = HTTPClient(transport, **client_options) if client is None else client
    try:
        response = used.request(method, url, data=body, headers=sent, timeout=timeout)
        if reauth is not None and response.status in REAUTH_STATUSES:
            _reauthenticate(reauth, used, url)
            response = used.request(method, url, data=body, headers=sent, timeout=timeout)
        return response
    finally:
        if own:
            used.close()

"""What a transport starts from: a request that passed the checks every transport
holds itself to."""

from __future__ import annotations

import typing as _ty

from ._body import prepare_body as _prepare_body
from ._headers import (
    check_body as _check_body,
    check_headers as _check_headers,
    check_method as _check_method,
    check_timeout as _check_timeout,
    check_url as _check_url,
    has_header as _has_header,
    wants_decoding as _wants_decoding,
)

# The methods whose request says `Content-Length: 0` when it has no body.
_EXPECTING_BODY = frozenset({"PATCH", "POST", "PUT"})


class PreparedRequest(_ty.NamedTuple):
    """A request that passed the checks of the transport contract.

    `headers` hold text values, with the `Content-Length` of a body whose
    length is known (`0` for a `PATCH`, `POST` or `PUT` without a body) and an
    `Accept-Encoding` of `gzip, deflate` unless the caller named one. `body` is
    `None`, `bytes`, an object that sends exactly the `Content-Length` bytes
    when it is read or iterated, or an iterable of `bytes` to send chunked.
    `timeout` is `(connect, read)`. `decode` says whether the response decodes
    a `gzip` or `deflate` body: build it with `HTTPResponse(...,
    decode=decode)`."""

    method: str
    url: str
    headers: "dict[str, str]"
    body: _ty.Any
    timeout: "tuple[float | None, float | None]"
    decode: bool


def prepare_request(
    method: str,
    url: str,
    *,
    headers: "_ty.Mapping[str, str] | None",
    body: "bytes | _ty.BinaryIO | _ty.Iterable[bytes] | None" = None,
    timeout: "float | tuple | None",
) -> PreparedRequest:
    """The arguments of `send()` as the contract reads them.

    `method` is upper-cased. Raises `ValueError`, before anything is sent, for
    a method or header name that is not an HTTP token, a header value or URL
    with a control character, a URL with credentials or another scheme, a
    `Content-Length` that is not a count of bytes or exceeds the body, and a
    `timeout` that is not a positive number, `None` or a pair of them;
    `TypeError` for a `str` body. None of the messages quotes the URL or a
    header value. The fragment is dropped from `url`."""
    method = _check_method(method)
    _check_url(url)
    _check_body(body)
    timeout = _check_timeout(timeout)
    pairs = _check_headers(headers)
    sent = dict(pairs)
    body, length = _prepare_body(body, pairs)
    if length is not None:
        sent["Content-Length"] = str(length)
    elif not _has_header(sent, "Content-Length"):
        if isinstance(body, (bytes, bytearray, memoryview)):
            sent["Content-Length"] = str(memoryview(body).nbytes)
        elif body is None and method in _EXPECTING_BODY:
            sent["Content-Length"] = "0"
    decode = _wants_decoding(sent.items())
    if not _has_header(sent, "Accept-Encoding"):
        sent["Accept-Encoding"] = "gzip, deflate"
    return PreparedRequest(method, url.split("#", 1)[0], sent, body, timeout, decode)

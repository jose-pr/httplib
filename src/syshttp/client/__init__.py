"""An HTTP client on the standard library, with a replaceable transport.

`HTTPClient` sends a request through a transport (an object with `send()` and
`close()`: the default `HTTPTransport` on `http.client`, or one written
against the `Transport` protocol) and follows redirects under one rule for
credentials: `Authorization` goes to the origin it was given for and to no
other scheme, host or port. A reply comes back as an `HTTPResponse`.

Importing this package loads `http.client` and `ssl`. Nothing here needs a
third-party library; `requests` in particular is not used.
"""

from __future__ import annotations

import sys as _sys
import types as _types

from . import _settings
from ._client import DEFAULT_TIMEOUT, HTTPClient
from ._context import CA_BUNDLE
from ._default import DEFAULT_TRANSPORT
from ._fetch import fetch
from ._follow import is_redirect, split_userinfo
from ._headers import Headers, peer_text
from ._prepare import PreparedRequest, prepare_request
from ._response import HTTPResponse
from ._state import COOKIE_HOSTS
from ._status import HTTPStatusError, drop_body, json_body, raise_for_status, read_limited
from ._transport import HTTPTransport, Transport

__all__ = [
    "CA_BUNDLE",
    "COOKIE_HOSTS",
    "DEFAULT_TIMEOUT",
    "DEFAULT_TRANSPORT",
    "HTTPClient",
    "HTTPResponse",
    "HTTPStatusError",
    "HTTPTransport",
    "Headers",
    "MAX_REPLY_BYTES",
    "PreparedRequest",
    "Transport",
    "drop_body",
    "fetch",
    "is_redirect",
    "json_body",
    "peer_text",
    "prepare_request",
    "raise_for_status",
    "read_limited",
    "split_userinfo",
]


class _Module(_types.ModuleType):
    """The module, with `MAX_REPLY_BYTES` read from and written to where it
    takes effect."""

    @property
    def MAX_REPLY_BYTES(self) -> int:
        return _settings.MAX_REPLY_BYTES

    @MAX_REPLY_BYTES.setter
    def MAX_REPLY_BYTES(self, value: int) -> None:
        _settings.MAX_REPLY_BYTES = value


_sys.modules[__name__].__class__ = _Module

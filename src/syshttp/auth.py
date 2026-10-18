from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:  # requests is optional at runtime: types only
    import requests


class AuthProvider(Protocol):
    """Something that makes ``session`` authenticated for ``url`` (a login,
    a token refresh) -- called before a request and again after a 401/403
    by :func:`.fetch.request_with_reauth`."""

    def ensure(self, session: "requests.Session", url: str) -> None: ...

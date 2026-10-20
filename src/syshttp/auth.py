from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:  # the client imports this module: types only
    from .client import HTTPClient


__all__ = ("AuthProvider",)


class AuthProvider(Protocol):
    """Something that makes ``client`` authenticated for ``url`` (a login,
    a token refresh): ``HTTPClient`` calls it before each request, and
    ``fetch(reauth=...)`` again after a 401 or 403."""

    def ensure(self, client: "HTTPClient", url: str) -> None: ...

"""What counts as transient -- the one list the client's
retries and a curl front end's ``--retry`` both use. Dependency-free."""

from __future__ import annotations

import time
from typing import Iterable, Optional, Tuple

from ._parse import ascii_int, http_date

__all__ = (
    "TRANSIENT_STATUSES",
    "retry_after",
)

#: The HTTP statuses curl calls transient: request timeout, too many
#: requests, and the 5xx a retry can fix.
TRANSIENT_STATUSES: Tuple[int, ...] = (408, 429, 500, 502, 503, 504)


def retry_after(headers: Iterable[Tuple[str, str]], now: Optional[float] = None) -> Optional[float]:
    """A response's ``Retry-After`` in seconds -- a number, or an HTTP date
    from now -- or ``None`` when absent or unreadable. ``headers`` are
    ``(name, value)`` pairs."""
    value = next((v for k, v in headers if k.lower() == "retry-after"), "").strip()
    if not value:
        return None
    seconds = ascii_int(value)
    if seconds is not None:
        return float(seconds)
    when = http_date(value)
    if when is None:
        return None
    return max(0.0, when - (time.time() if now is None else now))

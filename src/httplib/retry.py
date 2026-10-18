"""What counts as transient -- the one list the requests session's
``Retry`` and the curl fallback's ``--retry`` both use. Dependency-free."""
from __future__ import annotations

import email.utils
import time
from typing import Iterable, Optional, Tuple

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
    if value.isdigit():
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError, OverflowError):
        return None
    return max(0.0, when - (time.time() if now is None else now))

"""Readers for the numbers and dates that headers and cookie files carry."""

from __future__ import annotations

import email.utils
from datetime import timezone
from typing import Optional


def ascii_int(value: str) -> Optional[int]:
    """``value`` as a non-negative integer when it is only the digits
    ``0-9`` (``str.isdigit`` also accepts ``"²"``); else ``None``."""
    value = value.strip()
    return int(value) if value.isascii() and value.isdigit() else None


def http_date(value: str) -> Optional[float]:
    """An HTTP date (IMF-fixdate, RFC 850 or asctime) as a unix time, or
    ``None`` when unreadable. A date without a zone is UTC (RFC 9110
    section 5.6.7)."""
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    try:
        return when.timestamp()
    except (ValueError, OverflowError, OSError):
        return None

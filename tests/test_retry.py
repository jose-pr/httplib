"""retry_after: the seconds a Retry-After header asks for, and the statuses
the session and a curl front end retry."""

import pytest

from syshttp.retry import TRANSIENT_STATUSES, retry_after

WHEN = 784111777.0  # Sun, 06 Nov 1994 08:49:37 GMT


def ask(value, now=None, name="Retry-After"):
    return retry_after([("Content-Type", "text/plain"), (name, value)], now=now)


def test_a_number_of_seconds():
    assert ask("120") == 120.0
    assert ask("  7 ") == 7.0
    assert ask("0") == 0.0


def test_the_header_name_has_any_case_and_the_first_one_counts():
    assert ask("5", name="retry-after") == 5.0
    assert retry_after([("Retry-After", "5"), ("retry-after", "9")]) == 5.0


@pytest.mark.parametrize(
    "date", ["Sun, 06 Nov 1994 08:49:37 GMT", "Sunday, 06-Nov-94 08:49:37 GMT", "Sun Nov  6 08:49:37 1994"]
)
def test_an_http_date_in_each_of_its_three_forms_is_seconds_from_now(date):
    assert ask(date, now=WHEN - 3600) == 3600.0


def test_a_date_in_the_past_is_zero_seconds():
    assert ask("Sun, 06 Nov 1994 08:49:37 GMT", now=WHEN + 60) == 0.0


@pytest.mark.parametrize(
    "value", ["", "   ", "soon", "-5", "1.5", "\u00b2", "\u0663", "12abc", "Sun, 99 Nov 1994 08:49:37 GMT"]
)
def test_an_unreadable_value_is_none(value):
    assert ask(value) is None


def test_an_absent_header_is_none():
    assert retry_after([]) is None
    assert retry_after([("Content-Length", "3")]) is None


def test_the_transient_statuses_are_what_curl_retries():
    assert TRANSIENT_STATUSES == (408, 429, 500, 502, 503, 504)

"""The credential headers a caller names stay with their origin: a redirect to
another scheme, host or port leaves them off, as requests and urllib3 do."""

import pytest

from client_fakes import Script
from syshttp.client import HTTPClient
from syshttp.cookies import CookieSpec
from syshttp.jar import MemoryCookieJar

# -- the caller's credentials stay with their origin ----------------------------

HEADERS = {"Cookie": "sid=secret", "Proxy-Authorization": "Basic x", "Authorization": "Bearer t", "X-Keep": "1"}


@pytest.mark.parametrize(
    "first, second",
    [
        ("https://a.example/", "http://a.example/"),  # a downgrade
        ("https://a.example/", "https://b.example/"),
        ("https://a.example/", "https://a.example:8443/"),
        ("http://a.example/", "https://a.example/"),
    ],
)
def test_a_redirect_to_another_origin_leaves_off_the_callers_credential_headers(first, second):
    script = Script({first: (302, [("Location", second)])})
    with HTTPClient(script) as client:
        client.request("GET", first, headers=HEADERS)
    sent_first, sent_second = script.sent
    assert {"Cookie", "Proxy-Authorization", "Authorization"} <= set(sent_first[2])
    assert sent_second[1] == second
    assert not {"Cookie", "Proxy-Authorization", "Authorization"} & set(sent_second[2])
    assert sent_second[2]["X-Keep"] == "1", "only the credential headers are left off"


def test_a_redirect_within_the_origin_keeps_them():
    script = Script({"https://a.example/": (302, [("Location", "/next")])})
    with HTTPClient(script) as client:
        client.request("GET", "https://a.example/", headers=HEADERS)
    assert script.sent[1][2]["Cookie"] == "sid=secret" and script.sent[1][2]["Proxy-Authorization"] == "Basic x"


def test_the_names_are_matched_without_case_and_a_return_to_the_first_origin_does_not_bring_them_back():
    script = Script(
        {
            "https://a.example/": (302, [("Location", "https://b.example/")]),
            "https://b.example/": (302, [("Location", "https://a.example/back")]),
        }
    )
    with HTTPClient(script) as client:
        client.request("GET", "https://a.example/", headers={"cookie": "sid=secret", "proxy-authorization": "Basic x"})
    assert [bool({"cookie", "proxy-authorization"} & set(sent[2])) for sent in script.sent] == [True, False, False]


def test_the_cookies_of_the_jar_are_chosen_again_for_each_hop():
    jar = MemoryCookieJar(
        {
            "a.example": [CookieSpec("a.example", "/", False, None, "mine", "a")],
            "b.example": [CookieSpec("b.example", "/", False, None, "theirs", "b")],
        }
    )
    script = Script({"https://a.example/": (302, [("Location", "https://b.example/")])})
    with HTTPClient(script, cookies=jar) as client:
        client.request("GET", "https://a.example/")
    assert [sent[2].get("Cookie") for sent in script.sent] == ["mine=a", "theirs=b"]


def test_redirect_leaves_them_off_too():
    script = Script({"https://a.example/": (302, [("Location", "http://b.example/")])})
    with HTTPClient(script) as client:
        moved = client.request("GET", "https://a.example/", headers=HEADERS, allow_redirects=False)
        client.redirect("GET", "https://a.example/", moved, headers=HEADERS)
    assert not {"Cookie", "Proxy-Authorization", "Authorization"} & set(script.sent[-1][2])
    assert script.sent[-1][2]["X-Keep"] == "1"

"""A Secure cookie is left alone by a plain-http response (RFC 6265bis 5.7),
and none is set over plain http but for the loopback hosts."""

from client_fakes import Script
from syshttp.client import HTTPClient

# -- a Secure cookie is left alone by a plain-http response -----------------------


def fetching(answers, *urls):
    script = Script(answers)
    with HTTPClient(script) as client:
        for url in urls:
            client.request("GET", url)
    return script


def cookie_of(script, index):
    return script.sent[index][2].get("Cookie")


SECURE = "https://site.example/"
PLAIN = "http://site.example/"


def test_a_plain_http_response_cannot_replace_a_secure_cookie():
    script = fetching(
        {
            SECURE: (200, [("Set-Cookie", "sid=good; Secure; Path=/")]),
            PLAIN: (200, [("Set-Cookie", "sid=evil; Secure; Path=/")]),
        },
        SECURE,
        PLAIN,
        SECURE + "x",
    )
    assert cookie_of(script, 2) == "sid=good"


def test_nor_with_a_cookie_of_the_same_name_that_is_not_secure():
    script = fetching(
        {
            SECURE: (200, [("Set-Cookie", "sid=good; Secure; Path=/")]),
            PLAIN: (200, [("Set-Cookie", "sid=evil; Path=/")]),
        },
        SECURE,
        PLAIN,
        SECURE + "x",
    )
    assert cookie_of(script, 2) == "sid=good"


def test_nor_delete_it():
    script = fetching(
        {
            SECURE: (200, [("Set-Cookie", "sid=good; Secure; Path=/")]),
            PLAIN: (200, [("Set-Cookie", "sid=; Max-Age=0; Path=/")]),
        },
        SECURE,
        PLAIN,
        SECURE + "x",
    )
    assert cookie_of(script, 2) == "sid=good"


def test_a_secure_cookie_is_not_set_over_plain_http_at_all():
    script = fetching({PLAIN: (200, [("Set-Cookie", "t=1; Secure; Path=/")])}, PLAIN, SECURE)
    assert cookie_of(script, 1) is None


def test_other_cookies_from_a_plain_response_are_kept():
    script = fetching(
        {
            SECURE: (200, [("Set-Cookie", "sid=good; Secure; Path=/admin")]),
            PLAIN: (200, [("Set-Cookie", "other=1; Path=/"), ("Set-Cookie", "sid=free; Path=/else")]),
        },
        SECURE,
        PLAIN,
        SECURE + "else",
    )
    assert sorted(cookie_of(script, 2).split("; ")) == ["other=1", "sid=free"]


def test_a_secure_response_may_replace_a_secure_cookie():
    script = Script({SECURE: (200, [("Set-Cookie", "sid=good; Secure; Path=/")])})
    with HTTPClient(script) as client:
        client.request("GET", SECURE)
        script.answers[SECURE] = (200, [("Set-Cookie", "sid=new; Secure; Path=/")])
        client.request("GET", SECURE)
        client.request("GET", SECURE)
    assert [cookie_of(script, i) for i in (1, 2)] == ["sid=good", "sid=new"]


def test_a_secure_response_may_delete_a_secure_cookie():
    script = Script({SECURE: (200, [("Set-Cookie", "sid=good; Secure; Path=/")])})
    with HTTPClient(script) as client:
        client.request("GET", SECURE)
        script.answers[SECURE] = (200, [("Set-Cookie", "sid=; Max-Age=0; Secure; Path=/")])
        client.request("GET", SECURE)
        client.request("GET", SECURE)
    assert [cookie_of(script, i) for i in (1, 2)] == ["sid=good", None]


def test_a_domain_that_contains_the_other_counts_either_way():
    answers = {
        "https://example.test/": (200, [("Set-Cookie", "sid=good; Secure; Domain=example.test; Path=/")]),
        "http://sub.example.test/": (200, [("Set-Cookie", "sid=evil; Path=/")]),
    }
    script = fetching(answers, "https://example.test/", "http://sub.example.test/", "https://example.test/x")
    assert cookie_of(script, 2) == "sid=good"


def test_the_loopback_hosts_are_secure_contexts():
    script = fetching(
        {"http://localhost/": (200, [("Set-Cookie", "s=1; Secure; Path=/")])}, "http://localhost/", "http://localhost/x"
    )
    assert cookie_of(script, 1) == "s=1"

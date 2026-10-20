"""Cookie host aliases: hosts a user declares to be one for cookies."""

import pytest

from syshttp.cookies import host_aliases, set_cookie_specs
from syshttp.env import HTTPEnv
from syshttp.exceptions import ConfigurationError
from syshttp.jar import FileCookieJar, MemoryCookieJar

from test_cookies import _get, _jar, web  # noqa: F401  (web is a fixture)

GROUP = host_aliases([["app.example.com", "app.example.net"]])


def placed(header, host, aliases=GROUP):
    found = set_cookie_specs([header], host, now=0, aliases=aliases)
    return [(c.domain, c.subdomains) for c, _ in found]


def test_host_aliases_maps_every_host_to_the_first():
    assert host_aliases([["A.example", "b.example.", "[::1]"], ["solo"]]) == {
        "a.example": "a.example",
        "b.example": "a.example",
        "::1": "a.example",
    }


@pytest.mark.parametrize("group", [["a.example", "b.example:8080"], ["a.example", " "], ["a.example", "x/y"]])
def test_a_host_that_is_not_a_name_or_an_address_is_refused(group):
    with pytest.raises(ValueError):
        host_aliases([group])


def test_a_host_in_two_groups_or_a_string_group_is_refused():
    with pytest.raises(ValueError, match="two cookie host groups"):
        host_aliases([["a.example", "b.example"], ["c.example", "b.example"]])
    with pytest.raises(TypeError):
        host_aliases(["a.example,b.example"])


def test_a_member_cookie_belongs_to_the_first_host():
    assert placed("k=v", "app.example.net") == [("app.example.com", False)]
    assert placed("k=v; Domain=app.example.net", "app.example.net") == [("app.example.com", True)]
    assert placed("k=v; Domain=app.example.com", "app.example.net") == [("app.example.com", True)]


def test_a_domain_outside_the_group_is_judged_on_the_host_itself():
    assert placed("k=v; Domain=example.net", "app.example.net") == [("example.net", True)]
    assert placed("k=v; Domain=example.com", "app.example.net") == []
    assert placed("k=v; Domain=app.example.com", "evil.example.org") == []
    assert placed("k=v; Domain=app.example.com", "app.example.net", aliases=None) == []


def test_a_member_sets_a_cookie_every_member_receives_and_the_first_host_keeps(web, tmp_path):
    from syshttp.session import new_session

    session = new_session(cookies=FileCookieJar(tmp_path), retries=0, env=web, cookie_hosts=[list(GROUP)])
    _get(session, "http://app.example.net/", "sid=1; Path=/")
    _get(session, "http://app.example.net/", "wide=1; Domain=app.example.com; Path=/")
    assert sorted(_get(session, "http://app.example.com/").split("; ")) == ["sid=1", "wide=1"]
    assert sorted(_get(session, "http://app.example.net/").split("; ")) == ["sid=1", "wide=1"]
    assert _get(session, "http://other.example.org/") == ""
    assert sorted(p.name for p in (tmp_path / "cookies").iterdir()) == ["app.example.com.txt"]
    again = new_session(cookies=FileCookieJar(tmp_path), retries=0, env=web, cookie_hosts=[list(GROUP)])
    assert sorted(_get(again, "http://app.example.net/").split("; ")) == ["sid=1", "wide=1"]


def test_a_parent_domain_cookie_of_a_member_goes_to_the_whole_group_and_no_further(web, tmp_path):
    from syshttp.session import new_session

    session = new_session(cookies=FileCookieJar(tmp_path), retries=0, env=web, cookie_hosts=[list(GROUP)])
    _get(session, "http://app.example.net/", "sso=1; Domain=example.net; Path=/")
    _get(session, "http://app.example.com/", "corp=1; Domain=example.com; Path=/")
    assert _get(session, "http://api.example.net/") == "sso=1"
    assert _get(session, "http://api.example.com/") == "corp=1"
    assert sorted(_get(session, "http://app.example.com/").split("; ")) == ["corp=1", "sso=1"]
    again = new_session(cookies=FileCookieJar(tmp_path), retries=0, env=web, cookie_hosts=[list(GROUP)])
    assert sorted(_get(again, "http://app.example.net/").split("; ")) == ["corp=1", "sso=1"]


@pytest.mark.parametrize("jar", [None, MemoryCookieJar])
def test_a_member_deletes_the_cookie_another_member_set(web, jar):
    from syshttp.session import new_session

    session = new_session(cookies=jar() if jar else False, retries=0, env=web, cookie_hosts=[list(GROUP)])
    _get(session, "http://app.example.com/", "k=1; Path=/")
    _get(session, "http://app.example.net/", "k=; Max-Age=0; Path=/")
    assert _jar(session) == []


def test_without_a_group_a_host_still_cannot_set_another_hosts_cookie(web):
    from syshttp.session import new_session

    session = new_session(retries=0, env=web)
    _get(session, "http://app.example.net/", "k=1; Path=/")
    _get(session, "http://app.example.net/", "w=1; Domain=app.example.com; Path=/")
    assert _get(session, "http://app.example.com/") == ""
    assert _jar(session) == [("k", "app.example.net", "/", "1")]


def test_the_setting_declares_the_groups_and_an_argument_wins(web):
    from syshttp.session import new_session

    environ = dict(web.environ, SYSHTTP_COOKIE_HOSTS="app.example.com, app.example.net ; wiki,wiki.corp.test")
    env = HTTPEnv(environ=environ)
    session = new_session(retries=0, env=env)
    _get(session, "http://wiki/", "k=1; Path=/")
    assert _get(session, "http://wiki.corp.test/") == "k=1"
    plain = new_session(retries=0, env=env, cookie_hosts=[])
    _get(plain, "http://wiki/", "k=1; Path=/")
    assert _get(plain, "http://wiki.corp.test/") == ""


def test_a_malformed_setting_names_the_variable(web):
    from syshttp.session import new_session

    env = HTTPEnv(environ=dict(web.environ, SYSHTTP_COOKIE_HOSTS="a.example,b.example:80"))
    with pytest.raises(ConfigurationError, match="SYSHTTP_COOKIE_HOSTS"):
        new_session(env=env)

"""How the default transport routes a request: by the proxy map, in absolute
form for `http:` and through `CONNECT` for `https:`, to the first entry that
accepts a connection, with a proxy's credential going to the proxy alone."""

import base64
import ssl
import traceback

import proxylib
import pytest

from client_wire import Proxy, Wire, loopback_authority, refusing_port, response
from syshttp import HTTPEnv
from syshttp.client import HTTPTransport
from syshttp.exceptions import ConfigurationError

TIMEOUT = (5, 5)
NOWHERE = HTTPEnv(environ={})


def get(transport, url, **kwargs):
    return transport.send("GET", url, headers={}, timeout=TIMEOUT, **kwargs)


def basic(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


class Provider:
    """A proxy map as the transport sees it: indexed with a URL, it answers
    one proxy, a sequence of them, `None`, or raises `KeyError`."""

    def __init__(self, answer):
        self.answer = answer
        self.asked = []

    def __getitem__(self, url):
        self.asked.append(url)
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


class Proxied:
    """An object with a `url`, as a proxy resolver's proxies have."""

    def __init__(self, url, username=None, password=None):
        self.url = url
        self.username = username
        self.password = password


@pytest.fixture
def transport_for():
    made = []

    def make(proxymap=None, **kwargs):
        kwargs.setdefault("env", NOWHERE)
        transport = HTTPTransport(proxymap=proxymap, **kwargs)
        made.append(transport)
        return transport

    yield make
    for transport in made:
        transport.close()


# --- http: through a proxy --------------------------------------------------


def test_an_http_request_goes_to_the_proxy_in_absolute_form(transport_for):
    # `backend.test` is never resolved: the proxy is the only host connected to.
    with Proxy() as proxy:
        transport = transport_for(Provider(proxy.url))
        reply = get(transport, "http://backend.test/dir/f?x=1#frag")
        assert reply.read() == b"via proxy"
    (request,) = proxy.requests
    assert request.target == "http://backend.test/dir/f?x=1"
    assert request.header("Host") == "backend.test"


def test_the_map_is_asked_with_the_request_url(transport_for):
    provider = Provider(None)
    with Wire() as wire:
        get(transport_for(provider), wire.url + "/a b?q=1#frag").read()
    assert provider.asked == [f"http://127.0.0.1:{wire.port}/a%20b?q=1"]


def test_proxy_credentials_become_a_proxy_authorization_header(transport_for):
    with Proxy() as proxy:
        url = f"http://us%40er:p%3Aw@127.0.0.1:{proxy.port}"
        get(transport_for(Provider(url)), "http://backend.test/f").read()
    assert proxy.requests[0].header("Proxy-Authorization") == basic("us@er", "p:w")


def test_credentials_of_a_proxy_object_without_them_in_its_url_are_used(transport_for):
    with Proxy() as proxy:
        found = Proxied(proxy.url, username="alice", password="s3cret")
        get(transport_for(Provider(found)), "http://backend.test/f").read()
    assert proxy.requests[0].header("Proxy-Authorization") == basic("alice", "s3cret")


def test_a_proxy_that_carries_its_own_headers_sends_them_to_it_alone(transport_for):
    with Proxy() as proxy:
        entry = proxylib.Proxy("http", "127.0.0.1", proxy.port, headers={"X-Proxy-Token": "t0k"})
        get(transport_for(Provider(entry)), "http://backend.test/f").read()
    assert proxy.requests[0].header("X-Proxy-Token") == "t0k"
    assert proxy.requests[0].header("Proxy-Authorization") is None


def test_the_proxy_credentials_do_not_go_to_a_server_reached_directly(transport_for):
    with Wire() as wire:
        get(transport_for(Provider(None)), wire.url + "/").read()
    assert wire.requests[0].header("Proxy-Authorization") is None


def test_a_proxy_authorization_the_request_sets_is_kept(transport_for):
    with Proxy() as proxy:
        transport = transport_for(Provider(f"http://u:p@127.0.0.1:{proxy.port}"))
        transport.send(
            "GET", "http://backend.test/f", headers={"Proxy-Authorization": "Bearer mine"}, timeout=TIMEOUT
        ).read()
    assert proxy.requests[0].header("Proxy-Authorization") == "Bearer mine"


def test_a_plain_dict_may_use_the_keys_requests_uses(transport_for):
    with Proxy() as proxy:
        transport = transport_for({"http": proxy.url})
        get(transport, "http://backend.test/f").read()
    assert len(proxy.requests) == 1


def test_a_dict_that_names_no_proxy_for_the_url_sends_it_direct(transport_for):
    with Wire() as wire:
        get(transport_for({"https": "http://127.0.0.1:1"}), wire.url + "/").read()
    assert len(wire.requests) == 1


def test_a_proxy_url_without_a_scheme_is_an_http_proxy(transport_for):
    with Proxy() as proxy:
        get(transport_for(Provider(f"127.0.0.1:{proxy.port}")), "http://backend.test/f").read()
    assert len(proxy.requests) == 1


def test_a_map_is_made_from_a_configured_value(transport_for):
    with Proxy() as proxy:
        get(transport_for(f"127.0.0.1:{proxy.port}"), "http://backend.test/f").read()
    assert len(proxy.requests) == 1


def test_a_second_request_to_the_same_proxy_reuses_its_connection(transport_for):
    with Proxy() as proxy:
        transport = transport_for(Provider(proxy.url))
        get(transport, "http://backend.test/a").read()
        get(transport, "http://backend.test/b").read()
        assert [r.target for r in proxy.requests] == ["http://backend.test/a", "http://backend.test/b"]
        assert [r.connection for r in proxy.requests] == [0, 0]


# --- https: through CONNECT ----------------------------------------------------


@pytest.fixture
def secure_origin():
    authority = loopback_authority()
    with Wire(lambda r: response(body=b"secure"), tls=authority.server_context()) as wire:
        yield authority, wire


def test_an_https_request_is_tunnelled_with_connect(transport_for, secure_origin):
    authority, origin = secure_origin
    with Proxy(upstream=("127.0.0.1", origin.port)) as proxy:
        transport = transport_for(
            Provider(f"http://carol:PROXYSECRET@127.0.0.1:{proxy.port}"), ssl_context=authority.client_context()
        )
        assert get(transport, f"https://localhost:{origin.port}/secret?a=b").read() == b"secure"
    (connect,) = proxy.requests
    assert (connect.method, connect.target) == ("CONNECT", f"localhost:{origin.port}")
    assert connect.header("Proxy-Authorization") == basic("carol", "PROXYSECRET")
    (request,) = origin.requests
    assert (request.method, request.target) == ("GET", "/secret?a=b")
    assert request.header("Host") == f"localhost:{origin.port}"
    assert request.header("Proxy-Authorization") is None


def test_the_tunnelled_server_is_verified_for_the_name_asked_for(transport_for, secure_origin):
    authority, origin = secure_origin
    with Proxy(upstream=("127.0.0.1", origin.port)) as proxy:
        # The certificate names localhost and 127.0.0.1, not other.test.
        transport = transport_for(Provider(proxy.url), ssl_context=authority.client_context())
        with pytest.raises(ssl.SSLCertVerificationError):
            get(transport, "https://other.test/")
    assert origin.requests == []


def test_a_proxy_that_refuses_connect_is_a_connection_error(transport_for):
    with Proxy(refuse=407) as proxy:
        transport = transport_for(Provider(f"http://carol:PROXYSECRET@127.0.0.1:{proxy.port}"))
        with pytest.raises(ConnectionError) as excinfo:
            get(transport, "https://backend.test/")
    assert "407" in str(excinfo.value)
    text = "".join(traceback.format_exception(type(excinfo.value), excinfo.value, excinfo.tb))
    assert "PROXYSECRET" not in text and "carol" not in text


def test_a_refused_tunnel_does_not_try_the_next_proxy(transport_for):
    with Proxy(refuse=403) as refusing, Proxy() as second:
        transport = transport_for(Provider([refusing.url, second.url]))
        with pytest.raises(ConnectionError):
            get(transport, "https://backend.test/")
    assert second.requests == []


def test_a_non_ascii_proxy_header_is_refused_without_quoting_it(transport_for):
    with Proxy() as proxy:
        entry = proxylib.Proxy("http", "127.0.0.1", proxy.port, headers={"X-Proxy-Token": "sécret"})
        with pytest.raises(ValueError) as excinfo:
            get(transport_for(Provider(entry)), "http://backend.test/f")
    assert "sécret" not in str(excinfo.value) and proxy.requests == []


# --- an order of proxies -----------------------------------------------------


def test_proxies_are_tried_in_order_when_the_first_cannot_be_reached(transport_for):
    dead = f"http://127.0.0.1:{refusing_port()}"
    with Proxy() as proxy:
        provider = Provider([dead, proxy.url])
        assert get(transport_for(provider), "http://backend.test/f").read() == b"via proxy"
    assert len(proxy.requests) == 1


def test_a_later_proxy_is_not_contacted_once_one_has_answered(transport_for):
    with Proxy() as first, Proxy() as second:
        get(transport_for(Provider([first.url, second.url])), "http://backend.test/f").read()
    assert (len(first.requests), len(second.requests)) == (1, 0)


def test_a_direct_entry_after_a_dead_proxy_means_a_direct_connection(transport_for):
    dead = f"http://127.0.0.1:{refusing_port()}"
    with Wire() as wire:
        reply = get(transport_for(Provider([dead, None])), wire.url + "/")
        assert reply.read() == b"ok"
    assert len(wire.requests) == 1


def test_when_no_proxy_answers_and_none_is_direct_the_request_is_refused(transport_for):
    dead = [f"http://127.0.0.1:{refusing_port()}" for _ in range(2)]
    with pytest.raises(proxylib.NoReachableProxyError):
        get(transport_for(Provider(dead)), "http://backend.test/f")


def test_an_empty_answer_means_no_proxy(transport_for):
    with Wire() as wire:
        get(transport_for(Provider([])), wire.url + "/").read()
    assert len(wire.requests) == 1


# --- no opinion, and the settings ----------------------------------------------


def test_a_keyerror_from_the_map_means_a_direct_connection(transport_for):
    with Wire() as wire:
        get(transport_for(Provider(KeyError("no opinion"))), wire.url + "/").read()
    assert len(wire.requests) == 1


def test_an_empty_mapping_forces_direct_and_the_settings_are_not_read(transport_for):
    environ = {"HTTP_PROXY": f"http://127.0.0.1:{refusing_port()}"}
    with Wire() as wire:
        get(transport_for({}, env=HTTPEnv(environ=environ)), wire.url + "/").read()
    assert len(wire.requests) == 1


def test_without_a_map_the_proxy_variables_choose_the_proxy(transport_for):
    with Proxy() as proxy:
        env = HTTPEnv(environ={"HTTP_PROXY": proxy.url})
        assert get(transport_for(env=env), "http://backend.test/f").read() == b"via proxy"
    assert proxy.requests[0].target == "http://backend.test/f"


def test_syshttp_proxy_beats_the_proxy_variables(transport_for):
    with Proxy() as mine, Proxy() as machine:
        env = HTTPEnv(environ={"SYSHTTP_PROXY": mine.url, "HTTP_PROXY": machine.url})
        get(transport_for(env=env), "http://backend.test/f").read()
    assert (len(mine.requests), len(machine.requests)) == (1, 0)


def test_no_proxy_sends_a_host_direct(transport_for):
    with Proxy() as proxy, Wire() as wire:
        env = HTTPEnv(environ={"HTTP_PROXY": proxy.url, "NO_PROXY": "127.0.0.1"})
        get(transport_for(env=env), wire.url + "/").read()
    assert proxy.requests == [] and len(wire.requests) == 1


def test_all_proxy_serves_a_scheme_with_none_of_its_own(transport_for):
    with Proxy() as proxy:
        get(transport_for(env=HTTPEnv(environ={"ALL_PROXY": proxy.url})), "http://backend.test/f").read()
    assert len(proxy.requests) == 1


def test_the_settings_are_read_through_the_prefixes_of_the_env(transport_for):
    with Proxy() as mine, Proxy() as machine:
        environ = {"MYTOOL_SYSHTTP_PROXY": mine.url, "SYSHTTP_PROXY": machine.url}
        get(transport_for(env=HTTPEnv("MYTOOL_", environ=environ)), "http://backend.test/f").read()
    assert (len(mine.requests), len(machine.requests)) == (1, 0)


def test_a_malformed_proxy_setting_is_refused_when_the_transport_is_made():
    env = HTTPEnv(environ={"SYSHTTP_PROXY": "http://proxy.example:3128", "SYSHTTP_PROXY_AUTH": "SECRET\nTWO"})
    with pytest.raises(ValueError) as caught:
        HTTPTransport(env=env)
    assert "SYSHTTP_PROXY_AUTH" in str(caught.value) and "SECRET" not in str(caught.value)


# --- what is not spoken, and what is never shown ----------------------------------


@pytest.mark.parametrize(
    "url", ["socks5://carol:PROXYSECRET@127.0.0.1:1080", "socks4://127.0.0.1:1080", "socks5h://127.0.0.1:1080"]
)
def test_a_socks_proxy_is_refused_naming_it_without_its_credential(transport_for, url):
    with pytest.raises(proxylib.UnsupportedProxyError) as excinfo:
        get(transport_for(Provider(url)), "http://backend.test/f")
    text = str(excinfo.value)
    assert "socks" in text and "PROXYSECRET" not in text and "carol" not in text


def test_a_socks_entry_among_others_is_skipped(transport_for):
    with Proxy() as proxy:
        provider = Provider(["socks5://127.0.0.1:1", proxy.url])
        assert get(transport_for(provider), "http://backend.test/f").read() == b"via proxy"


def test_a_transport_repr_shows_no_proxy_credentials(transport_for):
    transport = transport_for(Provider("http://user:PROXYSECRET@proxy.example:3128"))
    assert "PROXYSECRET" not in repr(transport) + str(transport)


# --- a URL-prefix gateway ------------------------------------------------------


def gateway(proxy, prefix="/fetch/"):
    return proxylib.Proxy("prefix+http", "127.0.0.1", proxy.port, "carol", "PROXYSECRET", path=prefix)


def test_a_gateway_is_asked_for_its_prefix_and_the_url_with_its_credential(transport_for):
    with Proxy() as proxy:
        reply = get(transport_for(Provider(gateway(proxy))), "http://backend.test/dir/f?x=1")
        assert reply.read() == b"via proxy"
    (request,) = proxy.requests
    assert request.target == "/fetch/http://backend.test/dir/f?x=1"
    assert request.header("Host") == f"127.0.0.1:{proxy.port}"
    assert request.header("Proxy-Authorization") == basic("carol", "PROXYSECRET")


def test_a_reply_through_a_gateway_keeps_the_url_asked_for(transport_for):
    with Proxy() as proxy:
        reply = get(transport_for(Provider(gateway(proxy))), "http://backend.test/dir/f?x=1#frag")
        assert reply.url == "http://backend.test/dir/f?x=1"
        reply.close()


def test_a_gateway_carries_the_headers_of_the_request_and_its_own(transport_for):
    with Proxy() as proxy:
        entry = proxylib.Proxy("prefix+http", "127.0.0.1", proxy.port, path="/fetch/", headers={"X-Gate": "g"})
        transport = transport_for(Provider(entry))
        transport.send("GET", "http://backend.test/f", headers={"Cookie": "a=1"}, timeout=TIMEOUT).read()
    (request,) = proxy.requests
    assert request.header("Cookie") == "a=1" and request.header("X-Gate") == "g"


def test_an_https_origin_is_not_sent_through_a_plain_http_gateway(transport_for):
    """Its tokens and Secure cookies would cross the gateway in clear text."""
    with Proxy() as proxy:
        with pytest.raises(proxylib.UnsupportedProxyError) as excinfo:
            get(transport_for(Provider(gateway(proxy))), "https://backend.test/f")
    assert "clear text" in str(excinfo.value) and "PROXYSECRET" not in str(excinfo.value)
    assert proxy.requests == []


def test_a_plain_http_gateway_is_skipped_for_an_https_origin_when_another_entry_can_serve_it(transport_for):
    authority = loopback_authority()
    with Wire(lambda r: response(body=b"secure"), tls=authority.server_context()) as origin:
        with Proxy() as proxy:
            entries = [gateway(proxy), None]
            transport = transport_for(Provider(entries), ssl_context=authority.client_context())
            assert get(transport, f"https://localhost:{origin.port}/x").read() == b"secure"
    assert proxy.requests == [] and len(origin.requests) == 1


def test_an_http_origin_is_still_asked_of_a_plain_http_gateway(transport_for):
    with Proxy() as proxy:
        get(transport_for(Provider(gateway(proxy))), "http://backend.test/f").read()
    assert proxy.requests[0].target == "/fetch/http://backend.test/f"


def test_an_https_origin_is_asked_of_an_https_gateway_over_tls_without_a_tunnel(transport_for):
    authority = loopback_authority()
    with Wire(lambda r: response(body=b"gateway"), tls=authority.server_context()) as gate:
        entry = proxylib.Proxy("prefix+https", "localhost", gate.port, "carol", "PROXYSECRET", path="/fetch/")
        transport = transport_for(Provider(entry), proxy_ssl_context=authority.client_context())
        assert get(transport, "https://backend.test/f").read() == b"gateway"
    (request,) = gate.requests
    assert (request.method, request.target) == ("GET", "/fetch/https://backend.test/f")
    assert request.header("Proxy-Authorization") == basic("carol", "PROXYSECRET")


def test_a_configured_gateway_routes_through_the_settings(transport_for):
    with Proxy() as proxy:
        environ = {"SYSHTTP_PROXY": proxy.url, "SYSHTTP_PROXY_TYPE": "prefix:/fetch/", "SYSHTTP_PROXY_AUTH": "Bearer t"}
        get(transport_for(env=HTTPEnv(environ=environ)), "http://backend.test/f").read()
    (request,) = proxy.requests
    assert request.target == "/fetch/http://backend.test/f"
    assert request.header("Proxy-Authorization") == "Bearer t"


def test_a_setting_that_cannot_be_used_is_a_configuration_error():
    env = HTTPEnv(environ={"SYSHTTP_PROXY": "http://proxy.example:3128", "SYSHTTP_PROXY_TYPE": "socks5"})
    with pytest.raises(ConfigurationError, match="SYSHTTP_PROXY_TYPE"):
        HTTPTransport(env=env)

"""SYSHTTP_DEFAULT_TRANSPORT: the transport of a client that is given none, named
by an object reference (`module:attr`, `<file>.py:attr`) and read through the
prefixes like every setting."""

import pytest

from client_fakes import FakeTransport, reply
from syshttp import HTTPEnv
from syshttp.client import DEFAULT_TRANSPORT, HTTPClient, HTTPTransport
from syshttp.exceptions import ConfigurationError

SHARED = FakeTransport(default=reply(200, b"shared"))
BUILT = []


def factory():
    BUILT.append(FakeTransport(default=reply(200, b"made")))
    return BUILT[-1]


class Nothing:
    """Not a transport, and what it makes is not one either."""


def make_nothing():
    return object()


def env(value, prefixes=None, **more):
    return HTTPEnv(prefixes, environ={DEFAULT_TRANSPORT: value, **more})


@pytest.fixture(autouse=True)
def _built():
    del BUILT[:]
    SHARED.sent.clear()
    SHARED.closed = 0


def test_the_variable_is_named_in_the_module():
    assert DEFAULT_TRANSPORT == "SYSHTTP_DEFAULT_TRANSPORT"


def test_without_the_setting_the_client_builds_an_http_transport():
    with HTTPClient(env=HTTPEnv(environ={})) as client:
        assert type(client.transport) is HTTPTransport


def test_an_object_with_send_is_the_transport_and_stays_the_callers():
    client = HTTPClient(env=env("test_client_default_transport:SHARED"))
    assert client.transport is SHARED
    assert client.request("GET", "http://h/x").content == b"shared"
    client.close()
    assert SHARED.closed == 0, "a shared object is not the client's to close"


def test_a_class_is_called_for_the_transport_and_the_client_closes_it():
    client = HTTPClient(env=env("client_fakes:FakeTransport"))
    made = client.transport
    assert type(made) is FakeTransport and made is not SHARED
    client.close()
    assert made.closed == 1


def test_a_factory_is_called_once_per_client_and_again_after_close():
    client = HTTPClient(env=env("test_client_default_transport:factory"))
    assert len(BUILT) == 1 and client.transport is BUILT[0]
    assert client.request("GET", "http://h/x").content == b"made"
    client.close()
    assert BUILT[0].closed == 1
    assert client.transport is BUILT[1] and len(BUILT) == 2


class Holder:
    shared = SHARED


def test_a_dotted_attribute_is_followed():
    assert HTTPClient(env=env("test_client_default_transport:Holder.shared")).transport is SHARED


def test_a_python_file_names_the_object(tmp_path):
    source = tmp_path / "my transport.py"
    source.write_text(
        "from client_fakes import FakeTransport, reply\n"
        "class Mine(FakeTransport):\n"
        "    def __init__(self):\n"
        "        super().__init__(default=reply(200, b'from a file'))\n",
        encoding="utf-8",
    )
    client = HTTPClient(env=env("%s:Mine" % source))
    assert client.request("GET", "http://h/x").content == b"from a file"


def test_an_explicit_transport_beats_the_setting():
    mine = FakeTransport(default=reply(200, b"mine"))
    client = HTTPClient(mine, env=env("test_client_default_transport:SHARED"))
    assert client.transport is mine
    assert client.request("GET", "http://h/x").content == b"mine" and SHARED.sent == []


def test_the_setting_is_read_through_the_prefixes():
    environ = {"APP_SYSHTTP_DEFAULT_TRANSPORT": "test_client_default_transport:SHARED"}
    client = HTTPClient(env=HTTPEnv("APP_:", environ=environ))
    assert client.transport is SHARED
    # Only the unprefixed name set: the first prefix has none, the empty one has it.
    both = HTTPEnv("APP_:", environ={DEFAULT_TRANSPORT: "test_client_default_transport:SHARED"})
    assert HTTPClient(env=both).transport is SHARED
    # A tool that opts out of the unprefixed names does not see it.
    only_app = HTTPEnv("APP_", environ={DEFAULT_TRANSPORT: "test_client_default_transport:SHARED"})
    assert type(HTTPClient(env=only_app).transport) is HTTPTransport


def test_the_first_prefix_wins():
    environ = {
        "APP_SYSHTTP_DEFAULT_TRANSPORT": "test_client_default_transport:factory",
        DEFAULT_TRANSPORT: "test_client_default_transport:SHARED",
    }
    assert HTTPClient(env=HTTPEnv("APP_:", environ=environ)).transport is BUILT[0]


def test_the_setting_is_read_when_the_client_is_built():
    environ = {DEFAULT_TRANSPORT: "test_client_default_transport:SHARED"}
    client = HTTPClient(env=HTTPEnv(environ=environ))
    environ[DEFAULT_TRANSPORT] = "test_client_default_transport:factory"
    assert client.transport is SHARED and BUILT == []


@pytest.mark.parametrize(
    "value, fragment",
    [
        ("nonsense", "written <module or file.py>:<name>"),
        ("no_such_module_xyz:thing", "cannot be loaded (ModuleNotFoundError"),
        ("client_fakes:no_such_attribute", "cannot be loaded (AttributeError"),
        ("test_client_default_transport:BUILT", "neither a transport nor something that makes one"),
        ("test_client_default_transport:make_nothing", "makes no object with send()"),
        ("test_client_default_transport:Nothing", "makes no object with send()"),
    ],
)
def test_a_value_that_cannot_be_used_is_a_configuration_error_naming_the_variable(value, fragment):
    with pytest.raises(ConfigurationError) as caught:
        HTTPClient(env=env(value))
    assert DEFAULT_TRANSPORT in str(caught.value) and fragment in str(caught.value)


def test_the_error_names_the_variable_as_it_is_set_under_a_prefix():
    environ = {"APP_SYSHTTP_DEFAULT_TRANSPORT": "no_such_module_xyz:thing"}
    with pytest.raises(ConfigurationError, match="APP_SYSHTTP_DEFAULT_TRANSPORT"):
        HTTPClient(env=HTTPEnv("APP_", environ=environ))


def test_a_factory_that_raises_is_a_configuration_error_with_its_error_as_the_cause():
    with pytest.raises(ConfigurationError, match="failed to make a transport") as caught:
        HTTPClient(env=env("test_client_default_transport:explode"))
    assert isinstance(caught.value.__cause__, RuntimeError)


def explode():
    raise RuntimeError("no transport today")


@pytest.mark.parametrize("option", [{"verify": False}, {"ssl_context": object()}, {"proxymap": {}}])
def test_options_of_the_default_transport_beside_the_setting_are_refused(option):
    with pytest.raises(ConfigurationError, match="SYSHTTP_DEFAULT_TRANSPORT"):
        HTTPClient(env=env("test_client_default_transport:SHARED"), **option)

"""The error classes: what went wrong at run time is a SysHTTPError (and the
builtin a caller already catches); a caller's own mistake is not."""

import pytest

import syshttp
from syshttp import HTTPEnv, hooks, proxy
from syshttp.exceptions import ConfigurationError, HookError, ResponseError, SysHTTPError


def test_the_classes_are_exported_from_the_root_and_the_module():
    for name in ("SysHTTPError", "ConfigurationError", "HookError", "ResponseError"):
        assert getattr(syshttp, name) is getattr(__import__("syshttp.exceptions", fromlist=[name]), name)
    assert issubclass(ConfigurationError, (SysHTTPError, ValueError))
    assert issubclass(ResponseError, (SysHTTPError, ValueError))
    assert issubclass(HookError, (SysHTTPError, RuntimeError))
    assert not issubclass(SysHTTPError, (ValueError, RuntimeError))


@pytest.mark.parametrize(
    "environ",
    [
        {"SYSHTTP_PROXY": "http://h:1", "SYSHTTP_PROXY_TYPE": "bogus"},
        {"SYSHTTP_PROXY": "http://h:1", "SYSHTTP_PROXY_AUTH": "x", "SYSHTTP_PROXY_AUTH_HEADER": "bad name"},
        {"SYSHTTP_PROXY": "http://h:1", "SYSHTTP_PROXY_AUTH": "a\nb"},
        {"SYSHTTP_PROXY": "socks5://h:1", "SYSHTTP_PROXY_TYPE": "prefix"},
        {"SYSHTTP_SYSTEM_PROXY": "maybe"},
    ],
)
def test_a_malformed_proxy_setting_is_a_configuration_error(environ):
    import proxylib

    env = HTTPEnv(environ=environ)
    with pytest.raises(ConfigurationError) as caught:
        proxylib.lookup(proxy.proxy_map(env=env), "http://a.example/")
    assert isinstance(caught.value, ValueError)


def test_a_malformed_prefix_variable_is_a_configuration_error_and_the_argument_is_not():
    with pytest.raises(ConfigurationError, match="SYSHTTP_PREFIX"):
        HTTPEnv(environ={"SYSHTTP_PREFIX": "A-B_"}).prefixes
    with pytest.raises(ValueError) as caught:
        HTTPEnv("A-B_")
    assert not isinstance(caught.value, SysHTTPError)


def test_hook_settings_that_cannot_be_used_are_configuration_errors():
    with pytest.raises(ConfigurationError, match="SYSHTTP_HOOKS_BAD"):
        hooks.hooks_from_env(env=HTTPEnv(environ={"SYSHTTP_HOOKS_BAD": "(", "SYSHTTP_HOOKS_BAD_PY": "m:f"}))
    with pytest.raises(ConfigurationError):
        hooks.load_callable("nocolon")
    with pytest.raises(ConfigurationError, match="not callable"):
        hooks.load_callable("os:sep")
    empty = hooks.Hook("X", __import__("re").compile("."), "  ", None)
    with pytest.raises(ConfigurationError):
        hooks.curl_command(empty)


def test_a_failing_hook_is_a_hook_error_with_the_hooks_own_exception_as_its_cause():
    env = HTTPEnv(environ={"SYSHTTP_HOOKS_B": ".", "SYSHTTP_HOOKS_B_PY": "nosuchmodule_xyz:f"})
    with pytest.raises(HookError) as caught:
        hooks.call_py_hooks(None, "GET", "https://h/x", {}, env=env)
    assert isinstance(caught.value, RuntimeError) and isinstance(caught.value.__cause__, ImportError)


def test_a_body_that_is_not_json_is_a_response_error():
    from client_fakes import FakeTransport, reply
    from syshttp import fetch

    response = fetch("http://h/", transport=FakeTransport(default=reply(200, b"<html>")))
    with pytest.raises(ResponseError, match="HTTP 200"):
        response.json()


def test_a_callers_contradictory_options_are_plain_value_errors():
    import ssl

    from client_fakes import FakeTransport
    from syshttp.client import HTTPClient

    with pytest.raises(ValueError) as caught:
        HTTPClient(ssl_context=ssl.create_default_context(), verify=False)
    assert not isinstance(caught.value, SysHTTPError)
    with pytest.raises(ValueError) as caught:
        HTTPClient(FakeTransport(), verify=False)
    assert not isinstance(caught.value, SysHTTPError)


def test_a_token_with_a_line_break_is_a_configuration_error():
    from syshttp.client import HTTPClient
    from syshttp.jar import MemoryTokenJar

    client = HTTPClient(tokens=MemoryTokenJar({"127.0.0.1": "a\nb"}), retries=0, env=HTTPEnv(environ={}))
    with pytest.raises(ConfigurationError, match="127.0.0.1"):
        client.request("GET", "http://127.0.0.1:9/")


def test_building_a_client_changes_no_process_wide_warning_filter():
    import warnings

    from syshttp.client import HTTPClient

    before = list(warnings.filters)
    HTTPClient(verify=False, env=HTTPEnv(environ={})).close()
    assert list(warnings.filters) == before


def test_constructing_a_jar_touches_no_filesystem(tmp_path):
    from syshttp.jar import FileCookieJar, FileTokenJar

    FileCookieJar(tmp_path / "state")
    FileTokenJar(tmp_path / "state")
    assert not (tmp_path / "state").exists()

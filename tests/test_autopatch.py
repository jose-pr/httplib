"""syshttp.autopatch: requests, urllib, httpx and aiohttp, patched, route by
syshttp and verify with the system's context, unless the caller chose.

The proxy is a loopback forward proxy that answers itself and records the
credential (test_proxy_auth); <P>_PROXY names it, or a fake system
configuration does."""

import asyncio
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

import proxylib
import pytest

from syshttp import HTTPEnv, autopatch
from syshttp import proxy as syshttp_proxy
from syshttp import tls as syshttp_tls
from test_proxy_auth import BEARER, _clean_env, _Proxy, proxy, target  # noqa: F401  (fixtures)

requests = pytest.importorskip("requests")
httpx = pytest.importorskip("httpx")
aiohttp = pytest.importorskip("aiohttp")


@pytest.fixture()
def patched():
    """Patch every target for the test, unpatch after."""
    autopatch.patch()
    try:
        yield
    finally:
        autopatch.unpatch()


@pytest.fixture()
def configured(proxy, monkeypatch):
    """<P>_PROXY is the loopback proxy, with a Bearer credential."""
    _Proxy.expected = BEARER
    monkeypatch.setenv("SYSHTTP_PROXY", "http://" + proxy)
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    return proxy


@pytest.fixture()
def dead_port():
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _unreachable_system(monkeypatch, port):
    """The system names one proxy, and nothing listens there."""
    monkeypatch.setattr(syshttp_proxy, "system_map", lambda: proxylib.SimpleProxyMap("PROXY 127.0.0.1:%d" % port))


# ---- the setting ---------------------------------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [
        ("1", set(autopatch.TARGETS)),
        ("TRUE", set(autopatch.TARGETS)),
        ("0", set()),
        ("", set()),
        ("requests:urllib.request: httpx", {"requests", "urllib", "httpx"}),
        ("aiohttp::", {"aiohttp"}),
    ],
)
def test_the_setting_names_the_targets(value, expected):
    assert autopatch.enabled(env=HTTPEnv(environ={"SYSHTTP_IMPORTPATCH": value})) == expected


def test_an_unknown_name_is_logged_and_skipped(caplog):
    env = HTTPEnv(environ={"SYSHTTP_IMPORTPATCH": "requests:pycurl"})
    assert autopatch.enabled(env=env) == {"requests"}
    assert "SYSHTTP_IMPORTPATCH names 'pycurl'" in caplog.text


def test_a_prefix_of_its_own_names_prefix_syshttp_importpatch():
    env = HTTPEnv(
        environ={
            "SYSHTTP_PREFIX": "AGENTS",
            "AGENTS_SYSHTTP_IMPORTPATCH": "httpx",
            "AGENTS_IMPORTPATCH": "1",
            "SYSHTTP_IMPORTPATCH": "1",
        }
    )
    assert autopatch.setting_name(env=env) == "AGENTS_SYSHTTP_IMPORTPATCH"
    assert autopatch.enabled(env=env) == {"httpx"}


@pytest.mark.parametrize("prefix", [None, "SYSHTTP", ""])
def test_the_default_or_no_prefix_reads_syshttp_importpatch(prefix):
    environ = {"SYSHTTP_IMPORTPATCH": "requests"}
    env = HTTPEnv(environ=environ) if prefix is None else HTTPEnv(prefix=prefix, environ=environ)
    assert autopatch.setting_name(env=env) == "SYSHTTP_IMPORTPATCH"
    assert autopatch.enabled(env=env) == {"requests"}


def test_the_entry_point_patches_only_what_the_setting_enables(monkeypatch):
    try:
        autopatch.importpatch("requests", requests)
        assert autopatch.patched() == ()
        monkeypatch.setenv("SYSHTTP_IMPORTPATCH", "requests")
        autopatch.importpatch("requests", requests)
        autopatch.importpatch("httpx", httpx)
        assert autopatch.patched() == ("requests",)
    finally:
        autopatch.unpatch()


def test_a_plain_import_is_patched_in_a_new_interpreter():
    """The real path: importpatch's .pth, syshttp's entry point, the setting."""
    code = (
        "import proxylib, requests\n"
        "adapter = requests.Session().get_adapter('https://x.example/')\n"
        "try:\n"
        "    print(proxylib.lookup(adapter.proxymap, 'https://x.example/')[0].url)\n"
        "except KeyError:\n"
        "    print('no opinion')\n"
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith(("SYSHTTP_", "PROXYLIB_"))}
    env["SYSHTTP_PROXY"] = "http://p.example:1"
    plain = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60)
    env["SYSHTTP_IMPORTPATCH"] = "requests"
    patched = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60)
    assert (plain.stdout.strip(), patched.stdout.strip()) == ("no opinion", "http://p.example:1"), patched.stderr


def test_unpatch_restores_every_library(patched):
    autopatch.unpatch()
    assert autopatch.patched() == ()
    for target in ("requests", "urllib", "httpx", "aiohttp"):
        assert type(proxylib.patching.active(target)).__module__ != "syshttp.proxy", target
    assert not hasattr(requests.adapters.HTTPAdapter.cert_verify, "__wrapped__")
    assert ssl._create_default_https_context is not autopatch._default_https_context
    with httpx.Client() as client:
        assert client._transport._transports._kwargs.get("verify", True) is True


# ---- requests ----------------------------------------------------------------


def test_requests_goes_through_the_configured_proxy(patched, configured, target):
    resp = requests.get(target + "/x", timeout=5)
    assert resp.text == "via-proxy" and _Proxy.seen[-1] == (target + "/x", BEARER)


def test_requests_keeps_the_callers_proxy_for_its_host(patched, proxy, target, monkeypatch, dead_port):
    """proxylib's rule: a caller's entry at ``scheme://hostname`` wins; a bare
    ``"http"`` key -- the one requests also fills from the environment --
    does not."""
    _Proxy.expected = None
    monkeypatch.setenv("SYSHTTP_PROXY", "http://127.0.0.1:%d" % dead_port)
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
    resp = requests.get(target + "/x", proxies={"http://127.0.0.1": "http://" + proxy}, timeout=5)
    assert resp.text == "via-proxy" and _Proxy.seen[-1] == (target + "/x", None), "no syshttp credential"
    with pytest.raises(requests.exceptions.ProxyError):
        requests.get(target + "/x", proxies={"http": "http://" + proxy}, timeout=5)


def test_requests_gets_the_system_context(patched):
    if not hasattr(requests.adapters.HTTPAdapter, "build_connection_pool_key_attributes"):
        pytest.skip("requests < 2.32.2 builds its pools without this hook")
    adapter = requests.Session().get_adapter("https://example.com/")
    prepared = requests.Request("GET", "https://example.com/").prepare()
    _host, pool = adapter.build_connection_pool_key_attributes(prepared, True, None)
    assert pool["ssl_context"] is syshttp_tls.os_ssl_context()


def test_requests_reports_no_reachable_proxy(patched, monkeypatch, dead_port):
    _unreachable_system(monkeypatch, dead_port)
    with pytest.raises(requests.exceptions.ProxyError, match="port=%d" % dead_port):
        requests.get("http://a.example/", timeout=5)


# ---- urllib ------------------------------------------------------------------


def test_urllib_goes_through_the_configured_proxy_on_every_hop(patched, configured, target):
    with urllib.request.urlopen(target + "/redirect", timeout=5) as resp:
        assert resp.read() == b"via-proxy"
    assert _Proxy.seen == [(target + "/redirect", BEARER), (target + "/final", BEARER)]


def test_urllib_keeps_an_explicit_proxy_handler(patched, target, monkeypatch, dead_port):
    monkeypatch.setenv("SYSHTTP_PROXY", "http://127.0.0.1:%d" % dead_port)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(target + "/x", timeout=5) as resp:
        assert resp.read() == b"hello"


def test_urllib_gets_the_system_context_by_default(patched):
    ctx = ssl._create_default_https_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert ctx is not syshttp_tls.os_ssl_context(), "http.client sets ALPN on it: not the shared one"


def test_urllib_refuses_a_custom_credential_header_over_connect(patched, monkeypatch, configured):
    """urllib moves only Proxy-Authorization onto the CONNECT; any other
    header would travel through the tunnel to the origin."""
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH_HEADER", "X-Proxy-Token")
    with pytest.raises(proxylib.UnsupportedProxyError):
        urllib.request.urlopen("https://example.invalid/", timeout=5)


def test_urllib_reports_no_reachable_proxy(patched, monkeypatch, dead_port):
    _unreachable_system(monkeypatch, dead_port)
    with pytest.raises(urllib.error.URLError) as caught:
        urllib.request.urlopen("http://a.example/", timeout=5)
    assert isinstance(caught.value.reason, proxylib.NoReachableProxyError)


def test_urllib_goes_through_a_prefix_gateway(patched, monkeypatch, target):
    from test_proxy_auth import _Gateway, _serve

    _Gateway.seen = []
    gw = _serve(_Gateway)
    try:
        monkeypatch.setenv("SYSHTTP_PROXY", "http://127.0.0.1:%d" % gw.server_address[1])
        monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "prefix:/fetch/")
        monkeypatch.setenv("SYSHTTP_PROXY_AUTH", BEARER)
        with urllib.request.urlopen(target + "/x", timeout=5) as resp:
            assert resp.read() == b"via-gateway" and resp.url == target + "/x"
        assert _Gateway.seen[-1] == ("/fetch/" + target + "/x", BEARER)
    finally:
        gw.shutdown()
        gw.server_close()


# ---- httpx -------------------------------------------------------------------


def test_httpx_goes_through_the_configured_proxy(patched, configured, target):
    assert httpx.get(target + "/x", timeout=5).text == "via-proxy"
    assert _Proxy.seen[-1] == (target + "/x", BEARER)


def test_httpx_async_goes_through_the_configured_proxy(patched, configured, target):
    async def get():
        async with httpx.AsyncClient(timeout=5) as client:
            return (await client.get(target + "/x")).text

    assert asyncio.run(get()) == "via-proxy" and _Proxy.seen[-1] == (target + "/x", BEARER)


def test_httpx_keeps_the_callers_proxy(patched, proxy, target, monkeypatch, dead_port):
    _Proxy.expected = None
    monkeypatch.setenv("SYSHTTP_PROXY", "http://127.0.0.1:%d" % dead_port)
    with httpx.Client(proxy="http://" + proxy, timeout=5) as client:
        assert client.get(target + "/x").text == "via-proxy"
    assert _Proxy.seen[-1] == (target + "/x", None)


def test_httpx_gets_the_system_context(patched):
    with httpx.Client() as client:
        assert client._transport._transports._kwargs["verify"] is syshttp_tls.os_ssl_context()
    with httpx.Client(verify=False) as client:
        assert client._transport._transports._kwargs["verify"] is False


def test_httpx_reports_no_reachable_proxy(patched, monkeypatch, dead_port):
    _unreachable_system(monkeypatch, dead_port)
    with pytest.raises((httpx.ProxyError, httpx.ConnectError)):
        httpx.get("http://a.example/", timeout=5)


# ---- aiohttp -----------------------------------------------------------------


def _aiohttp_get(url, **kwargs):
    async def get():
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), **kwargs) as resp:
                return await resp.text()

    return asyncio.run(get())


def test_aiohttp_goes_through_the_configured_proxy(patched, configured, target):
    assert _aiohttp_get(target + "/x") == "via-proxy"
    assert _Proxy.seen[-1] == (target + "/x", BEARER)


def test_aiohttp_keeps_the_callers_proxy(patched, proxy, target, monkeypatch, dead_port):
    _Proxy.expected = None
    monkeypatch.setenv("SYSHTTP_PROXY", "http://127.0.0.1:%d" % dead_port)
    assert _aiohttp_get(target + "/x", proxy="http://" + proxy) == "via-proxy"
    assert _Proxy.seen[-1] == (target + "/x", None)


def test_aiohttp_gets_the_system_context(monkeypatch, target):
    seen = {}

    async def recorder(self, method, url, **kwargs):
        seen.update(kwargs)
        raise RuntimeError("recorded")

    monkeypatch.setattr(aiohttp.ClientSession, "_request", recorder)
    autopatch.patch(["aiohttp"])
    try:
        with pytest.raises(RuntimeError, match="recorded"):
            _aiohttp_get(target + "/x")
    finally:
        autopatch.unpatch()
    assert seen["ssl"] is syshttp_tls.os_ssl_context() and seen.get("proxy") is None


def test_aiohttp_reports_no_reachable_proxy(patched, monkeypatch, dead_port):
    _unreachable_system(monkeypatch, dead_port)
    with pytest.raises(aiohttp.ClientConnectionError, match="127.0.0.1:%d" % dead_port):
        _aiohttp_get("http://a.example/")


def test_aiohttp_does_not_follow_a_prefix_gateway(patched, monkeypatch, dead_port):
    """aiohttp is not offered URL-prefix gateways (not supported for now):
    the request is refused before anything is sent."""
    monkeypatch.setenv("SYSHTTP_PROXY", "http://127.0.0.1:%d" % dead_port)
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "prefix:/fetch/")
    with pytest.raises(proxylib.UnsupportedProxyError):
        _aiohttp_get("http://a.example/")


# ---- pip ---------------------------------------------------------------------


def test_pip_is_a_target_and_keeps_its_own_tls():
    pytest.importorskip("pip._vendor.requests")
    from pip._vendor.requests import adapters

    before = adapters.HTTPAdapter.cert_verify
    try:
        assert autopatch.patch(["pip"]) == ("pip",) and autopatch.patched() == ("pip",)
        assert adapters.HTTPAdapter.cert_verify is before, "pip verifies with its own context"
    finally:
        autopatch.unpatch()
    assert autopatch.enabled(env=HTTPEnv(environ={"SYSHTTP_IMPORTPATCH": "pip._vendor.requests"})) == {"pip"}

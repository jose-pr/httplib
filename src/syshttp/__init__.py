"""syshttp -- HTTP plumbing that follows the system, with an optional
``requests`` session on top.

Public surface (the package's AGENTS.md documents each name):
  env.HTTPEnv                          — where settings come from: <P>_<NAME>, the
                                         prefix from SYSHTTP_PREFIX (default SYSHTTP)
  proxy.proxy_map                      — the routing as a proxylib ProxyMap: <P>_PROXY with
                                         its credential, else the *_PROXY variables or the
                                         system's configuration, NO_PROXY first (-x / -U /
                                         --noproxy overrides included)
  proxy.configured_proxy / proxy_type  — <P>_PROXY as a proxylib Proxy; <P>_PROXY_TYPE
                                         (connect | prefix[:/endpoint])
  cookies.load_netscape / save_netscape / cookie_applies / set_cookie_specs
                                       — Netscape jars and curl's cookie rules
  tls.os_ssl_context / new_os_context  — the system's TLS client (sslcontext) as an SSLContext
  retry.TRANSIENT_STATUSES / retry_after — what counts as transient, Retry-After
  jar.FileCookieJar / FileTokenJar     — file-backed jars under <P>_HOME
  hooks                                — <P>_HOOKS_<KEY> URL hooks (a curl wrapper,
                                         an syshttp callable) matched on the caller's URL
  session.new_session                  — configured requests.Session
  fetch.request_text / request_json / request_with_reauth / *_auto helpers
  autopatch                            — SYSHTTP_IMPORTPATCH: requests, urllib, httpx, aiohttp,
                                         pip patched on import to route and verify the same way

``env``, ``proxy``, ``jar``, ``cookies``, ``tls``, ``retry`` and ``hooks``
need only syshttp's dependencies (proxylib, sslcontext);
``session``/``fetch`` import ``requests`` lazily (the
``session`` extra).
"""

from importlib.metadata import PackageNotFoundError, version
from typing import Any

from .env import HTTPEnv
from .exceptions import ConfigurationError, HookError, ResponseError, SysHTTPError

__all__ = [
    "ConfigurationError",
    "HTTPEnv",
    "HookError",
    "NoReachableProxyError",
    "ResponseError",
    "SysHTTPError",
    "configured_proxy",
    "proxy_map",
    "proxy_type",
]

# Read from syshttp.proxy when first asked for: importing syshttp must not
# import proxylib, whose own import of urllib.request runs syshttp's
# import-time patch (syshttp.autopatch) while proxylib is half built.
_FROM_PROXY = ("NoReachableProxyError", "configured_proxy", "proxy_map", "proxy_type")


def __getattr__(name: str) -> Any:
    if name in _FROM_PROXY:
        from . import proxy

        return getattr(proxy, name)
    raise AttributeError("module %r has no attribute %r" % (__name__, name))


try:
    __version__ = version("syshttp")
except PackageNotFoundError:  # a source tree on sys.path, not installed
    __version__ = "0+unknown"

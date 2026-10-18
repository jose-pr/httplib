"""httplib -- HTTP plumbing over the standard library, with an optional
``requests`` session on top.

Public surface (the package's AGENTS.md documents each name):
  env.HTTPEnv                          — where settings come from: <P>_<NAME>, the
                                         prefix from HTTPLIB_PREFIX (default HTTPLIB)
  proxy.proxy_url / proxies_from_env   — the proxy from <P>_PROXY, else HTTPS_PROXY & co.
  proxy.resolve                        — (clean proxy URL, Proxy-Authorization value):
                                         <P>_PROXY_AUTH / HTTP_PROXY_AUTH verbatim,
                                         else Basic from the URL's userinfo
  proxy.proxy_type / prefix_url        — <P>_PROXY_TYPE (connect | prefix[:/endpoint]);
                                         the <proxy><endpoint><url> a prefix gateway gets
  proxy.redact / should_bypass         — a printable URL, the NO_PROXY decision
  proxy.plan / ProxyPlan               — the whole proxy decision (-x / -U / --noproxy
                                         overrides included) the session and curl share
  cookies.load_netscape / save_netscape / cookie_applies / set_cookie_specs
                                       — Netscape jars and curl's cookie rules
  tls.os_ssl_context / new_os_context  — the OS trust store as an SSLContext
  retry.TRANSIENT_STATUSES / retry_after — what counts as transient, Retry-After
  jar.FileCookieJar / FileTokenJar     — file-backed jars under <P>_HOME
  hooks                                — <P>_HOOKS_<KEY> URL hooks (a curl wrapper,
                                         an httplib callable) matched on the caller's URL
  session.new_session                  — configured requests.Session
  fetch.request_text / request_json / request_with_reauth / *_auto helpers

``env``, ``proxy``, ``jar``, ``cookies``, ``tls``, ``retry`` and ``hooks``
are dependency-free; ``session``/``fetch`` import ``requests`` lazily (the
``session`` extra).
"""

from importlib.metadata import PackageNotFoundError, version

from .env import HTTPEnv
from .proxy import (
    prefix_url,
    proxies_from_env,
    proxy_authorization,
    proxy_type,
    proxy_url,
    redact,
    resolve,
    should_bypass,
)

__all__ = [
    "HTTPEnv",
    "prefix_url",
    "proxies_from_env",
    "proxy_authorization",
    "proxy_type",
    "proxy_url",
    "redact",
    "resolve",
    "should_bypass",
]

try:
    __version__ = version("httplib")
except PackageNotFoundError:  # a source tree on sys.path, not installed
    __version__ = "0+unknown"

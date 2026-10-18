"""httplib — a small session toolkit over the optional ``requests`` dependency.

Public surface (see the package's AGENTS.md):
  proxy.proxy_url / proxies_from_env  — agent proxy from AGENTS_PROXY
  proxy.resolve                        — (clean proxy URL, Proxy-Authorization value):
                                         AGENTS_PROXY_AUTH / HTTP_PROXY_AUTH verbatim,
                                         else Basic from the URL's userinfo
  proxy.proxy_type / prefix_url        — AGENTS_PROXY_TYPE (connect | prefix[:/endpoint]);
                                         the <proxy><endpoint><url> a prefix gateway gets
  proxy.redact / should_bypass         — a printable URL, the NO_PROXY decision
  proxy.plan / ProxyPlan               — the whole proxy decision (-x / -U / --noproxy
                                         overrides included) the session and cli share
  cookies.load_netscape / save_netscape / cookie_applies / set_cookie_specs
                                       — Netscape jars and curl's cookie rules
  tls.os_ssl_context / new_os_context  — the OS trust store as an SSLContext
  retry.TRANSIENT_STATUSES / retry_after — what counts as transient, Retry-After
  jar.FileCookieJar / FileTokenJar     — file-backed jars under the dotagents store
  hooks                                — NET_HOOKS_<KEY> URL hooks (a curl wrapper,
                                         an httplib callable) matched on the caller's URL
  session.new_session                  — configured requests.Session
  fetch.request_text / request_json / request_with_reauth / *_auto helpers

``proxy``, ``jar``, ``cookies``, ``tls``, ``retry`` and ``hooks`` are
dependency-free; ``session``/``fetch`` import ``requests`` lazily (the
``session`` extra).
"""
from .proxy import (  # noqa: F401
    prefix_url, proxies_from_env, proxy_authorization, proxy_type, proxy_url, redact, resolve, should_bypass,
)

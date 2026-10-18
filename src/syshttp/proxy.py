"""Proxy resolution: which proxy, with which credentials, for which hosts.

Settings are read through an :class:`~syshttp.env.HTTPEnv` (``env=``, default
``HTTPEnv()``); below, ``<P>`` is its prefix, ``SYSHTTP`` unless
``SYSHTTP_PREFIX`` or the ``HTTPEnv`` says otherwise.

The proxy source is **``<P>_PROXY``** -- a proxy for this package's traffic,
distinct from the machine's global proxy so other tools (git, npm, corporate
CLIs) are not forced through it. If it is unset, fall back to the
environment's convention: ``HTTPS_PROXY`` -> ``HTTP_PROXY`` -> ``ALL_PROXY``
(either case). If none is set, the **system's proxy configuration** for the
URL being requested (:func:`system_proxy`, through proxylib: WinHTTP on
Windows, CFNetwork on macOS, libproxy or the desktop's settings elsewhere --
manual proxies, PAC scripts and WPAD alike). ``<P>_SYSTEM_PROXY=0`` turns that
last source off. A system proxy is always spoken to as ``connect``.

**Credentials.** An authenticating proxy is the normal case behind a corporate
gateway, and a proxy that is configured but not authenticated to is worse than
none: every request dies with 407. The credential is the value of the
``Proxy-Authorization`` header, sent verbatim, so any scheme works (``Basic``,
``Bearer``, ``Negotiate`` tokens, ...). Sources, first one wins:

1. **``<P>_PROXY_AUTH``** -- the configured proxy's header value;
2. **``HTTP_PROXY_AUTH``** -- the same for the machine's proxy;
3. userinfo in the proxy URL (``http://user:pass@host:port``), turned into
   ``Basic`` -- the form curl, ``requests`` and ``urllib`` also read natively.

Example: ``SYSHTTP_PROXY_AUTH="Basic $(printf 'user:pass' | base64)"``.

When a header value is configured the proxy URL is used **without** its userinfo
(:func:`resolve`), so no HTTP stack adds a second, competing header. Anything
that prints a proxy URL goes through :func:`redact`.

**Kind.** ``<P>_PROXY_TYPE`` says how the proxy is spoken to:

* ``connect`` (default) -- a standard HTTP proxy: plain-http requests are sent to
  it with an absolute URL, https goes through a ``CONNECT`` tunnel;
* ``prefix[:/endpoint]`` -- a URL-prefix gateway: the request is made **directly**
  to ``<proxy><endpoint><url>`` (``endpoint`` defaults to ``/``), e.g.
  ``SYSHTTP_PROXY=https://gw.example SYSHTTP_PROXY_TYPE=prefix:/fetch/`` turns
  ``GET https://api.example.com/x`` into
  ``GET https://gw.example/fetch/https://api.example.com/x``. The
  ``Proxy-Authorization`` value is sent as a header of that request.

**Bypass.** ``NO_PROXY`` / ``no_proxy`` (comma-separated ``host[:port]`` suffixes,
or ``*``) is honoured the same way curl and ``requests`` read it, so a loopback
test server or an internal host is not sent to the proxy: :func:`should_bypass`.
"""

from __future__ import annotations

import base64
import logging
import threading
import time
from typing import Any, Optional, Tuple
from urllib.parse import unquote, urlsplit, urlunsplit

# The stdlib's own NO_PROXY matcher (what urllib and requests use); absent
# from typeshed.
from urllib.request import proxy_bypass_environment  # type: ignore[attr-defined]

from .env import HTTPEnv

#: The settings this module reads, as ``<P>_<NAME>``.
PROXY = "PROXY"
PROXY_AUTH = "PROXY_AUTH"
#: The header the credential rides in; default the standard one. A gateway
#: that wants it under another name (``X-Proxy-Token``) sets this.
PROXY_AUTH_HEADER = "PROXY_AUTH_HEADER"
#: How the proxy is spoken to: ``connect`` (default) or ``prefix[:/endpoint]``.
PROXY_TYPE = "PROXY_TYPE"
DEFAULT_AUTH_HEADER = "Proxy-Authorization"

#: Whether the system's proxy configuration is the last source, as a boolean
#: ``<P>_SYSTEM_PROXY`` (``1``/``true``/``yes``/``on`` or their opposites;
#: unset or empty: on).
SYSTEM_PROXY = "SYSTEM_PROXY"
#: How long the system's proxy configuration is reused (seconds) before it is
#: read again, and how long one URL's answer is kept.
SYSTEM_PROXY_MAX_AGE = 60

_log = logging.getLogger(__name__)
_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")
_system_lock = threading.Lock()
_system_map: Any = None
_system_map_at = 0.0

#: The machine proxy's header value, read under any prefix.
MACHINE_AUTH_VAR = "HTTP_PROXY_AUTH"
# Fallback order after <P>_PROXY, both cases (curl reads lowercase per httpoxy).
_FALLBACK_VARS = (
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
)


def _env(env: Optional[HTTPEnv]) -> HTTPEnv:
    return HTTPEnv() if env is None else env


def _var(env: HTTPEnv, setting: str) -> str:
    """The variable to name in a message about ``setting``."""
    return env.name(setting) or setting


def _normalize(url: str) -> str:
    """curl accepts a bare ``host:port``; the HTTP stacks need a scheme."""
    return url if "://" in url else "http://" + url


def system_proxy_enabled(*, env: Optional[HTTPEnv] = None) -> bool:
    """``<P>_SYSTEM_PROXY`` as a boolean, default on. Any other value than
    ``1``/``true``/``yes``/``on`` or ``0``/``false``/``no``/``off`` (any case)
    is a ``ValueError`` naming the variable."""
    env = _env(env)
    raw = env.get(SYSTEM_PROXY)
    if raw is None:
        return True
    if raw.lower() in _TRUE:
        return True
    if raw.lower() in _FALSE:
        return False
    raise ValueError("%s must be one of %s, not %r" % (_var(env, SYSTEM_PROXY), "/".join(_TRUE + _FALSE), raw))


def system_proxy_map() -> Any:
    """The system's proxy configuration as a proxylib ``ProxyMap``, read once
    and reused for :data:`SYSTEM_PROXY_MAX_AGE` seconds -- or ``None`` when it
    cannot be read (logged at DEBUG; a broken configuration is no proxy, never
    a failed request). The OS's own engine answers (``proxylib.system_proxy(
    "system")``), so a PAC script or WPAD is evaluated the way the system's
    own clients evaluate it."""
    global _system_map, _system_map_at
    with _system_lock:
        now = time.monotonic()
        if _system_map_at and now - _system_map_at <= SYSTEM_PROXY_MAX_AGE:
            return _system_map
        try:
            import proxylib

            found = proxylib.system_proxy("system")
            # A PAC URL still to be loaded (a JS engine evaluates it: the pac extra).
            source: Any = proxylib.load_pac(found) if isinstance(found, str) else found
            _system_map = proxylib.ConfigurableProxyMap(source, cache_ttl=SYSTEM_PROXY_MAX_AGE)
        except Exception as exc:
            _log.debug("the system proxy configuration could not be read: %s", exc)
            _system_map = None
        _system_map_at = now
        return _system_map


def system_proxy(url: str, *, env: Optional[HTTPEnv] = None) -> Optional[str]:
    """The proxy the system's configuration names for ``url`` (its first
    choice), or ``None`` for DIRECT, for no opinion, when it cannot be read,
    or when ``<P>_SYSTEM_PROXY`` turns it off. A PAC answer's later
    fallbacks (``PROXY a; PROXY b; DIRECT``) are not tried."""
    if not system_proxy_enabled(env=env):
        return None
    mapping = system_proxy_map()
    if mapping is None:
        return None
    try:
        first = next(iter(mapping[url]), None)
    except KeyError:
        return None
    except Exception as exc:
        _log.debug("the system proxy configuration failed for a URL: %s", exc)
        return None
    return first.url if first is not None else None


def configured_proxy_url(*, env: Optional[HTTPEnv] = None) -> Optional[str]:
    """The proxy the environment names: ``<P>_PROXY``, else the first set of
    ``HTTPS_PROXY``/``HTTP_PROXY``/``ALL_PROXY`` (either case); ``None``
    without one. The system's configuration is not consulted."""
    env = _env(env)
    value = env.get(PROXY) or env.conventional(*_FALLBACK_VARS)
    return _normalize(value) if value else None


def proxy_url(*, url: Optional[str] = None, env: Optional[HTTPEnv] = None) -> Optional[str]:
    """The proxy URL to use (userinfo included if the source put it there),
    or ``None`` for direct.

    :func:`configured_proxy_url` wins; otherwise, given the ``url`` being
    requested, :func:`system_proxy` for it. Without ``url`` the system's
    configuration is not consulted: its answer depends on the URL."""
    configured = configured_proxy_url(env=env)
    if configured or not url:
        return configured
    found = system_proxy(url, env=env)
    return _normalize(found) if found else None


def basic_authorization(user: str, password: str) -> str:
    """The ``Proxy-Authorization`` value for Basic credentials."""
    token = base64.b64encode(("%s:%s" % (user, password)).encode("utf-8")).decode("ascii")
    return "Basic " + token


def userinfo(url: Optional[str]) -> Optional[Tuple[str, str]]:
    """``(user, password)`` from the URL's userinfo, percent-decoded, or ``None``."""
    if not url:
        return None
    parts = urlsplit(_normalize(url))
    if parts.username is None:
        return None
    return unquote(parts.username), unquote(parts.password or "")


def auth_header(*, env: Optional[HTTPEnv] = None) -> str:
    """The name of the header the proxy credential is sent in:
    ``<P>_PROXY_AUTH_HEADER``, else ``Proxy-Authorization``. A value with
    a colon or whitespace is not a header name: a ``ValueError``."""
    env = _env(env)
    name = env.get(PROXY_AUTH_HEADER)
    if not name:
        return DEFAULT_AUTH_HEADER
    if ":" in name or any(ch.isspace() for ch in name):
        raise ValueError("%s must be a header name, not %r" % (_var(env, PROXY_AUTH_HEADER), name))
    return name


def configured_authorization(*, env: Optional[HTTPEnv] = None) -> Optional[str]:
    """The header value from ``<P>_PROXY_AUTH`` / ``HTTP_PROXY_AUTH``, or ``None``."""
    env = _env(env)
    return env.get(PROXY_AUTH) or env.conventional(MACHINE_AUTH_VAR)


def proxy_authorization(
    url: Optional[str] = None,
    *,
    configured: bool = True,
    env: Optional[HTTPEnv] = None,
    target: Optional[str] = None,
) -> Optional[str]:
    """The ``Proxy-Authorization`` value to send to the proxy, or ``None``.

    A configured header value (``<P>_PROXY_AUTH`` then ``HTTP_PROXY_AUTH``)
    wins; otherwise the URL's userinfo as ``Basic``. ``url`` defaults to the
    proxy :func:`proxy_url` picks for ``target``. ``configured=False`` ignores
    the variables -- for a proxy the caller named explicitly (curl's ``-x``),
    whose credentials are its own userinfo, never the configured proxy's."""
    if configured:
        value = configured_authorization(env=env)
        if value:
            return value
    creds = userinfo(url if url is not None else proxy_url(url=target, env=env))
    if creds:
        return basic_authorization(*creds)
    return None


def strip_auth(url: str) -> str:
    """``url`` without any userinfo: the authority is what follows the last
    ``@`` of the netloc, verbatim (IPv6 brackets, odd ports and case intact)."""
    parts = urlsplit(_normalize(url))
    return urlunsplit(parts._replace(netloc=parts.netloc.rpartition("@")[2]))


def redact(url: Optional[str]) -> Optional[str]:
    """``url`` safe to print: the password, if any, replaced by ``***``."""
    if not url:
        return url
    parts = urlsplit(_normalize(url))
    if parts.password is None:
        return url
    authority = parts.netloc.rpartition("@")[2]
    return urlunsplit(parts._replace(netloc="%s:***@%s" % (parts.username or "", authority)))


def resolve(
    url: Optional[str] = None,
    *,
    configured: bool = True,
    env: Optional[HTTPEnv] = None,
    target: Optional[str] = None,
) -> Optional[Tuple[str, Optional[str]]]:
    """``(proxy_url_without_userinfo, authorization)`` -- what an HTTP stack
    should connect to and the ``Proxy-Authorization`` value to send it (``None``
    when the proxy needs none) -- or ``None`` when no proxy is configured.
    ``url``/``configured`` as in :func:`proxy_authorization`; without ``url``
    the proxy is :func:`proxy_url` for ``target``, the URL being requested."""
    url = url if url is not None else proxy_url(url=target, env=env)
    if not url:
        return None
    return strip_auth(url), proxy_authorization(url, configured=configured, env=env)


def proxy_type(*, env: Optional[HTTPEnv] = None) -> Tuple[str, Optional[str]]:
    """``("connect", None)`` for a standard proxy, or ``("prefix", "/endpoint")``
    for a URL-prefix gateway (endpoint defaults to ``/``), from
    ``<P>_PROXY_TYPE``. Anything else is a configuration error, raised."""
    env = _env(env)
    raw = env.get(PROXY_TYPE)
    if not raw:
        return "connect", None
    kind, _, endpoint = raw.partition(":")
    kind = kind.strip().lower()
    if kind == "connect":
        return "connect", None
    if kind != "prefix":
        raise ValueError("%s must be 'connect' or 'prefix[:/endpoint]', not %r" % (_var(env, PROXY_TYPE), raw))
    endpoint = endpoint.strip() or "/"
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint
    return "prefix", endpoint


def prefix_url(
    target: str, proxy: Optional[str] = None, endpoint: Optional[str] = None, *, env: Optional[HTTPEnv] = None
) -> str:
    """``<proxy><endpoint><target>``: the URL to request from a prefix gateway.
    ``proxy`` (userinfo dropped) and ``endpoint`` default to the configured ones;
    the target is appended as-is, so the gateway sees the URL the caller wrote."""
    proxy = strip_auth(proxy if proxy is not None else (proxy_url(env=env) or ""))
    if endpoint is None:
        endpoint = proxy_type(env=env)[1] or "/"
    return proxy.rstrip("/") + endpoint + target


def bypassed_by(host: str, no_proxy: Optional[str]) -> bool:
    """Does ``no_proxy`` (curl's comma list: ``host[:port]`` suffixes, or ``*``)
    say ``host`` goes direct? ``host`` may include a port."""
    if not no_proxy:
        return False
    return bool(proxy_bypass_environment(host, {"no": no_proxy}))


def no_proxy_from_env(*, env: Optional[HTTPEnv] = None) -> Optional[str]:
    """The ``NO_PROXY`` / ``no_proxy`` list (either case), or ``None``."""
    return _env(env).conventional("NO_PROXY", "no_proxy")


_ENV = object()  # sentinel: "read NO_PROXY from the environment"


def should_bypass(host_or_url: str, no_proxy=_ENV, *, env: Optional[HTTPEnv] = None) -> bool:
    """Does the bypass list say this host goes direct? ``no_proxy`` defaults
    to the environment's ``NO_PROXY``/``no_proxy``; pass a list of your own
    (curl's ``--noproxy`` REPLACES the environment's) or ``None`` for "never
    bypass". Accepts a URL or a bare ``host[:port]``. A URL that does not
    parse (``http://h:notaport/``) is not bypassed -- the HTTP stack reports
    it on its own terms."""
    if no_proxy is _ENV:
        no_proxy = no_proxy_from_env(env=env)
    if not no_proxy:
        return False
    if "://" in host_or_url:
        parts = urlsplit(host_or_url)
        host = parts.hostname or ""
        try:
            if parts.port is not None:
                host = "%s:%d" % (host, parts.port)
        except ValueError:
            return False
    else:
        host = host_or_url
    return bypassed_by(host, no_proxy)


def proxies_from_env(*, env: Optional[HTTPEnv] = None) -> Optional[dict]:
    """A ``requests``-style ``{"http": ..., "https": ...}`` dict of the configured
    proxy URL (userinfo as configured), or ``None``. Note that a header value
    from ``<P>_PROXY_AUTH`` cannot ride in a URL: :func:`session.new_session`
    is what applies it; see :func:`resolve` for the two halves."""
    p = proxy_url(env=env)
    if not p:
        return None
    return {"http": p, "https": p}


class ProxyPlan:
    """One proxy decision -- the session's adapter and a curl front end's
    handler both apply it per hop.

    ``proxy`` -- the proxy URL without userinfo; ``authorization`` -- the
    credential (the header value), or ``None``; ``auth_header`` -- the header
    it rides in (:func:`auth_header`); ``endpoint`` -- ``None`` for a
    ``connect`` proxy, the ``/endpoint`` of a prefix gateway; ``no_proxy`` --
    the bypass list in force (curl's ``--noproxy`` REPLACES ``NO_PROXY``),
    re-checked for every hop's host.
    """

    __slots__ = ("proxy", "authorization", "endpoint", "no_proxy", "auth_header")

    def __init__(
        self,
        proxy: str,
        authorization: Optional[str],
        endpoint: Optional[str],
        no_proxy: Optional[str],
        auth_header: Optional[str] = None,
    ) -> None:
        self.proxy = proxy
        self.authorization = authorization
        self.endpoint = endpoint
        self.no_proxy = no_proxy
        self.auth_header = auth_header or DEFAULT_AUTH_HEADER

    def bypasses(self, url: str) -> bool:
        return should_bypass(url, no_proxy=self.no_proxy)

    @property
    def gateway_base(self) -> Optional[str]:
        """``<proxy><endpoint>`` of a prefix gateway (a URL already in its
        namespace starts with it), or ``None`` for a ``connect`` proxy."""
        return prefix_url("", self.proxy, self.endpoint) if self.endpoint is not None else None


def plan(
    proxy: Optional[str] = None,
    noproxy: Optional[str] = None,
    proxy_user: Optional[str] = None,
    *,
    url: Optional[str] = None,
    env: Optional[HTTPEnv] = None,
) -> Optional[ProxyPlan]:
    """The :class:`ProxyPlan` for a request to ``url``, or ``None`` for direct.

    ``proxy`` (curl's ``-x``) wins over the configured chain (``<P>_PROXY``,
    then the global vars, then -- for ``url``, outside the bypass list -- the
    system's configuration) and is always a plain ``connect`` proxy whose
    credential is its own userinfo or ``proxy_user`` (``-U``, as Basic) --
    never the configured proxy's ``<P>_PROXY_AUTH``. For the configured
    proxy, ``proxy_user`` wins over the configured header value, which wins
    over the URL's userinfo. ``noproxy`` replaces ``NO_PROXY``. A malformed
    ``<P>_PROXY`` or ``<P>_PROXY_TYPE`` raises ``ValueError`` (a
    configuration error, only when that proxy would actually be used).
    """
    no_proxy = noproxy if noproxy is not None else no_proxy_from_env(env=env)
    endpoint: Optional[str] = None
    if proxy:
        resolved = resolve(proxy, configured=False, env=env)
    elif configured_proxy_url(env=env):
        resolved = resolve(env=env)
        endpoint = proxy_type(env=env)[1]
    elif url and not should_bypass(url, no_proxy):
        resolved = resolve(target=url, env=env)  # the system's choice: connect
    else:
        resolved = None
    if not resolved:
        return None
    url, authorization = resolved
    if proxy_user:
        user, _, password = proxy_user.partition(":")
        authorization = basic_authorization(user, password)
    return ProxyPlan(url, authorization, endpoint, no_proxy, auth_header(env=env))

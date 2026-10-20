"""Proxy routing: syshttp's settings as one proxylib proxy map.

Settings are read through an :class:`~syshttp.env.HTTPEnv` (``env=``, default
``HTTPEnv()``), each name under each of its prefixes (``SYSHTTP_PREFIX``);
below they are named as written, under the empty prefix.

:func:`proxy_map` is a proxylib ``ProxyMap`` that reads the settings at every
lookup and answers, in order:

1. **``SYSHTTP_PROXY``** -- a proxy for this package's traffic, distinct from
   the machine's so other tools (git, npm, corporate CLIs) are not forced
   through it. Its credential is ``SYSHTTP_PROXY_AUTH`` (a header value sent
   verbatim, in ``SYSHTTP_PROXY_AUTH_HEADER``, default
   ``Proxy-Authorization``), else the URL's userinfo as Basic.
   ``SYSHTTP_PROXY_TYPE=prefix[:/endpoint]`` makes it a
   URL-prefix gateway: ``GET https://api.example.com/x`` becomes
   ``GET <proxy><endpoint>https://api.example.com/x``.
2. **The machine's proxy**: the ``*_PROXY`` variables when any is set (per
   scheme, as proxylib's ``EnvProxyConfig`` reads them, the lowercase
   spelling first under each prefix), else the system's configuration for
   the URL (WinHTTP on Windows, CFNetwork on macOS, libproxy or the desktop's
   settings elsewhere; PAC scripts and WPAD included), unless
   ``SYSHTTP_SYSTEM_PROXY`` is off. ``HTTP_PROXY_AUTH`` is its credential
   (``Proxy-Authorization``).
3. **DIRECT.**

``NO_PROXY`` / ``no_proxy`` hosts go direct before any of it (proxylib's
``BypassRules``: suffixes, CIDR, ports, loopback). An answer is a list
(``PROXY a; PROXY b; DIRECT``): proxylib's client integrations try it in
order and raise the last error when no entry connects; a client that sends
through one proxy only (urllib, a curl command line) takes it through
``proxylib.Probed``, which raises :class:`NoReachableProxyError`.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, Optional, Tuple

import proxylib
from proxylib import NoReachableProxyError, Proxy

from .env import HTTPEnv
from .exceptions import ConfigurationError

__all__ = (
    "DEFAULT_AUTH_HEADER",
    "MACHINE_AUTH_VAR",
    "NoReachableProxyError",
    "PROXY",
    "PROXY_AUTH",
    "PROXY_AUTH_HEADER",
    "PROXY_TYPE",
    "SYSTEM_PROXY",
    "SYSTEM_PROXY_MAX_AGE",
    "auth_header",
    "configured_proxy",
    "proxy_map",
    "proxy_type",
    "system_map",
    "system_proxy_enabled",
)

#: The settings this module reads, each under every prefix.
PROXY = "SYSHTTP_PROXY"
PROXY_AUTH = "SYSHTTP_PROXY_AUTH"
#: The header the credential rides in; default the standard one. A gateway
#: that wants it under another name (``X-Proxy-Token``) sets this.
PROXY_AUTH_HEADER = "SYSHTTP_PROXY_AUTH_HEADER"
#: How the proxy is spoken to: ``connect`` (default) or ``prefix[:/endpoint]``.
PROXY_TYPE = "SYSHTTP_PROXY_TYPE"
DEFAULT_AUTH_HEADER = "Proxy-Authorization"
#: Whether the system's proxy configuration is consulted, as a boolean
#: (``1``/``true``/``yes``/``on`` or their opposites; unset or empty: on).
SYSTEM_PROXY = "SYSHTTP_SYSTEM_PROXY"
#: The machine proxy's header value.
MACHINE_AUTH_VAR = "HTTP_PROXY_AUTH"
#: How long (seconds) the system's configuration, and its answer for one URL,
#: are reused before they are read again.
SYSTEM_PROXY_MAX_AGE = 60

_log = logging.getLogger(__name__)
_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")
_system_lock = threading.Lock()
_system: Any = None
_system_at = 0.0


def _env(env: Optional[HTTPEnv]) -> HTTPEnv:
    return HTTPEnv() if env is None else env


def _var(env: HTTPEnv, setting: str) -> str:
    """The variable to name in a message about ``setting``: the one set, else
    the name under the first prefix."""
    found = env.find(setting)
    return found[0] if found else env.name(setting)


def system_proxy_enabled(*, env: Optional[HTTPEnv] = None) -> bool:
    """``SYSHTTP_SYSTEM_PROXY`` as a boolean, default on. Any other value than
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
    raise ConfigurationError("%s must be one of %s, not %r" % (_var(env, SYSTEM_PROXY), "/".join(_TRUE + _FALSE), raw))


def auth_header(*, env: Optional[HTTPEnv] = None) -> str:
    """The name of the header ``SYSHTTP_PROXY_AUTH`` is sent in:
    ``SYSHTTP_PROXY_AUTH_HEADER``, else ``Proxy-Authorization``. A value with
    a colon or whitespace is not a header name: a ``ValueError``."""
    env = _env(env)
    name = env.get(PROXY_AUTH_HEADER)
    if not name:
        return DEFAULT_AUTH_HEADER
    if ":" in name or any(ch.isspace() for ch in name):
        raise ConfigurationError("%s must be a header name, not %r" % (_var(env, PROXY_AUTH_HEADER), name))
    return name


def proxy_type(*, env: Optional[HTTPEnv] = None) -> Tuple[str, Optional[str]]:
    """``("connect", None)`` for a standard proxy, or ``("prefix", "/endpoint")``
    for a URL-prefix gateway (endpoint defaults to ``/``), from
    ``SYSHTTP_PROXY_TYPE``. Anything else is a configuration error, raised."""
    env = _env(env)
    raw = env.get(PROXY_TYPE)
    if not raw:
        return "connect", None
    kind, _, endpoint = raw.partition(":")
    kind = kind.strip().lower()
    if kind == "connect":
        return "connect", None
    if kind != "prefix":
        raise ConfigurationError("%s must be 'connect' or 'prefix[:/endpoint]', not %r" % (_var(env, PROXY_TYPE), raw))
    endpoint = endpoint.strip() or "/"
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint
    return "prefix", endpoint


def _checked(variable: str, value: str) -> str:
    """``value``, the credential read from ``variable``, unless it holds a CR,
    LF or NUL, which would end the header. The message names the variable,
    never the value (a secret)."""
    if any(ch in value for ch in "\r\n\0"):
        raise ConfigurationError("%s must not contain a carriage return, line feed or NUL character" % variable)
    return value


def _with_credential(proxy: Proxy, header: str, value: str) -> Proxy:
    """``proxy`` sending ``value`` in ``header`` instead of its userinfo."""
    headers = proxy.headers
    headers[header] = value
    return Proxy(proxy.scheme, proxy.host, proxy.port, path=proxy.path, headers=headers)


def _with_user(proxy: Proxy, user: str) -> Proxy:
    """``proxy`` with curl's ``-U user:password`` as its only credential."""
    name, _, password = user.partition(":")
    return Proxy(proxy.scheme, proxy.host, proxy.port, name, password, path=proxy.path)


def configured_proxy(*, env: Optional[HTTPEnv] = None) -> Optional[Proxy]:
    """``SYSHTTP_PROXY`` as a proxylib ``Proxy`` with its credential and kind,
    or ``None`` when it is unset. ``SYSHTTP_PROXY_AUTH`` replaces the URL's
    userinfo; ``SYSHTTP_PROXY_TYPE=prefix`` makes a gateway. A malformed value
    raises ``ValueError`` (``ProxyParseError`` for the URL)."""
    env = _env(env)
    raw = env.get(PROXY)
    if not raw:
        return None
    found = Proxy.parse(raw)
    kind, endpoint = proxy_type(env=env)
    if kind == "prefix":
        if found.scheme not in ("http", "https"):
            raise ConfigurationError("%s=prefix needs an http or https %s" % (_var(env, PROXY_TYPE), _var(env, PROXY)))
        found = Proxy("prefix+" + found.scheme, found.host, found.port, found.username, found.password, path=endpoint)
    value = env.get(PROXY_AUTH)
    if not value:
        return found
    return _with_credential(found, auth_header(env=env), _checked(_var(env, PROXY_AUTH), value))


#: The conventional proxy variables, lower-cased.
_PROXY_VARIABLES = tuple(s + "_proxy" for s in ("http", "https", "ftp", "ws", "wss", "all"))


def _proxy_environ(env: HTTPEnv) -> Dict[str, str]:
    """The conventional proxy variables as ``EnvProxyConfig`` reads them,
    each found through ``env``'s prefixes (lowercase spelling first)."""
    found = {}
    for name in _PROXY_VARIABLES:
        value = env.get(name, name.upper())
        if value:
            found[name] = value
    return found


class _Quiet:
    """The system's map with its failures as "no opinion": a configuration
    that cannot be read or run is DIRECT, never a failed request."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner

    def __getitem__(self, url: str) -> Any:
        try:
            return proxylib.lookup(self.inner, url)
        except KeyError:
            raise
        except Exception as exc:
            _log.debug("the system proxy configuration failed for a URL: %s", exc)
            raise KeyError(url) from None

    def close(self) -> None:
        close = getattr(self.inner, "close", None)
        if close is not None:
            close()


def system_map() -> Any:
    """The system's proxy configuration as a proxylib ``ProxyMap``
    (``proxylib.auto_proxy`` with no environment variables: the OS resolver,
    then the OS settings), read once per :data:`SYSTEM_PROXY_MAX_AGE` seconds,
    each URL's answer kept as long. ``None`` when it cannot be read (logged at
    DEBUG). A URL it cannot answer raises ``KeyError``."""
    global _system, _system_at
    with _system_lock:
        now = time.monotonic()
        if _system_at and now - _system_at <= SYSTEM_PROXY_MAX_AGE:
            return _system
        try:
            _system = proxylib.Cached(_Quiet(proxylib.auto_proxy(environ={})), ttl=SYSTEM_PROXY_MAX_AGE)
        except Exception as exc:
            _log.debug("the system proxy configuration could not be read: %s", exc)
            _system = None
        _system_at = now
        return _system


class _Credential:
    """Every proxy ``inner`` answers, given ``Proxy-Authorization: value``
    (SOCKS entries, which take no header, and DIRECT as they are)."""

    def __init__(self, inner: Any, value: str) -> None:
        self.inner = inner
        self.value = value

    def __getitem__(self, url: str) -> Tuple[Optional[Proxy], ...]:
        return tuple(
            (
                entry
                if entry is None or entry.scheme.startswith("socks")
                else _with_credential(entry, DEFAULT_AUTH_HEADER, self.value)
            )
            for entry in proxylib.lookup(self.inner, url)
        )


class _SettingsMap:
    """:func:`proxy_map`'s map: the settings read again at every lookup."""

    def __init__(self, proxy: Optional[str], noproxy: Optional[str], proxy_user: Optional[str], env: Any) -> None:
        self.proxy = proxy
        self.noproxy = noproxy
        self.proxy_user = proxy_user
        self.env = env

    def __repr__(self) -> str:
        return "proxy_map(%s)" % ("proxy=%r" % Proxy.parse(self.proxy).url if self.proxy else "")

    def _inner(self, env: HTTPEnv) -> Any:
        if self.proxy is not None:
            # curl's -x: always a plain proxy, its credential its own.
            return proxylib.SimpleProxyMap(Proxy.parse(self.proxy) if self.proxy else None)
        configured = configured_proxy(env=env)
        if configured is not None:
            return proxylib.SimpleProxyMap(configured)
        environ = _proxy_environ(env)
        machine: Any = None
        if environ or not system_proxy_enabled(env=env):
            # Its variables alone decide, as urllib.request.getproxies() has it;
            # --noproxy replaces NO_PROXY in the variables' own map too.
            no_proxy = env.get("no_proxy", "NO_PROXY")
            if no_proxy:
                environ["no_proxy"] = no_proxy
            machine = proxylib.EnvProxyConfig(environ, no_proxy=self.noproxy)
        else:
            machine = system_map()
        chain = proxylib.ChainProxyMap(*(m for m in (machine, proxylib.SimpleProxyMap()) if m is not None))
        found = env.find(MACHINE_AUTH_VAR)
        return _Credential(chain, _checked(*found)) if found else chain

    def _no_proxy(self, env: HTTPEnv) -> Optional[str]:
        return self.noproxy if self.noproxy is not None else env.get("no_proxy", "NO_PROXY")

    def __getitem__(self, url: str) -> Tuple[Optional[Proxy], ...]:
        env = _env(self.env)
        inner = self._inner(env)
        no_proxy = self._no_proxy(env)
        if no_proxy:
            inner = proxylib.Bypass(inner, no_proxy)
        answer = proxylib.lookup(inner, url)
        if self.proxy_user is not None:
            answer = tuple(None if entry is None else _with_user(entry, self.proxy_user) for entry in answer)
        return answer

    def close(self) -> None:
        """Nothing to free: the system's map is shared."""


def proxy_map(
    proxy: Optional[str] = None,
    noproxy: Optional[str] = None,
    proxy_user: Optional[str] = None,
    *,
    env: Optional[HTTPEnv] = None,
) -> Any:
    """syshttp's routing as a proxylib ``ProxyMap`` (``proxylib.lookup(m,
    url)`` reads it; every proxylib integration takes it). The settings are
    read at every lookup, so one map serves a long-lived client. It always
    answers (never ``KeyError``).

    ``proxy`` (curl's ``-x``) replaces the settings with that proxy, always a
    plain one whose credential is its own userinfo, never the configured
    ``SYSHTTP_PROXY_AUTH``; ``""`` means direct. ``noproxy`` (``--noproxy``)
    replaces ``NO_PROXY``. ``proxy_user`` (``-U user:password``) becomes the
    credential of whichever proxy answers, replacing the configured one. A
    malformed setting raises ``ValueError`` at lookup, only when it would be
    used."""
    return _SettingsMap(proxy, noproxy, proxy_user, env)

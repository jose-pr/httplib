"""Build a configured ``requests.Session`` with retry/backoff, routing by
:func:`proxy.proxy_map` (in ONE adapter, proxylib's ``ProxyMapAdapter`` with
the system's TLS), and transparent cookie/token load-save + per-host auth.

Cookies and tokens are always chosen by the host of the URL the caller asked
for -- the origin -- never by the proxy's or the gateway's: the jars are read
before the adapter sees the request, and a gateway's response keeps the
caller's request and URL. A token is a per-request
``Authorization`` header (``Bearer <value>``, or the value verbatim when it
already names a scheme), never a session header, so it cannot leak to another
host; an explicit header or ``auth=`` wins.

Jars, tokens, hooks and ``auth_provider`` apply to ``session.request`` (so to
``get``, ``post``, ...), not to a bare ``session.send()``, which gets the
adapter's routing and TLS only.

URL hooks (``SYSHTTP_HOOKS_<KEY>`` + ``_PY``, see :mod:`.hooks`) run in the
same place, on the caller's URL, before the request: a hook may log in, set
headers in the request's kwargs, or return a response of its own. A hook
that makes requests through the session does not trigger hooks again.

TLS is the system's: with ``verify=True`` the adapter hands urllib3
``tls.os_ssl_context()`` (sslcontext's system context: the OS verifies
servers, and a client certificate comes from the OS store when a server asks)
and no CA file, so no ``certifi`` bundle is involved. ``verify=<path>`` and the
``CA_BUNDLE`` setting name a bundle explicitly (requests' own
``REQUESTS_CA_BUNDLE`` / ``CURL_CA_BUNDLE`` are not read); ``verify=False`` is
left to requests. ``ssl_context=`` replaces all of that with a context of the caller's
own -- a client certificate (a keystore identity too), a cipher list, a
pinned protocol version -- used as given for every https origin;
``proxy_ssl_context=`` does the same for the TLS to an ``https://`` proxy.

``requests`` + ``urllib3`` are this toolkit's **optional dependency** (the
``session`` extra). ``new_session`` imports them lazily and raises a clear,
actionable error if they are absent; every other module works without them.
"""

from __future__ import annotations

import contextvars
import os
import re
import ssl
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterable, Optional, Tuple, Union
from urllib.parse import urlparse

from . import hooks as _hooks
from .auth import AuthProvider
from .cookies import (
    _spec_from_cookie,
    apply_to_session,
    domain_covers,
    host_aliases,
    host_only_policy,
    merge_set_cookie_headers,
)
from .env import HTTPEnv
from .exceptions import ConfigurationError
from .jar import CookieJar, FileCookieJar, FileTokenJar, TokenJar
from .retry import TRANSIENT_STATUSES
from .tls import OS_CONTEXT_MAX_AGE, new_os_context, os_ssl_context  # noqa: F401  (re-exported: session's own API)
from . import proxy as _proxy

if TYPE_CHECKING:  # requests is optional at runtime: types only
    import requests

__all__ = ("CA_BUNDLE", "COOKIE_HOSTS", "new_session")

#: The settings this module reads, each under every prefix: hosts that share
#: cookies, and the CA bundle ``verify=True`` uses.
COOKIE_HOSTS = "SYSHTTP_COOKIE_HOSTS"
CA_BUNDLE = "CA_BUNDLE"

VerifyT = Union[bool, str, Path]


def _import_requests():
    try:
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
    except ImportError as exc:
        raise ImportError("syshttp.session needs 'requests' (with urllib3): " "pip install 'syshttp[session]'") from exc
    return requests, HTTPAdapter, Retry


#: The URL the caller asked for, while an adapter sends it: a request sent to
#: another URL is the hop to a URL-prefix gateway.
_ASKED_URL: "contextvars.ContextVar[Optional[str]]" = contextvars.ContextVar("syshttp_asked_url", default=None)


def _explicit_verify(verify: Any) -> bool:
    """Is ``verify`` something the caller chose beyond the default: ``False``
    or a bundle. A session with an ``ssl_context`` never turns ``True`` into
    ``CA_BUNDLE``, so anything else came from the caller."""
    return verify is not True


def _proxy_adapter_class():
    """The one adapter that owns every proxy decision: proxylib's
    ``ProxyMapAdapter`` (built on the lazily imported requests) with the
    system's TLS. ``HTTPAdapter.send`` is the single point every request --
    ``session.get``, a bare ``session.send``, and every redirect hop -- passes
    through."""
    import proxylib

    class ProxyAdapter(proxylib.ProxyMapAdapter):  # type: ignore[misc,valid-type]
        """``proxymap`` (default :func:`proxy.proxy_map` for ``env``) routes
        each request: entries tried in order, the next on a connection
        failure, a proxy's headers sent to it only, a URL-prefix gateway
        asked for ``<gateway><URL>`` with the response kept on the caller's
        URL (proxylib). ``ssl_context`` / ``proxy_ssl_context``: the caller's
        TLS for every https origin / https proxy; without them ``verify=True``
        verifies with ``tls.os_ssl_context()``."""

        def __init__(
            self,
            proxymap: Any = None,
            *,
            env: Optional[HTTPEnv] = None,
            ssl_context: "Optional[ssl.SSLContext]" = None,
            proxy_ssl_context: "Optional[ssl.SSLContext]" = None,
            **kwargs: Any,
        ) -> None:
            # Set before HTTPAdapter.__init__, which builds the pool manager.
            self.ssl_context = ssl_context
            self.proxy_ssl_context = proxy_ssl_context
            self._identities: "dict[Any, ssl.SSLContext]" = {}
            self._identities_lock = threading.Lock()
            super().__init__(_proxy.proxy_map(env=env) if proxymap is None else proxymap, **kwargs)

        def route(self, url: str) -> "Tuple[Any, ...]":
            """The proxy map's answer for ``url``: proxylib ``Proxy`` entries
            to try in order, ``None`` for DIRECT; ``()`` when the map has no
            opinion and requests decides from ``proxies``."""
            import proxylib as _proxylib

            try:
                return _proxylib.lookup(self.proxymap, url)
            except KeyError:
                return ()

        def send(self, request, *args, **kwargs):
            token = _ASKED_URL.set(request.url)
            try:
                return super().send(request, *args, **kwargs)
            finally:
                _ASKED_URL.reset(token)

        @staticmethod
        def _to_gateway(url: str) -> bool:
            asked = _ASKED_URL.get()
            return asked is not None and asked != url

        def _identity_context(self, cert: Any) -> "ssl.SSLContext":
            """A context of its own for the client certificate ``cert`` (a path,
            or a ``(certificate, key)`` pair), cached per file and
            modification time. urllib3 loads a pool's ``cert_file`` into the
            context it is given, so the shared OS context must never get one."""
            cert_file, key_file = (cert[0], cert[1]) if isinstance(cert, (tuple, list)) else (cert, None)
            key = tuple((path, os.stat(path).st_mtime_ns) for path in (cert_file, key_file) if path)
            with self._identities_lock:
                context = self._identities.get(key)
                if context is None:
                    context = new_os_context(client_certificates=False)
                    context.load_cert_chain(cert_file, key_file)
                    self._identities[key] = context
            return context

        def build_connection_pool_key_attributes(self, request, verify, cert=None):
            """Over https: the caller's ``ssl_context`` when there is one,
            else for ``verify=True`` the OS trust-store context, in place of
            requests' own (a ``certifi`` bundle in 2.32-2.33); with a client
            certificate (``cert=``), a context of its own that holds it. The OS
            context only for ``verify=True`` -- urllib3 writes a pool's
            ``cert_reqs`` into the context it is given, so a ``verify=False``
            pool must never share it."""
            host_params, pool_kwargs = super().build_connection_pool_key_attributes(request, verify, cert)
            if host_params.get("scheme") == "https":
                if self._to_gateway(request.url):
                    # The gateway is not the origin: never the origin's
                    # context or client certificate.
                    pool_kwargs.pop("cert_file", None)
                    pool_kwargs.pop("key_file", None)
                    if self.proxy_ssl_context is not None:
                        pool_kwargs["ssl_context"] = self.proxy_ssl_context
                    elif verify is True:
                        pool_kwargs["ssl_context"] = os_ssl_context()
                elif self.ssl_context is not None:
                    pool_kwargs["ssl_context"] = self.ssl_context
                    pool_kwargs.pop("cert_file", None)
                    pool_kwargs.pop("key_file", None)
                elif verify is True and cert:
                    pool_kwargs["ssl_context"] = self._identity_context(cert)
                    pool_kwargs.pop("cert_file", None)
                    pool_kwargs.pop("key_file", None)
                elif verify is True:
                    pool_kwargs["ssl_context"] = os_ssl_context()
            return host_params, pool_kwargs

        def proxy_manager_for(self, proxy, **proxy_kwargs):
            """An ``https://`` proxy is spoken to over TLS with the caller's
            ``proxy_ssl_context`` when there is one."""
            if self.proxy_ssl_context is not None and proxy.lower().startswith("https://"):
                proxy_kwargs.setdefault("proxy_ssl_context", self.proxy_ssl_context)
            return super().proxy_manager_for(proxy, **proxy_kwargs)

        def cert_verify(self, conn, url: str, verify, cert) -> None:
            """With the caller's ``ssl_context``, its own ``verify_mode``
            decides: urllib3 writes the connection's ``cert_reqs`` into the
            context, so it is given the value the context already holds, and
            no CA file. ``verify=True`` keeps certificate checking on but
            names no CA file: requests would set ``certifi.where()`` (and
            raise when it is ``None``); with none, urllib3 verifies through
            the pool's OS context, or loads the OS defaults itself on older
            requests."""
            if url.lower().startswith("https") and self._to_gateway(url):
                context = self.proxy_ssl_context
                if context is not None or verify is True:
                    super().cert_verify(conn, url, False, None)  # no CA file, no origin certificate
                    conn.cert_reqs = "CERT_REQUIRED" if context is None else context.verify_mode
                    return
                super().cert_verify(conn, url, verify, None)
                return
            if self.ssl_context is not None and url.lower().startswith("https"):
                if cert:
                    raise ValueError(
                        "cert= and ssl_context contradict: load the client certificate into the ssl_context"
                    )
                if _explicit_verify(verify):
                    raise ValueError(
                        "verify=%r and ssl_context contradict: the context's verify_mode decides" % (verify,)
                    )
                super().cert_verify(conn, url, False, None)  # no CA file
                conn.cert_reqs = self.ssl_context.verify_mode
                return
            if verify is True and url.lower().startswith("https"):
                # The certificate, if any, is in the pool's context already.
                super().cert_verify(conn, url, False, None)  # no CA file
                conn.cert_reqs = "CERT_REQUIRED"
                return
            super().cert_verify(conn, url, verify, cert)

    return ProxyAdapter


def _session_class():
    """``requests.Session`` with the cookie header built under
    :func:`host_only_policy`. requests builds each request's header from a
    fresh merged jar with the default policy, so a policy set on
    ``session.cookies`` alone never reaches it."""
    import requests

    class Session(requests.Session):  # type: ignore[misc,valid-type]
        _cookie_aliases: Dict[str, str] = {}
        #: Where ``CA_BUNDLE`` is read; ``None`` when the session's
        #: ``ssl_context`` decides instead.
        _ca_env: Optional[HTTPEnv] = None

        def merge_environment_settings(self, url, proxies, stream, verify, cert):
            # requests turns verify=True into REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE;
            # here CA_BUNDLE, read through the session's prefixes, does instead.
            default = verify is True or verify is None
            settings = super().merge_environment_settings(url, proxies, stream, False if default else verify, cert)
            if default:
                chosen = self.verify if verify is None else True
                if chosen is True and self._ca_env is not None:
                    chosen = self._ca_env.get(CA_BUNDLE) or True
                settings["verify"] = chosen
            return settings

        def prepare_request(self, request):
            prepared = super().prepare_request(request)
            jar = getattr(prepared, "_cookies", None)
            if jar is None or not hasattr(jar, "set_policy"):
                return prepared
            jar.set_policy(host_only_policy(self._cookie_aliases))
            own = [h for h in (request.headers, self.headers) if h]
            kept = next((v for h in own for k, v in h.items() if str(k).lower() == "cookie"), None)
            prepared.headers.pop("Cookie", None)
            if kept is not None:
                prepared.headers["Cookie"] = kept
            prepared.prepare_cookies(jar)
            return prepared

    return Session


def _cookie_aliases(cookie_hosts: Optional[Iterable[Iterable[str]]], env: HTTPEnv) -> Dict[str, str]:
    """``cookie_hosts``, else ``SYSHTTP_COOKIE_HOSTS`` (groups split by ``;``,
    hosts by ``,``), as :func:`cookies.host_aliases` maps them."""
    if cookie_hosts is not None:
        return host_aliases(cookie_hosts)
    found = env.find(COOKIE_HOSTS)
    if not found:
        return {}
    variable, raw = found
    groups = [[h for h in group.split(",") if h.strip()] for group in raw.split(";")]
    try:
        return host_aliases(groups)
    except ValueError as exc:
        raise ConfigurationError("%s: %s" % (variable, exc)) from None


def new_session(
    *,
    user_agent: Optional[str] = None,
    proxies: Optional[dict] = None,
    verify: VerifyT = True,
    retries: int = 3,
    backoff: float = 1,
    status_forcelist: Iterable[int] = TRANSIENT_STATUSES,
    cookies: Union[bool, str, "CookieJar"] = False,
    tokens: Union[bool, str, "TokenJar"] = False,
    auth_provider: Optional["AuthProvider"] = None,
    env: Optional[HTTPEnv] = None,
    ssl_context: Optional[ssl.SSLContext] = None,
    proxy_ssl_context: Optional[ssl.SSLContext] = None,
    cookie_hosts: Optional[Iterable[Iterable[str]]] = None,
) -> "requests.Session":
    """A ``requests.Session`` configured as the module docstring says.
    ``env`` -- where proxy, jar and hook settings are read
    (:class:`~syshttp.env.HTTPEnv`, default ``HTTPEnv()``). ``ssl_context`` --
    the TLS context for every https origin, used as given: its
    ``verify_mode``, trust store, client identity and ciphers decide, so
    ``verify`` must stay ``True`` beside it (anything else: ``ValueError``).
    ``proxy_ssl_context`` -- the same for an ``https://`` proxy.
    ``cookie_hosts`` -- groups of hosts that share cookies (default
    ``SYSHTTP_COOKIE_HOSTS``; ``[]`` for none). A status in
    ``status_forcelist`` that outlasts ``retries`` is returned as a response
    (not raised); a connection that never succeeds still raises."""
    for name, value in (("ssl_context", ssl_context), ("proxy_ssl_context", proxy_ssl_context)):
        if value is not None and not isinstance(value, ssl.SSLContext):
            raise TypeError("%s must be an ssl.SSLContext, not %s" % (name, type(value).__name__))
    if ssl_context is not None and verify is not True:
        raise ValueError("verify=%r and ssl_context contradict: the context's verify_mode decides" % (verify,))
    env = HTTPEnv() if env is None else env
    # First, for its actionable ImportError when requests is absent.
    _, _, Retry = _import_requests()
    aliases = _cookie_aliases(cookie_hosts, env)
    session = _session_class()()
    session._cookie_aliases = aliases
    session._ca_env = env if ssl_context is None else None
    session.cookies.set_policy(host_only_policy(aliases))
    cookie_jar: Optional[CookieJar] = None
    cookie_key: Optional[str] = None
    if cookies is True:
        cookie_jar = FileCookieJar(env=env)
        cookie_key = "__by_host__"
    elif isinstance(cookies, str):
        cookie_jar = FileCookieJar(env=env)
        cookie_key = cookies
    elif cookies is not None and cookies is not False:
        # `is not`, not truthiness: an empty MemoryCookieJar is a jar.
        cookie_jar = cookies
        cookie_key = "__by_host__"
    token_jar: Optional[TokenJar] = None
    token_key: Optional[str] = None
    if tokens is True:
        token_jar = FileTokenJar(env=env)
        token_key = "__by_host__"
    elif isinstance(tokens, str):
        token_jar = FileTokenJar(env=env)
        token_key = tokens
    elif tokens is not None and tokens is not False:
        token_jar = tokens
        token_key = "__by_host__"
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=list(status_forcelist),
        # The last response comes back when the retries run out, as plain
        # requests returns it, instead of a RetryError.
        raise_on_status=False,
    )
    proxymap: Any = None
    if proxies is None:
        # Validated now, decided per request by proxy.proxy_map(env=env).
        _proxy.configured_proxy(env=env)
    else:
        # Caller-supplied proxies are requests' business (userinfo included):
        # a map with no opinion leaves every request to them.
        session.proxies = proxies
        proxymap = {}
    adapter = _proxy_adapter_class()(
        proxymap,
        env=env,
        ssl_context=ssl_context,
        proxy_ssl_context=proxy_ssl_context,
        max_retries=retry_strategy,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    if isinstance(verify, Path):
        session.verify = str(verify)
    else:
        session.verify = verify
    if user_agent:
        session.headers["User-Agent"] = user_agent
    _orig_request = session.request
    loaded_keys = set()

    def _key_for(url: str) -> str:
        return urlparse(url).hostname or ""

    def _has_header(mapping, name: str) -> bool:
        try:
            return any(str(k).lower() == name for k in mapping)
        except Exception:
            return False

    def _authorization_for(url: str) -> Optional[str]:
        """The ``Authorization`` value for ``url``'s host from the token jar,
        or ``None``. A value that already names its scheme (``Basic …``,
        ``token …``) goes verbatim; a bare token is a bearer token. The
        value is a secret: never logged."""
        if token_jar is None:
            return None
        key = token_key if token_key and token_key != "__by_host__" else _key_for(url)
        if not key:
            return None
        try:
            token = token_jar.get(key)
        except Exception:
            return None
        if not token:
            return None
        token = str(token).strip()
        if any(ch in token for ch in "\r\n\0"):
            # Named, not echoed: the value is a secret.
            raise ConfigurationError("the token for %r contains a carriage return, line feed or NUL character" % key)
        return token if re.match(r"^[A-Za-z][\w-]*\s+\S", token) else "Bearer " + token

    def _cookie_host(url: str) -> str:
        # An alias group's cookies are kept under its first host.
        host = _key_for(url)
        return aliases.get(host.lower(), host)

    #: Per first host of an alias group, the group's hosts.
    group_of: dict = {}
    for alias, first in aliases.items():
        group_of.setdefault(first, []).append(alias)

    def _cookie_keys_for(url: str) -> list:
        host = _cookie_host(url)
        if cookie_key and cookie_key != "__by_host__":
            return [cookie_key]
        return [host] if host else []

    #: Per jar key, the rows the session last loaded from or wrote to the
    #: jar: a response that changes none of them writes nothing.
    synced: dict = {}

    def _session_specs(host: str) -> Optional[list]:
        """The session's cookies as jar rows, or ``None`` when they cannot be
        read (a write then would empty the jar)."""
        try:
            return [_spec_from_cookie(c, host) for c in session.cookies]
        except Exception:
            return None

    def _covers(row, host: str) -> bool:
        # A row's domain is bare; its include-subdomains flag is the dot.
        return domain_covers("." + row.domain if row.subdomains else row.domain, host)

    def _rows_for(key: str, host: str, specs: list) -> list:
        # A host's file holds that host's cookies: by-host keys keep only the
        # rows whose domain covers the host, so a session that talked to two
        # hosts never copies one's cookies into the other's file. A named jar
        # keeps everything.
        if key != host:
            return specs
        hosts = group_of.get(key, [key])
        return [c for c in specs if any(_covers(c, h) for h in hosts)]

    def _remember(key: str, host: str) -> None:
        specs = _session_specs(host)
        if specs is not None:
            synced[key] = frozenset(_rows_for(key, host, specs))

    def _load_cookies_for(url: str) -> None:  # noqa: E306
        if cookie_jar is None:
            return
        for key in _cookie_keys_for(url):
            if not key or key in loaded_keys:
                continue
            try:
                apply_to_session(session, cookie_jar.get(key, []))
            except Exception:
                pass
            _remember(key, _cookie_host(url))
            loaded_keys.add(key)

    def _save_cookies_for(url: str, response: "requests.Response") -> None:
        if cookie_jar is None and not aliases:
            return
        try:
            merge_set_cookie_headers(session, response, aliases=aliases)
        except Exception:
            pass
        if cookie_jar is None:
            return
        host = _cookie_host(url)
        specs = _session_specs(host)
        if specs is None:
            return
        for key in _cookie_keys_for(url):
            if not key:
                continue
            rows = _rows_for(key, host, specs)
            state = frozenset(rows)
            if synced.get(key) == state:
                continue
            try:
                cookie_jar[key] = rows
            except Exception:
                continue
            synced[key] = state

    #: Whether this thread is inside ``auth_provider.ensure`` or a hook: its
    #: own requests must not start either again, other threads' must.
    busy = threading.local()

    def _load_state(url: str) -> None:
        _load_cookies_for(url)
        if auth_provider and not getattr(busy, "ensuring", False):
            try:
                busy.ensuring = True
                auth_provider.ensure(session, url)
            except Exception:
                pass
            finally:
                busy.ensuring = False

    def request(method: str, url: str, **kwargs: Any) -> "requests.Response":
        _load_state(url)
        if not getattr(busy, "in_hook", False):
            busy.in_hook = True
            try:
                hooked = _hooks.call_py_hooks(session, method, url, kwargs, env=env)
            finally:
                busy.in_hook = False
            if hooked is not None:
                return hooked
        authorization = _authorization_for(url)
        if authorization and not kwargs.get("auth") and not _has_header(session.headers, "authorization"):
            headers = dict(kwargs.get("headers") or {})
            if not _has_header(headers, "authorization"):
                headers["Authorization"] = authorization
                kwargs["headers"] = headers
        resp = _orig_request(method, url, **kwargs)
        _save_cookies_for(getattr(resp, "url", url), resp)
        return resp

    session.request = request
    if cookie_jar is not None and cookie_key and cookie_key != "__by_host__":
        try:
            apply_to_session(session, cookie_jar.get(cookie_key, []))
            _remember(cookie_key, "")
            loaded_keys.add(cookie_key)
        except Exception:
            pass
    return session

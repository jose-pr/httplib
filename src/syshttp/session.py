"""Build a configured ``requests.Session`` with retry/backoff, the configured proxy
(credential, kind and ``NO_PROXY`` bypass, all decided in ONE adapter), and
transparent cookie/token load-save + per-host auth.

Cookies and tokens are always chosen by the host of the URL the caller asked
for -- the origin -- never by the proxy's or the gateway's: the jars are read
before the adapter sees the request, the adapter rewrites a COPY, and what
comes back is attributed to the origin again (``response.url``,
``response.request``, ``response.cookies``). A token is a per-request
``Authorization`` header (``Bearer <value>``, or the value verbatim when it
already names a scheme), never a session header, so it cannot leak to another
host; an explicit header or ``auth=`` wins.

URL hooks (``<P>_HOOKS_<KEY>`` + ``_PY``, see :mod:`.hooks`) run in the
same place, on the caller's URL, before the request: a hook may log in, set
headers in the request's kwargs, or return a response of its own. A hook
that makes requests through the session does not trigger hooks again.

TLS is the system's: with ``verify=True`` the adapter hands urllib3
``tls.os_ssl_context()`` (sslcontext's system context: the OS verifies
servers, and a client certificate comes from the OS store when a server asks)
and no CA file, so no ``certifi`` bundle is involved. ``verify=<path>`` and ``REQUESTS_CA_BUNDLE`` /
``CURL_CA_BUNDLE`` still name a bundle explicitly; ``verify=False`` is left to
requests. ``ssl_context=`` replaces all of that with a context of the caller's
own -- a client certificate (a keystore identity too), a cipher list, a
pinned protocol version -- used as given for every https origin;
``proxy_ssl_context=`` does the same for the TLS to an ``https://`` proxy.

``requests`` + ``urllib3`` are this toolkit's **optional dependency** (the
``session`` extra). ``new_session`` imports them lazily and raises a clear,
actionable error if they are absent; every other module works without them.
"""

from __future__ import annotations

import re
import ssl
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterable, Optional, Tuple, Union
from urllib.parse import urlparse

from . import hooks as _hooks
from .auth import AuthProvider
from .cookies import CookieSpec, apply_to_session, domain_covers, merge_set_cookie_headers
from .env import HTTPEnv
from .jar import CookieJar, FileCookieJar, FileTokenJar, TokenJar
from .retry import TRANSIENT_STATUSES
from .tls import OS_CONTEXT_MAX_AGE, os_ssl_context  # noqa: F401  (re-exported: session's own API)

# The module, not its functions: `should_bypass`'s default sentinel belongs
# to the module instance, and a function bound by name before a reload
# would pass a stale one.
from . import proxy as _proxy
from .warnings import disable_insecure_request_warnings

if TYPE_CHECKING:  # requests is optional at runtime: types only
    import requests

VerifyT = Union[bool, str, Path]


def _import_requests():
    try:
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
    except ImportError as exc:  # pragma: no cover - exercised via message assert
        raise ImportError("syshttp.session needs 'requests' (with urllib3): " "pip install 'syshttp[session]'") from exc
    return requests, HTTPAdapter, Retry


def _proxy_adapter_class(HTTPAdapter):
    """The one adapter that owns every proxy decision, built lazily on the
    lazily imported ``HTTPAdapter``. ``HTTPAdapter.send(request, proxies=...)``
    is the single point every request -- ``session.get``, a bare
    ``session.send``, and every redirect hop -- passes through, so this is the
    layer requests designed for it; a ``session.request`` wrapper would miss
    the last two."""
    from requests.cookies import RequestsCookieJar, extract_cookies_to_jar

    class ProxyAdapter(HTTPAdapter):
        """``proxy`` (userinfo-free URL) + ``authorization`` (the
        ``Proxy-Authorization`` value) + ``endpoint`` (``None`` for a
        ``connect`` proxy, the ``/endpoint`` of a prefix gateway).

        * ``NO_PROXY`` hosts go direct, and never see the credential.
        * ``connect``: the proxy is passed EXPLICITLY per request, so the global
          ``HTTP_PROXY``/``HTTPS_PROXY`` that ``trust_env`` would otherwise merge
          in cannot win over the configured proxy -- and the credential is added by
          ``proxy_headers`` only for THIS proxy, so it can never reach another.
          That hook covers the plain-http request and the https ``CONNECT``; a
          header on the session would reach the origin inside the tunnel instead.
        * ``prefix``: the request goes directly to ``<proxy><endpoint><url>`` with
          the credential as a header of that request.

        Every send works on a COPY of the prepared request: requests builds
        redirect hops from the caller's object, so mutating it would carry the
        gateway URL and the credential into the next hop -- which may be a
        ``NO_PROXY`` origin. The response reports the caller's URL, so
        redirects, cookies and history speak the URL the caller asked for.
        """

        def __init__(
            self,
            *,
            proxy: Optional[str] = None,
            authorization: Optional[str] = None,
            endpoint: Optional[str] = None,
            auth_header: Optional[str] = None,
            env: Optional[HTTPEnv] = None,
            ssl_context: "Optional[ssl.SSLContext]" = None,
            proxy_ssl_context: "Optional[ssl.SSLContext]" = None,
            dynamic: bool = False,
            **kwargs: Any,
        ) -> None:
            # Set before HTTPAdapter.__init__, which builds the pool manager.
            self.ssl_context = ssl_context
            self.proxy_ssl_context = proxy_ssl_context
            super().__init__(**kwargs)
            self.env = env
            self.dynamic = dynamic
            self.proxy = proxy
            self.authorization = authorization
            self.endpoint = endpoint
            self.auth_header = auth_header or _proxy.DEFAULT_AUTH_HEADER
            # (header, value) per proxy URL, for proxy_headers.
            self._credentials: Dict[str, Tuple[str, str]] = {}
            if proxy and authorization:
                self._credentials[self._key(proxy)] = (self.auth_header, authorization)

        def build_connection_pool_key_attributes(self, request, verify, cert=None):
            """Over https: the caller's ``ssl_context`` when there is one,
            else for ``verify=True`` the OS trust-store context, in place of
            requests' own (a ``certifi`` bundle in 2.32-2.33). The OS context
            only for ``verify=True`` -- urllib3 writes a pool's ``cert_reqs``
            into the context it is given, so a ``verify=False`` pool must
            never share it."""
            host_params, pool_kwargs = super().build_connection_pool_key_attributes(request, verify, cert)
            if host_params.get("scheme") == "https":
                if self.ssl_context is not None:
                    pool_kwargs["ssl_context"] = self.ssl_context
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
            if self.ssl_context is not None and url.lower().startswith("https"):
                super().cert_verify(conn, url, False, cert)  # client cert, no CA file
                conn.cert_reqs = self.ssl_context.verify_mode
                return
            if verify is True and url.lower().startswith("https"):
                super().cert_verify(conn, url, False, cert)  # client cert, no CA file
                conn.cert_reqs = "CERT_REQUIRED"
                return
            super().cert_verify(conn, url, verify, cert)

        @staticmethod
        def _key(proxy: str) -> str:
            # requests lower-cases the proxy URL it hands back to proxy_headers.
            return proxy.rstrip("/").lower()

        def proxy_headers(self, proxy: str) -> Dict[str, str]:
            headers = super().proxy_headers(proxy)
            credential = self._credentials.get(self._key(proxy))
            if credential is None and self.dynamic:
                # Not yet routed through: the configured proxy's own credential.
                configured = _proxy.resolve(env=self.env)
                if configured and configured[1] and self._key(configured[0]) == self._key(proxy):
                    credential = (_proxy.auth_header(env=self.env), configured[1])
            if credential:
                headers[credential[0]] = credential[1]
            return headers

        def route(self, url: str) -> "Optional[_proxy.ProxyPlan]":
            """The plan for one hop: decided again for every request (the
            environment as it is now, and the system's answer for this URL)
            unless the session was given fixed proxies."""
            if self.dynamic:
                return _proxy.plan(url=url, env=self.env)
            if not self.proxy:
                return None
            return _proxy.ProxyPlan(self.proxy, self.authorization, self.endpoint, None, self.auth_header)

        def send(self, request: "requests.PreparedRequest", **kwargs: Any) -> "requests.Response":
            original = request.url or ""
            route = self.route(original)
            if route is None:
                if self.dynamic:
                    kwargs["proxies"] = {}  # decided: direct (trust_env must not re-add a proxy)
                return super().send(request, **kwargs)
            caller_request = request
            request = request.copy()
            if _proxy.should_bypass(original, env=self.env):
                kwargs["proxies"] = {}
                return super().send(request, **kwargs)
            if route.authorization:
                self._credentials[self._key(route.proxy)] = (route.auth_header, route.authorization)
            if route.endpoint is None:
                kwargs["proxies"] = {"http": route.proxy, "https": route.proxy}
                return super().send(request, **kwargs)
            # Prefix gateway. A Location the gateway wrote in its own namespace
            # is already prefixed: never wrap it twice.
            if not original.startswith(route.gateway_base or "\0"):
                request.url = _proxy.prefix_url(original, route.proxy, route.endpoint)
            if route.authorization:
                request.headers[route.auth_header] = route.authorization
            kwargs["proxies"] = {}
            response = super().send(request, **kwargs)
            response.url = original
            # The response speaks the caller's request too, not the transport
            # copy: `Session.resolve_redirects` compares `response.request.url`
            # with the next hop to decide whether `Authorization` survives,
            # and the per-response cookies must be extracted against the
            # origin host, not the gateway's, so a `Set-Cookie` is filed under
            # the origin.
            response.request = caller_request
            jar = RequestsCookieJar()
            extract_cookies_to_jar(jar, caller_request, response.raw)
            response.cookies = jar
            return response

    return ProxyAdapter


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
) -> "requests.Session":
    """A ``requests.Session`` configured as the module docstring says.
    ``env`` -- where proxy, jar and hook settings are read
    (:class:`~syshttp.env.HTTPEnv`, default ``HTTPEnv()``). ``ssl_context`` --
    the TLS context for every https origin, used as given: its
    ``verify_mode``, trust store, client identity and ciphers decide, so
    ``verify`` must stay ``True`` beside it (anything else: ``ValueError``).
    ``proxy_ssl_context`` -- the same for an ``https://`` proxy."""
    for name, value in (("ssl_context", ssl_context), ("proxy_ssl_context", proxy_ssl_context)):
        if value is not None and not isinstance(value, ssl.SSLContext):
            raise TypeError("%s must be an ssl.SSLContext, not %s" % (name, type(value).__name__))
    if ssl_context is not None and verify is not True:
        raise ValueError("verify=%r and ssl_context contradict: the context's verify_mode decides" % (verify,))
    env = HTTPEnv() if env is None else env
    disable_insecure_request_warnings()
    # Not `requests`: that name is the TYPE_CHECKING import the annotations
    # below refer to, and a local of the same name would shadow it.
    requests_mod, HTTPAdapter, Retry = _import_requests()
    session = requests_mod.Session()
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
    )
    proxy_url: Optional[str] = None
    authorization: Optional[str] = None
    endpoint: Optional[str] = None
    if proxies is None:
        # Validated now, decided per request: proxy.plan(url=...) for each hop,
        # the decision a curl front end makes too.
        _proxy.proxy_type(env=env) if _proxy.configured_proxy_url(env=env) else None
    else:
        # Caller-supplied proxies are requests' business (userinfo included);
        # the configured credential still applies if one of them IS the configured proxy.
        session.proxies = proxies
        configured = _proxy.resolve(env=env)
        if configured:
            proxy_url, authorization = configured[0], _proxy.configured_authorization(env=env)
            proxy_url = proxy_url if proxy_url in proxies.values() else None
    adapter = _proxy_adapter_class(HTTPAdapter)(
        proxy=proxy_url,
        authorization=authorization,
        endpoint=endpoint,
        auth_header=_proxy.auth_header(env=env),
        env=env,
        ssl_context=ssl_context,
        proxy_ssl_context=proxy_ssl_context,
        dynamic=proxies is None,
        max_retries=retry_strategy,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    if isinstance(verify, Path):
        session.verify = str(verify)
    else:
        session.verify = verify
    if user_agent:
        session.headers.setdefault("User-Agent", user_agent)
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
        return token if re.match(r"^[A-Za-z][\w-]*\s+\S", token) else "Bearer " + token

    def _cookie_keys_for(url: str) -> list:
        host = _key_for(url)
        if cookie_key and cookie_key != "__by_host__":
            return [cookie_key]
        return [host] if host else []

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
            loaded_keys.add(key)

    def _save_cookies_for(url: str, response: "requests.Response") -> None:
        if cookie_jar is None:
            return
        try:
            merge_set_cookie_headers(session, response)
        except Exception:
            pass
        specs = []
        try:
            for c in session.cookies:
                specs.append(
                    CookieSpec(
                        domain=getattr(c, "domain", "") or "",
                        path=getattr(c, "path", "/") or "/",
                        secure=bool(getattr(c, "secure", False)),
                        expires=getattr(c, "expires", None),
                        name=getattr(c, "name", ""),
                        value=getattr(c, "value", ""),
                    )
                )
        except Exception:
            specs = []
        for key in _cookie_keys_for(url):
            if not key:
                continue
            # A host's file holds that host's cookies: by-host keys keep
            # only the rows whose domain covers the host, so a session
            # that talked to two hosts never copies one's cookies into
            # the other's file. A named jar keeps everything.
            rows = specs if key != _key_for(url) else [c for c in specs if domain_covers(c.domain, key)]
            try:
                cookie_jar[key] = rows
            except Exception:
                pass

    _ensuring = False

    def _load_state(url: str) -> None:
        _load_cookies_for(url)
        nonlocal _ensuring
        if auth_provider and not _ensuring:
            try:
                _ensuring = True
                auth_provider.ensure(session, url)
            except Exception:
                pass
            finally:
                _ensuring = False

    _in_hook = False

    def request(method: str, url: str, **kwargs: Any) -> "requests.Response":
        nonlocal _in_hook
        _load_state(url)
        if not _in_hook:
            _in_hook = True
            try:
                hooked = _hooks.call_py_hooks(session, method, url, kwargs, env=env)
            finally:
                _in_hook = False
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
            loaded_keys.add(cookie_key)
        except Exception:
            pass
    return session

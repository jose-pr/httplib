"""Build a configured ``requests.Session`` with retry/backoff, the agent proxy
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

URL hooks (``NET_HOOKS_<KEY>`` + ``_PY``, see :mod:`.hooks`) run in the
same place, on the caller's URL, before the request: a hook may log in, set
headers in the request's kwargs, or return a response of its own. A hook
that makes requests through the session does not trigger hooks again.

TLS verification uses the OS trust store directly: with ``verify=True`` the
adapter hands urllib3 an ``ssl.create_default_context()`` (the certificate
store on Windows, OpenSSL's system defaults elsewhere) and no CA file, so no
``certifi`` bundle is involved. ``verify=<path>`` and ``REQUESTS_CA_BUNDLE`` /
``CURL_CA_BUNDLE`` still name a bundle explicitly; ``verify=False`` is left to
requests.

``requests`` + ``urllib3`` are this toolkit's **optional dependency** (the
``session`` extra). ``new_session`` imports them lazily and raises a clear,
actionable error if they are absent; every other module works without them.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterable, Optional, Union
from urllib.parse import urlparse

from . import hooks as _hooks
from .auth import AuthProvider
from .cookies import CookieSpec, apply_to_session, domain_covers, merge_set_cookie_headers
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
        raise ImportError(
            "httplib.session needs 'requests' (with urllib3): "
            "pip install 'httplib[session]'"
        ) from exc
    return requests, HTTPAdapter, Retry




def _agent_proxy_adapter_class(HTTPAdapter):
    """The one adapter that owns every proxy decision, built lazily on the
    lazily imported ``HTTPAdapter``. ``HTTPAdapter.send(request, proxies=...)``
    is the single point every request -- ``session.get``, a bare
    ``session.send``, and every redirect hop -- passes through, so this is the
    layer requests designed for it; a ``session.request`` wrapper would miss
    the last two."""
    from requests.cookies import RequestsCookieJar, extract_cookies_to_jar

    class AgentProxyAdapter(HTTPAdapter):
        """``proxy`` (userinfo-free URL) + ``authorization`` (the
        ``Proxy-Authorization`` value) + ``endpoint`` (``None`` for a
        ``connect`` proxy, the ``/endpoint`` of a prefix gateway).

        * ``NO_PROXY`` hosts go direct, and never see the credential.
        * ``connect``: the proxy is passed EXPLICITLY per request, so the global
          ``HTTP_PROXY``/``HTTPS_PROXY`` that ``trust_env`` would otherwise merge
          in cannot win over the agent proxy -- and the credential is added by
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
            self, *, proxy: Optional[str] = None, authorization: Optional[str] = None,
            endpoint: Optional[str] = None, auth_header: Optional[str] = None, **kwargs: Any,
        ) -> None:
            super().__init__(**kwargs)
            self.proxy = proxy
            self.authorization = authorization
            self.endpoint = endpoint
            self.auth_header = auth_header or _proxy.DEFAULT_AUTH_HEADER
            self._gateway_base = _proxy.prefix_url("", proxy, endpoint) if endpoint is not None and proxy else None

        def build_connection_pool_key_attributes(self, request, verify, cert=None):
            """``verify=True`` over https: the OS trust-store context, in
            place of requests' own (a ``certifi`` bundle in 2.32-2.33). Only
            for ``verify=True`` -- urllib3 writes a pool's ``cert_reqs`` into
            the context it is given, so a ``verify=False`` pool must never
            share it."""
            host_params, pool_kwargs = super().build_connection_pool_key_attributes(
                request, verify, cert
            )
            if verify is True and host_params.get("scheme") == "https":
                pool_kwargs["ssl_context"] = os_ssl_context()
            return host_params, pool_kwargs

        def cert_verify(self, conn, url: str, verify, cert) -> None:
            """``verify=True`` keeps certificate checking on but names no CA
            file: requests would set ``certifi.where()`` (and raise when it is
            ``None``); with none, urllib3 verifies through the pool's OS
            context, or loads the OS defaults itself on older requests."""
            if verify is True and url.lower().startswith("https"):
                super().cert_verify(conn, url, False, cert)  # client cert, no CA file
                conn.cert_reqs = "CERT_REQUIRED"
                return
            super().cert_verify(conn, url, verify, cert)

        def proxy_headers(self, proxy: str) -> Dict[str, str]:
            headers = super().proxy_headers(proxy)
            if self.authorization and self.proxy and proxy.rstrip("/") == self.proxy.rstrip("/"):
                headers[self.auth_header] = self.authorization
            return headers

        def send(self, request: "requests.PreparedRequest", **kwargs: Any) -> "requests.Response":
            if not self.proxy:
                return super().send(request, **kwargs)
            original = request.url or ""
            caller_request = request
            request = request.copy()
            if _proxy.should_bypass(original):
                kwargs["proxies"] = {}
                return super().send(request, **kwargs)
            if self.endpoint is None:
                kwargs["proxies"] = {"http": self.proxy, "https": self.proxy}
                return super().send(request, **kwargs)
            # Prefix gateway. A Location the gateway wrote in its own namespace
            # is already prefixed: never wrap it twice.
            if not (self._gateway_base and original.startswith(self._gateway_base)):
                request.url = _proxy.prefix_url(original, self.proxy, self.endpoint)
            if self.authorization:
                request.headers[self.auth_header] = self.authorization
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

    return AgentProxyAdapter


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
) -> "requests.Session":
    disable_insecure_request_warnings()
    # Not `requests`: that name is the TYPE_CHECKING import the annotations
    # below refer to, and a local of the same name would shadow it.
    requests_mod, HTTPAdapter, Retry = _import_requests()
    session = requests_mod.Session()
    cookie_jar: Optional[CookieJar] = None
    cookie_key: Optional[str] = None
    if cookies is True:
        cookie_jar = FileCookieJar()
        cookie_key = "__by_host__"
    elif isinstance(cookies, str):
        cookie_jar = FileCookieJar()
        cookie_key = cookies
    elif cookies is not None and cookies is not False:
        # `is not`, not truthiness: an empty MemoryCookieJar is a jar.
        cookie_jar = cookies
        cookie_key = "__by_host__"
    token_jar: Optional[TokenJar] = None
    token_key: Optional[str] = None
    if tokens is True:
        token_jar = FileTokenJar()
        token_key = "__by_host__"
    elif isinstance(tokens, str):
        token_jar = FileTokenJar()
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
        planned = _proxy.plan()  # the decision the curl fallback makes too
        if planned is not None:
            proxy_url, authorization, endpoint = planned.proxy, planned.authorization, planned.endpoint
    else:
        # Caller-supplied proxies are requests' business (userinfo included);
        # the configured credential still applies if one of them IS the agent proxy.
        session.proxies = proxies
        configured = _proxy.resolve()
        if configured:
            proxy_url, authorization = configured[0], _proxy.configured_authorization()
            proxy_url = proxy_url if proxy_url in proxies.values() else None
    adapter = _agent_proxy_adapter_class(HTTPAdapter)(
        proxy=proxy_url, authorization=authorization, endpoint=endpoint,
        auth_header=_proxy.auth_header(), max_retries=retry_strategy,
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
                hooked = _hooks.call_py_hooks(session, method, url, kwargs)
            finally:
                _in_hook = False
            if hooked is not None:
                return hooked
        authorization = _authorization_for(url)
        if (
            authorization
            and not kwargs.get("auth")
            and not _has_header(session.headers, "authorization")
        ):
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

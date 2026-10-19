"""Patch HTTP client libraries as they are imported, so they route and verify
the way syshttp does: ``<P>_PROXY``, the ``*_PROXY`` variables, ``NO_PROXY``
and the system's proxy configuration (:func:`syshttp.proxy.plan`), and the
system's TLS context (:func:`syshttp.tls.os_ssl_context`).

``SYSHTTP_IMPORTPATCH`` chooses the libraries -- ``<PREFIX>_SYSHTTP_IMPORTPATCH``
under a prefix of a tool's own (``SYSHTTP_PREFIX=AGENTS``:
``AGENTS_SYSHTTP_IMPORTPATCH``): ``1``/``true``/``yes``/``on`` for all of
:data:`TARGETS`, ``0``/``false``/``no``/``off``, empty or unset for none, else
their names separated by ``:`` (``requests:httpx``; ``urllib.request`` is
``urllib``). It is read when
the library is imported: importpatch (a dependency) calls :func:`importpatch`
for each target, through this distribution's ``importpatch`` entry points.
:func:`patch` applies the same patches from code, whatever the setting says.

What the caller chose always wins: a proxy given to the client, a context, a
CA bundle or ``verify=False``. A request with no proxy of the caller's is
routed by syshttp; with verification on and no TLS settings of the caller's,
it is verified with the system's context. When no proxy the system names is
reachable (and its list holds no DIRECT), the client's own proxy error is
raised.
"""

from __future__ import annotations

import functools
import importlib
import logging
import ssl
import threading
import time
from types import ModuleType
from typing import Any, Callable, Dict, FrozenSet, Iterable, Optional, Tuple
from urllib.parse import urlsplit

from . import proxy as _proxy
from . import tls as _tls
from .env import DEFAULT_PREFIX, HTTPEnv

__all__ = ["SETTING", "TARGETS", "enabled", "importpatch", "patch", "patched", "setting_name", "unpatch"]

#: The variable, under the default prefix or none; ``<PREFIX>_SYSHTTP_IMPORTPATCH``
#: under any other prefix (:func:`setting_name`).
SETTING = "SYSHTTP_IMPORTPATCH"
#: The libraries that can be patched: name -> the module whose import patches it.
TARGETS: Dict[str, str] = {
    "requests": "requests",
    "urllib": "urllib.request",
    "httpx": "httpx",
    "aiohttp": "aiohttp",
}

_log = logging.getLogger(__name__)
_TRUE = ("1", "true", "yes", "on")
_FALSE = ("", "0", "false", "no", "off")
_BY_MODULE = {module: name for name, module in TARGETS.items()}
_lock = threading.RLock()
# name -> the function that undoes its patch, in the order applied.
_undo: Dict[str, Callable[[], None]] = {}


def setting_name(*, env: Optional[HTTPEnv] = None) -> str:
    """The variable that chooses the libraries: ``SYSHTTP_IMPORTPATCH`` under
    the default prefix or the empty one, ``<PREFIX>_SYSHTTP_IMPORTPATCH``
    under any other (``AGENTS_SYSHTTP_IMPORTPATCH``)."""
    env = HTTPEnv() if env is None else env
    prefix = env.prefix
    return SETTING if prefix in ("", DEFAULT_PREFIX) else "%s_%s" % (prefix, SETTING)


def enabled(*, env: Optional[HTTPEnv] = None) -> FrozenSet[str]:
    """The names of :data:`TARGETS` that :func:`setting_name` enables, ``:``
    separated. A name that is not a target is logged at WARNING and skipped."""
    env = HTTPEnv() if env is None else env
    name = setting_name(env=env)
    raw = (env.environ.get(name) or "").strip()
    if raw.lower() in _FALSE:
        return frozenset()
    if raw.lower() in _TRUE:
        return frozenset(TARGETS)
    names = set()
    for part in raw.split(":"):
        part = part.strip()
        if not part:
            continue
        target = _BY_MODULE.get(part, part)
        if target in TARGETS:
            names.add(target)
        else:
            _log.warning("%s names %r, which is not one of %s", name, part, ", ".join(TARGETS))
    return frozenset(names)


def importpatch(name: str, module: ModuleType) -> None:
    """importpatch's entry point: patch ``module``, just imported as ``name``,
    when :func:`setting_name` enables it."""
    target = _BY_MODULE.get(name)
    if target is not None and target in enabled():
        _apply(target, module)


def patch(targets: Optional[Iterable[str]] = None) -> Tuple[str, ...]:
    """Patch ``targets`` now (default: every target whose library is
    installed), importing each library. A name that is not a target is a
    ``ValueError``; a named library that is not installed raises its
    ``ImportError``. Returns the names patched; patching twice does nothing."""
    names = list(TARGETS) if targets is None else [_BY_MODULE.get(t, t) for t in targets]
    for name in names:
        if name not in TARGETS:
            raise ValueError("%r is not one of %s" % (name, ", ".join(TARGETS)))
    done = []
    for name in names:
        try:
            module = importlib.import_module(TARGETS[name])
        except ImportError:
            if targets is not None:
                raise
            continue
        _apply(name, module)
        done.append(name)
    return tuple(done)


def unpatch() -> None:
    """Undo every patch, the last applied first. A client built while patched
    keeps what it was given."""
    with _lock:
        for name in reversed(list(_undo)):
            _undo.pop(name)()


def patched() -> Tuple[str, ...]:
    """The names patched now, in the order applied."""
    with _lock:
        return tuple(_undo)


def _apply(name: str, module: ModuleType) -> None:
    with _lock:
        if name not in _undo:
            _undo[name] = _PATCHERS[name](module)


def _context(certificate: bool = False) -> ssl.SSLContext:
    """The system's context; a fresh one offering no store certificate when
    the caller loads a certificate of its own into it."""
    if certificate:
        return _tls.new_os_context(client_certificates=False)
    return _tls.os_ssl_context()


# ---- requests ----------------------------------------------------------------


def _patch_requests(requests: ModuleType) -> Callable[[], None]:
    """Every new ``requests.Session`` mounts syshttp's adapter for ``http://``
    and ``https://``: per-request routing, the system's context for
    ``verify=True``. A proxy the caller chose, or ``trust_env = False``, is
    sent as requests would."""
    from .session import _proxy_adapter_class

    adapter_class = _proxy_adapter_class(requests.adapters.HTTPAdapter)
    session_class = requests.Session
    original = session_class.__init__

    @functools.wraps(original)
    def __init__(self: Any, *args: Any, **kwargs: Any) -> None:
        original(self, *args, **kwargs)
        adapter = adapter_class(dynamic=True, caller_proxies=True, session=self, env=HTTPEnv())
        self.mount("https://", adapter)
        self.mount("http://", adapter)

    session_class.__init__ = __init__
    return lambda: setattr(session_class, "__init__", original)


# ---- urllib ------------------------------------------------------------------

# One context for http.client's default: it sets ALPN on the context it is
# handed, so it does not share the requests session's.
_https_context: "Optional[ssl.SSLContext]" = None
_https_context_at = 0.0


def _default_https_context() -> ssl.SSLContext:
    global _https_context, _https_context_at
    with _lock:
        now = time.monotonic()
        if _https_context is None or now - _https_context_at > _tls.OS_CONTEXT_MAX_AGE:
            _https_context = _tls.new_os_context()
            _https_context_at = now
        return _https_context


def _patch_urllib(request: ModuleType) -> Callable[[], None]:
    """``urllib.request.ProxyHandler`` built without proxies (as every
    default opener builds it) routes each request and redirect hop by
    syshttp; one built with a mapping is the standard one. ``http.client``'s
    default HTTPS context (``ssl._create_default_https_context``) becomes the
    system's, for urllib and every other caller that gives none."""
    from urllib.error import URLError

    original_handler = request.ProxyHandler

    class SystemProxyHandler(original_handler):  # type: ignore[misc, valid-type]
        def __init__(self, proxies: Optional[Dict[str, str]] = None) -> None:
            self.system = proxies is None
            super().__init__({} if proxies is None else proxies)

        def _route(self, req: Any) -> Any:
            if not self.system:
                return req
            try:
                plan = _proxy.plan(url=req.full_url)
            except _proxy.NoReachableProxyError as exc:
                raise URLError(exc) from exc
            if plan is None or plan.bypasses(req.full_url):
                return req
            if plan.endpoint is not None:
                if not req.full_url.startswith(plan.gateway_base or "\0"):
                    req.full_url = _proxy.prefix_url(req.full_url, plan.proxy, plan.endpoint)
                if plan.authorization:
                    req.add_unredirected_header(plan.auth_header, plan.authorization)
                return req
            if req.type == "https" and plan.authorization and plan.auth_header.lower() != "proxy-authorization":
                # urllib moves only Proxy-Authorization onto the CONNECT; any
                # other header would travel through the tunnel to the origin.
                raise URLError(
                    "%s cannot be sent to an https proxy by urllib; use requests or httpx" % plan.auth_header
                )
            parts = urlsplit(plan.proxy)
            req.set_proxy(parts.netloc, parts.scheme)
            if plan.authorization:
                req.add_unredirected_header(plan.auth_header, plan.authorization)
            return req

        http_request = _route
        https_request = _route

    SystemProxyHandler.__name__ = SystemProxyHandler.__qualname__ = "ProxyHandler"
    SystemProxyHandler.__module__ = request.__name__
    original_context = ssl._create_default_https_context  # type: ignore[attr-defined]
    setattr(request, "ProxyHandler", SystemProxyHandler)
    setattr(ssl, "_create_default_https_context", _default_https_context)

    def undo() -> None:
        setattr(request, "ProxyHandler", original_handler)
        setattr(ssl, "_create_default_https_context", original_context)

    return undo


# ---- httpx -------------------------------------------------------------------


def _patch_httpx(httpx: ModuleType) -> Callable[[], None]:
    """``httpx.Client`` and ``AsyncClient`` built without ``transport``,
    ``proxy`` or ``mounts`` (and with ``trust_env``) get a transport that
    routes each request by syshttp; ``verify`` left at ``True`` becomes the
    system's context."""

    def routed(request: Any, plan: Optional[_proxy.ProxyPlan]) -> Tuple[Any, Any]:
        """``(key, request)``: the inner transport to use and the request to
        send through it."""
        url = str(request.url)
        if plan is None or plan.bypasses(url):
            return None, request
        if plan.endpoint is None:
            return (plan.proxy, plan.auth_header, plan.authorization), request
        target = url if url.startswith(plan.gateway_base or "\0") else _proxy.prefix_url(url, plan.proxy, plan.endpoint)
        headers = [(k, v) for k, v in request.headers.raw if k.lower() != b"host"]
        if plan.authorization:
            headers.append((plan.auth_header.encode("latin-1"), plan.authorization.encode("latin-1")))
        rewritten = httpx.Request(
            request.method, target, headers=headers, stream=request.stream, extensions=request.extensions
        )
        return None, rewritten

    def proxy_for(key: Any) -> Any:
        url, header, authorization = key
        return httpx.Proxy(url, headers={header: authorization} if authorization else None)

    class SystemTransport(httpx.BaseTransport):  # type: ignore[misc, name-defined]
        def __init__(self, **kwargs: Any) -> None:
            self._kwargs = kwargs
            self._inner: Dict[Any, Any] = {}
            self._lock = threading.Lock()

        def _transport(self, key: Any) -> Any:
            with self._lock:
                if key not in self._inner:
                    proxy = None if key is None else proxy_for(key)
                    self._inner[key] = httpx.HTTPTransport(proxy=proxy, **self._kwargs)
                return self._inner[key]

        def handle_request(self, request: Any) -> Any:
            try:
                plan = _proxy.plan(url=str(request.url))
            except _proxy.NoReachableProxyError as exc:
                raise httpx.ProxyError(str(exc), request=request) from exc
            key, request = routed(request, plan)
            return self._transport(key).handle_request(request)

        def close(self) -> None:
            with self._lock:
                inner, self._inner = list(self._inner.values()), {}
            for transport in inner:
                transport.close()

    class AsyncSystemTransport(httpx.AsyncBaseTransport):  # type: ignore[misc, name-defined]
        def __init__(self, **kwargs: Any) -> None:
            self._kwargs = kwargs
            self._inner: Dict[Any, Any] = {}

        def _transport(self, key: Any) -> Any:
            if key not in self._inner:
                proxy = None if key is None else proxy_for(key)
                self._inner[key] = httpx.AsyncHTTPTransport(proxy=proxy, **self._kwargs)
            return self._inner[key]

        async def handle_async_request(self, request: Any) -> Any:
            import anyio

            # The system's answer can take a PAC evaluation or a probe: off the loop.
            try:
                plan = await anyio.to_thread.run_sync(functools.partial(_proxy.plan, url=str(request.url)))
            except _proxy.NoReachableProxyError as exc:
                raise httpx.ProxyError(str(exc), request=request) from exc
            key, request = routed(request, plan)
            return await self._transport(key).handle_async_request(request)

        async def aclose(self) -> None:
            inner, self._inner = list(self._inner.values()), {}
            for transport in inner:
                await transport.aclose()

    def wrap(client_class: Any, transport_class: Any) -> Callable[[], None]:
        original = client_class.__init__

        @functools.wraps(original)
        def __init__(self: Any, *args: Any, **kwargs: Any) -> None:
            if kwargs.get("verify", True) is True:
                kwargs["verify"] = _context(certificate=kwargs.get("cert") is not None)
            routed_by_caller = any(kwargs.get(k) is not None for k in ("transport", "proxy", "proxies", "mounts"))
            if not routed_by_caller and kwargs.get("trust_env", True):
                inner = {
                    k: kwargs[k] for k in ("verify", "cert", "http1", "http2", "limits", "trust_env") if k in kwargs
                }
                kwargs["transport"] = transport_class(**inner)
            original(self, *args, **kwargs)

        client_class.__init__ = __init__
        return lambda: setattr(client_class, "__init__", original)

    steps = [wrap(httpx.Client, SystemTransport), wrap(httpx.AsyncClient, AsyncSystemTransport)]

    def undo() -> None:
        for step in reversed(steps):
            step()

    return undo


# ---- aiohttp -----------------------------------------------------------------


def _patch_aiohttp(aiohttp: ModuleType) -> Callable[[], None]:
    """``ClientSession`` requests with no ``proxy=`` are routed by syshttp
    (aiohttp reads no proxy of its own unless ``trust_env``); ``ssl`` left at
    ``True`` with no other TLS argument becomes the system's context."""
    import asyncio

    session_class = aiohttp.ClientSession
    original = session_class._request

    @functools.wraps(original)
    async def _request(self: Any, method: str, str_or_url: Any, **kwargs: Any) -> Any:
        if kwargs.get("ssl", True) is True and all(
            kwargs.get(k) is None for k in ("ssl_context", "verify_ssl", "fingerprint")
        ):
            kwargs["ssl"] = _context()
        if kwargs.get("proxy") is None:
            build = getattr(self, "_build_url", None)
            url = str(build(str_or_url) if build is not None else str_or_url)
            loop = asyncio.get_running_loop()
            try:
                plan = await loop.run_in_executor(None, functools.partial(_proxy.plan, url=url))
            except _proxy.NoReachableProxyError as exc:
                raise aiohttp.ClientConnectionError(str(exc)) from exc
            if plan is not None and not plan.bypasses(url):
                if plan.endpoint is not None:
                    if not url.startswith(plan.gateway_base or "\0"):
                        str_or_url = _proxy.prefix_url(url, plan.proxy, plan.endpoint)
                    if plan.authorization:
                        kwargs["headers"] = {**dict(kwargs.get("headers") or {}), plan.auth_header: plan.authorization}
                else:
                    kwargs["proxy"] = plan.proxy
                    # aiohttp sends proxy_headers on the CONNECT only; a plain
                    # http request goes to the proxy itself, every hop of it.
                    where = "proxy_headers" if urlsplit(url).scheme == "https" else "headers"
                    if plan.authorization:
                        kwargs[where] = {**dict(kwargs.get(where) or {}), plan.auth_header: plan.authorization}
        return await original(self, method, str_or_url, **kwargs)

    session_class._request = _request
    return lambda: setattr(session_class, "_request", original)


_PATCHERS: Dict[str, Callable[[ModuleType], Callable[[], None]]] = {
    "requests": _patch_requests,
    "urllib": _patch_urllib,
    "httpx": _patch_httpx,
    "aiohttp": _patch_aiohttp,
}

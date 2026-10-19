"""Patch HTTP client libraries as they are imported, so they route and verify
the way syshttp does: routing by :func:`syshttp.proxy.proxy_map` through
proxylib's client integrations (``proxylib.patch``), and TLS by the system's
context (:func:`syshttp.tls.os_ssl_context`).

``SYSHTTP_IMPORTPATCH`` chooses the libraries -- ``<PREFIX>_SYSHTTP_IMPORTPATCH``
under a prefix of a tool's own (``SYSHTTP_PREFIX=AGENTS``:
``AGENTS_SYSHTTP_IMPORTPATCH``): ``1``/``true``/``yes``/``on`` for all of
:data:`TARGETS`, ``0``/``false``/``no``/``off``, empty or unset for none, else
their names separated by ``:`` (``requests:httpx``; a module name such as
``urllib.request`` works too). It is read when the library is imported:
importpatch (a dependency) calls :func:`importpatch` for each target, through
this distribution's ``importpatch`` entry points. :func:`patch` applies the
same patches from code, whatever the setting says.

What the caller chose always wins: a proxy given to the client, a context, a
CA bundle or ``verify=False``.
"""

from __future__ import annotations

import functools
import importlib
import logging
import ssl
import sys
import threading
import time
from types import ModuleType
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Optional, Tuple

# Neither proxylib nor syshttp.proxy is imported here: proxylib's own import
# of urllib.request runs this module's hook while proxylib is half built.
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
    "pip": "pip._vendor.requests",
}

_log = logging.getLogger(__name__)
_TRUE = ("1", "true", "yes", "on")
_FALSE = ("", "0", "false", "no", "off")
_BY_MODULE = {module: name for name, module in TARGETS.items()}
_lock = threading.RLock()
# name -> the functions that undo its patch, in the order applied.
_undo: Dict[str, List[Callable[[], None]]] = {}


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
    _flush()
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
    _flush()
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
    keeps what it was given; proxylib's integrations stay installed, back on
    proxylib's default map."""
    with _lock:
        for name in reversed(list(_undo)):
            for step in reversed(_undo.pop(name)):
                step()


def patched() -> Tuple[str, ...]:
    """The names patched now, in the order applied."""
    with _lock:
        return tuple(_undo)


def _apply(name: str, module: ModuleType) -> None:
    with _lock:
        if name in _undo:
            return
        steps: List[Callable[[], None]] = []
        if _initializing("proxylib") or _initializing("syshttp.proxy"):
            steps.append(_defer(name, module))
        else:
            # Before the TLS patch: syshttp's wrappers then run first and
            # hand proxylib's transports the system context.
            steps.extend(_route(name))
        tls = _TLS[name]
        if tls is not None:
            steps.append(tls(module))
        _undo[name] = steps


def _initializing(name: str) -> bool:
    """Whether module ``name`` is being imported right now (half built)."""
    module = sys.modules.get(name)
    return module is not None and bool(getattr(getattr(module, "__spec__", None), "_initializing", False))


def _context(certificate: bool = False) -> ssl.SSLContext:
    """The system's context; a fresh one offering no store certificate when
    the caller loads a certificate of its own into it."""
    from . import tls as _tls

    if certificate:
        return _tls.new_os_context(client_certificates=False)
    return _tls.os_ssl_context()


# ---- routing -----------------------------------------------------------------


def _route(name: str) -> List[Callable[[], None]]:
    """``proxylib.patch`` with syshttp's map for target ``name``; nothing
    when this proxylib has no such target."""
    import proxylib

    from . import proxy as _proxy

    if name not in proxylib.patching.targets():
        _log.debug("proxylib %s has no %r patch target: %s is not routed", proxylib.__version__, name, name)
        return []
    proxymap = _URLErrorMap(_proxy.proxy_map()) if name == "urllib" else _proxy.proxy_map()
    return [proxylib.patch(proxymap, targets=[name]).undo]


# Targets whose routing waits for proxylib to finish importing -> their undo
# steps once routed (None until then).
_pending: Dict[str, Optional[List[Callable[[], None]]]] = {}


def _defer(name: str, module: ModuleType) -> Callable[[], None]:
    """Route ``name`` once proxylib is importable: at the next patch, or for
    urllib (the only client proxylib imports itself) at the first
    ``urlopen``, the call proxylib's urllib integration serves."""
    _pending[name] = None
    undo_opener: Callable[[], None] = lambda: None
    if name == "urllib":
        original = getattr(module, "urlopen")

        @functools.wraps(original)
        def urlopen(*args: Any, **kwargs: Any) -> Any:
            _flush()
            return original(*args, **kwargs)

        setattr(module, "urlopen", urlopen)
        undo_opener = lambda: setattr(module, "urlopen", original)  # noqa: E731

    def undo() -> None:
        undo_opener()
        for step in reversed(_pending.pop(name, None) or []):
            step()

    return undo


def _flush() -> None:
    """Route every deferred target, once proxylib can be used."""
    if not _pending or _initializing("proxylib") or _initializing("syshttp.proxy"):
        return
    with _lock:
        for name, steps in list(_pending.items()):
            if steps is None:
                _pending[name] = _route(name)


class _URLErrorMap:
    """urllib sends through one proxy: the first reachable one (``Probed``),
    with none reachable reported as urllib reports a connection failure."""

    def __init__(self, inner: Any) -> None:
        import proxylib

        self.inner = proxylib.Probed(inner)

    def __getitem__(self, url: str) -> Any:
        from urllib.error import URLError

        import proxylib

        try:
            return proxylib.lookup(self.inner, url)
        except proxylib.NoReachableProxyError as exc:
            raise URLError(exc) from exc


# ---- TLS: requests -----------------------------------------------------------


def _tls_requests(requests: ModuleType) -> Callable[[], None]:
    """Every ``HTTPAdapter`` -- proxylib's included -- verifies an https
    origin with the system's context when ``verify`` is ``True`` and the
    adapter's pool manager was given no context of its own."""
    adapter_class = requests.adapters.HTTPAdapter
    original_key = getattr(adapter_class, "build_connection_pool_key_attributes", None)
    if original_key is None:
        _log.debug("requests %s has no pool-key hook: its own verification stays", requests.__version__)
        return lambda: None
    original_verify = adapter_class.cert_verify

    def ours(adapter: Any, url: str, verify: Any) -> bool:
        pool = getattr(adapter, "poolmanager", None)
        own = getattr(pool, "connection_pool_kw", {}).get("ssl_context")
        return verify is True and own is None and url.lower().startswith("https")

    @functools.wraps(original_key)
    def build_connection_pool_key_attributes(self: Any, request: Any, verify: Any, cert: Any = None) -> Any:
        host_params, pool_kwargs = original_key(self, request, verify, cert)
        if ours(self, request.url or "", verify) and "ssl_context" not in pool_kwargs:
            pool_kwargs["ssl_context"] = _context()
        return host_params, pool_kwargs

    @functools.wraps(original_verify)
    def cert_verify(self: Any, conn: Any, url: str, verify: Any, cert: Any) -> None:
        if ours(self, url, verify):
            # No CA file: urllib3 would load it into the shared system context.
            original_verify(self, conn, url, False, cert)
            conn.cert_reqs = "CERT_REQUIRED"
            return
        original_verify(self, conn, url, verify, cert)

    setattr(adapter_class, "build_connection_pool_key_attributes", build_connection_pool_key_attributes)
    setattr(adapter_class, "cert_verify", cert_verify)

    def undo() -> None:
        setattr(adapter_class, "build_connection_pool_key_attributes", original_key)
        setattr(adapter_class, "cert_verify", original_verify)

    return undo


# ---- TLS: urllib -------------------------------------------------------------

# One context for http.client's default: it sets ALPN on the context it is
# handed, so it does not share the requests session's.
_https_context: "Optional[ssl.SSLContext]" = None
_https_context_at = 0.0


def _default_https_context() -> ssl.SSLContext:
    global _https_context, _https_context_at
    from . import tls as _tls

    with _lock:
        now = time.monotonic()
        if _https_context is None or now - _https_context_at > _tls.OS_CONTEXT_MAX_AGE:
            _https_context = _tls.new_os_context()
            _https_context_at = now
        return _https_context


def _tls_urllib(request: ModuleType) -> Callable[[], None]:
    """``http.client``'s default HTTPS context (``ssl._create_default_https_context``)
    becomes the system's, for urllib and every other caller that gives none."""
    original = ssl._create_default_https_context  # type: ignore[attr-defined]
    setattr(ssl, "_create_default_https_context", _default_https_context)
    return lambda: setattr(ssl, "_create_default_https_context", original)


# ---- TLS: httpx --------------------------------------------------------------


def _tls_httpx(httpx: ModuleType) -> Callable[[], None]:
    """``httpx.Client`` / ``AsyncClient`` built with ``verify`` left at
    ``True`` verify with the system's context (a fresh one offering no store
    certificate when ``cert=`` is given)."""

    def wrap(client_class: Any) -> Callable[[], None]:
        original = client_class.__init__

        @functools.wraps(original)
        def __init__(self: Any, *args: Any, **kwargs: Any) -> None:
            if kwargs.get("verify", True) is True:
                kwargs["verify"] = _context(certificate=kwargs.get("cert") is not None)
            original(self, *args, **kwargs)

        client_class.__init__ = __init__
        return lambda: setattr(client_class, "__init__", original)

    steps = [wrap(httpx.Client), wrap(httpx.AsyncClient)]

    def undo() -> None:
        for step in reversed(steps):
            step()

    return undo


# ---- TLS: aiohttp ------------------------------------------------------------


def _tls_aiohttp(aiohttp: ModuleType) -> Callable[[], None]:
    """``ClientSession`` requests with ``ssl`` left at ``True`` and no
    ``ssl_context`` / ``verify_ssl`` / ``fingerprint`` verify with the
    system's context."""
    session_class = aiohttp.ClientSession
    original = session_class._request

    @functools.wraps(original)
    async def _request(self: Any, method: str, str_or_url: Any, **kwargs: Any) -> Any:
        if kwargs.get("ssl", True) is True and all(
            kwargs.get(k) is None for k in ("ssl_context", "verify_ssl", "fingerprint")
        ):
            kwargs["ssl"] = _context()
        return await original(self, method, str_or_url, **kwargs)

    session_class._request = _request
    return lambda: setattr(session_class, "_request", original)


_TLS: Dict[str, Optional[Callable[[ModuleType], Callable[[], None]]]] = {
    "requests": _tls_requests,
    "urllib": _tls_urllib,
    "httpx": _tls_httpx,
    "aiohttp": _tls_aiohttp,
    # pip verifies with its own truststore context, which is kept.
    "pip": None,
}

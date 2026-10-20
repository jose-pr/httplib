"""Which TLS context a connection is made with: the caller's, a CA bundle, the
system's, or none that verifies."""

from __future__ import annotations

import os as _os
import ssl as _ssl
import threading as _threading

from .. import tls as _tls
from ..env import HTTPEnv
from ..exceptions import ConfigurationError

CA_BUNDLE = "CA_BUNDLE"
"""The setting naming a CA bundle (a PEM file) that replaces the system's trust
store for origins when verification is on and the caller gave no context."""

_VERIFIED: "dict[tuple[str, int], _ssl.SSLContext]" = {}
_UNVERIFIED: "list[_ssl.SSLContext]" = []
_LOCK = _threading.Lock()


def _unverified_context() -> "_ssl.SSLContext":
    """One context that accepts any certificate, for `verify=False`."""
    with _LOCK:
        if not _UNVERIFIED:
            context = _ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = _ssl.CERT_NONE
            _UNVERIFIED.append(context)
        return _UNVERIFIED[0]


def _bundle_context(path: str, source: str) -> "_ssl.SSLContext":
    """A context trusting only the PEM file `path`, shared and renewed when the
    file changes. `source` is what a message names: the variable or argument
    that gave the path."""
    try:
        key = (_os.path.abspath(path), _os.stat(path).st_mtime_ns)
        with _LOCK:
            context = _VERIFIED.get(key)
        if context is None:
            context = _tls.new_os_context(cafile=path, client_certificates=False)
            with _LOCK:
                for stale in [k for k in _VERIFIED if k[0] == key[0]]:
                    del _VERIFIED[stale]
                _VERIFIED[key] = context
        return context
    except (OSError, _ssl.SSLError) as error:
        raise ConfigurationError(
            "%s names a CA bundle that cannot be read (%s)" % (source, type(error).__name__)
        ) from None


class TLSChoice:
    """The TLS settings of one transport.

    `ssl_context` is used as given for every https origin, and its own
    `verify_mode` decides, so `verify` must stay `True` beside it. Without one,
    `verify=True` verifies with the CA bundle `CA_BUNDLE` names (read through
    `env` at each connection) and else with the system's context, `verify=False`
    verifies nothing, and a path as `verify` names a bundle. `proxy_ssl_context`
    is what an `https:` proxy or gateway is spoken to with; without it, the
    system's context."""

    def __init__(
        self,
        env: HTTPEnv,
        ssl_context: "_ssl.SSLContext | None",
        proxy_ssl_context: "_ssl.SSLContext | None",
        verify: "bool | str | _os.PathLike[str]",
    ):
        for name, value in (("ssl_context", ssl_context), ("proxy_ssl_context", proxy_ssl_context)):
            if value is not None and not isinstance(value, _ssl.SSLContext):
                raise TypeError("%s must be an ssl.SSLContext, not %s" % (name, type(value).__name__))
        if not isinstance(verify, (bool, str, _os.PathLike)):
            raise TypeError("verify is True, False or the path of a CA bundle, not %s" % type(verify).__name__)
        if ssl_context is not None and verify is not True:
            raise ValueError("verify=%r and ssl_context contradict: the context's verify_mode decides" % (verify,))
        self._env = env
        self._ssl_context = ssl_context
        self._proxy_ssl_context = proxy_ssl_context
        self._verify: "bool | str" = verify if isinstance(verify, bool) else _os.fspath(verify)

    @property
    def unverified(self) -> bool:
        """Whether this transport turns certificate checking off for origins."""
        return self._ssl_context is None and self._verify is False

    def origin(self) -> "_ssl.SSLContext":
        """The context for an https origin."""
        if self._ssl_context is not None:
            return self._ssl_context
        if self._verify is False:
            return _unverified_context()
        if isinstance(self._verify, str):
            return _bundle_context(self._verify, "verify")
        found = self._env.find(CA_BUNDLE)
        if found is not None:
            return _bundle_context(found[1], found[0])
        return _tls.os_ssl_context()

    def proxy(self) -> "_ssl.SSLContext":
        """The context for an `https:` proxy or gateway."""
        if self._proxy_ssl_context is not None:
            return self._proxy_ssl_context
        return _tls.os_ssl_context()

"""The OS trust store as an ``SSLContext`` -- what the requests session
(``session``) and a curl front end both verify servers against.

With neither ``cafile`` nor ``capath`` the context is a
``truststore.SSLContext``: certificates are verified by the operating
system's own verifier -- CryptoAPI on Windows, the Security framework on
macOS, OpenSSL over the system's store elsewhere -- so intermediate fetching,
enterprise roots and policy apply as they do for the system's own clients.
truststore needs Python 3.10; on 3.9 the context is
``ssl.create_default_context()``, which loads the certificate store on
Windows and OpenSSL's system defaults (``SSL_CERT_FILE`` / ``SSL_CERT_DIR``
included) elsewhere. A ``cafile`` / ``capath`` replaces the store: a plain
``ssl`` context trusting only them. No ``certifi`` bundle is involved."""

from __future__ import annotations

import ssl
import time
from typing import Optional

try:  # Python >= 3.10, where the dependency is installed
    import truststore
except ImportError:  # pragma: no cover - exercised on 3.9
    truststore = None  # type: ignore[assignment]

#: How long the shared context is reused (seconds) before it is rebuilt, so a
#: certificate added to the system store is picked up.
OS_CONTEXT_MAX_AGE = 60
_os_context: "Optional[ssl.SSLContext]" = None
_os_context_at = 0.0


def new_os_context(cafile: Optional[str] = None, capath: Optional[str] = None) -> "ssl.SSLContext":
    """A fresh verifying client context: on ``cafile`` / ``capath`` when given
    (they replace the OS store), else the OS trust store, verified by the OS
    (truststore) where available. Fresh, so a caller may load a client
    certificate into it."""
    if cafile or capath or truststore is None:
        return ssl.create_default_context(cafile=cafile, capath=capath)
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def os_ssl_context() -> "ssl.SSLContext":
    """An ``SSLContext`` verifying against the OS trust store, shared for
    :data:`OS_CONTEXT_MAX_AGE` seconds. Shared, because urllib3 keys its
    connection pools by the context object: one per request would never reuse
    a connection. Never load a client certificate into it: use
    :func:`new_os_context`."""
    global _os_context, _os_context_at
    now = time.monotonic()
    if _os_context is None or now - _os_context_at > OS_CONTEXT_MAX_AGE:
        _os_context = new_os_context()
        _os_context_at = now
    return _os_context

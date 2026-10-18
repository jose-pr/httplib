"""The OS trust store as an ``SSLContext`` -- what the requests session
(``session``) and the curl fallback (``cli``) both verify servers against.
``ssl.create_default_context()`` loads the certificate store on Windows and
OpenSSL's system defaults elsewhere (``SSL_CERT_FILE`` / ``SSL_CERT_DIR``
included), so no ``certifi`` bundle is involved. Dependency-free."""
from __future__ import annotations

import ssl
import time
from typing import Optional

#: How long the shared context is reused (seconds) before it is rebuilt, so a
#: certificate added to the system store is picked up.
OS_CONTEXT_MAX_AGE = 60
_os_context: "Optional[ssl.SSLContext]" = None
_os_context_at = 0.0


def new_os_context(cafile: Optional[str] = None, capath: Optional[str] = None) -> "ssl.SSLContext":
    """A fresh verifying context: on ``cafile`` / ``capath`` when given (they
    replace the OS store), else the OS trust store. Fresh, so a caller may
    load a client certificate into it."""
    return ssl.create_default_context(cafile=cafile, capath=capath)


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

"""The system's TLS client as an ``SSLContext`` -- what the requests session
(``session``) and a curl front end both connect with.

With neither ``cafile`` nor ``capath`` the context is
``sslcontext.system_context()``: certificates are verified by the operating
system's own verifier on Python 3.10+ (CryptoAPI on Windows, the Security
framework on macOS, OpenSSL over the system's store elsewhere), so
intermediate fetching, enterprise roots and policy apply as they do for the
system's own clients; on 3.9 by OpenSSL over the default store. A server that
asks for a client certificate gets one from the OS store (Windows Personal
store and smart cards, the macOS keychains, the default PKCS#11 module), chosen
as a browser chooses, or none. A ``cafile`` / ``capath`` replaces the store: a
plain ``ssl`` context trusting only them. No ``certifi`` bundle is involved."""

from __future__ import annotations

import ssl
import time
from typing import Optional

import sslcontext

#: How long the shared context is reused (seconds) before it is rebuilt, so a
#: certificate added to the system store is picked up.
OS_CONTEXT_MAX_AGE = 60
_os_context: "Optional[ssl.SSLContext]" = None
_os_context_at = 0.0


def new_os_context(
    cafile: Optional[str] = None, capath: Optional[str] = None, *, client_certificates: bool = True
) -> "ssl.SSLContext":
    """A fresh verifying client context: on ``cafile`` / ``capath`` when given
    (they replace the OS store), else the system's (``sslcontext.system_context``).
    ``client_certificates=False`` never offers a certificate from the OS store:
    pass it before loading a client certificate of your own, which a store
    certificate would otherwise replace."""
    if cafile or capath:
        return ssl.create_default_context(cafile=cafile, capath=capath)
    return sslcontext.system_context(selector=None if client_certificates else False)


def os_ssl_context() -> "ssl.SSLContext":
    """The system's ``SSLContext`` (:func:`new_os_context`), shared for
    :data:`OS_CONTEXT_MAX_AGE` seconds. Shared, because urllib3 keys its
    connection pools by the context object: one per request would never reuse
    a connection. Never load a client certificate into it: use
    :func:`new_os_context` with ``client_certificates=False``."""
    global _os_context, _os_context_at
    now = time.monotonic()
    if _os_context is None or now - _os_context_at > OS_CONTEXT_MAX_AGE:
        _os_context = new_os_context()
        _os_context_at = now
    return _os_context

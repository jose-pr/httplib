"""The route of a request: what the proxy map answers, narrowed to the entries
the transport speaks and to the first one that is reachable."""

from __future__ import annotations

import base64 as _base64
import typing as _ty

import proxylib

DEFAULT_PORTS = {"http": 80, "https": 443, "prefix+http": 80, "prefix+https": 443}
"""The proxy schemes the transport speaks, and their ports."""

PROBE_TIMEOUT = 5.0
"""Most seconds spent finding out whether one proxy of an answer accepts a
connection."""

Entry = _ty.Optional["proxylib.Proxy"]


def entries(proxymap: _ty.Any, url: str) -> "tuple[Entry, ...]":
    """The entries of `proxymap`'s answer for `url` that the transport can use,
    in order (`None` is a direct connection); `(None,)` when the map has no
    opinion. `proxylib.UnsupportedProxyError` when it names only proxies the
    transport cannot speak (SOCKS)."""
    try:
        answer = proxylib.lookup(proxymap, url)
    except KeyError:
        return (None,)
    usable = tuple(entry for entry in answer if entry is None or entry.scheme in DEFAULT_PORTS)
    if usable:
        return usable
    raise proxylib.UnsupportedProxyError(
        "syshttp.client",
        [(entry, "only http and https proxies and URL-prefix gateways are spoken") for entry in answer],
    )


def reachable(candidates: "tuple[Entry, ...]", url: str, connect_timeout: "float | None") -> Entry:
    """The first of `candidates` that accepts a TCP connection (a direct entry
    always does). `proxylib.NoReachableProxyError` when none does."""
    timeout = PROBE_TIMEOUT if connect_timeout is None else min(connect_timeout, PROBE_TIMEOUT)
    return proxylib.lookup(proxylib.Probed(proxylib.SimpleProxyMap(candidates), timeout=timeout), url)[0]


def port(proxy: "proxylib.Proxy") -> int:
    """The port a connection to `proxy` is made to."""
    return proxy.port or DEFAULT_PORTS[proxy.scheme]


def credentials(proxy: "proxylib.Proxy") -> "list[tuple[str, str]]":
    """The headers a request to `proxy` carries for it: its own headers, and
    its userinfo as Basic `Proxy-Authorization` unless one is among them. A
    value that is not ASCII is `ValueError`, without the value."""
    found = list(proxy.headers.items())
    if proxy.username is not None and not any(name.lower() == "proxy-authorization" for name, _ in found):
        token = f"{proxy.username}:{proxy.password or ''}".encode("utf-8")
        found.append(("Proxy-Authorization", "Basic " + _base64.b64encode(token).decode("ascii")))
    for name, value in found:
        if not value.isascii():
            raise ValueError(f"the value of the proxy header {name} is not ASCII")
    return found

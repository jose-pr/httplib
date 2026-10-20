"""What a client remembers between requests: the cookies of every host it talked
to, kept in memory and, with a jar, on disk by host; and the tokens that become
`Authorization` headers.

Both are chosen by the host of the URL being requested -- the origin -- never
by a proxy's or a gateway's: they sit above the transport."""

from __future__ import annotations

import dataclasses as _dataclasses
import ipaddress as _ipaddress
import re as _re
import threading as _threading
import time as _time
import typing as _ty
import urllib.parse as _urlparse

from ..cookies import CookieSpec, cookie_applies, domain_covers, host_aliases, set_cookie_specs
from ..env import HTTPEnv
from ..exceptions import ConfigurationError
from ..jar import CookieJar, FileCookieJar, FileTokenJar, TokenJar
from ._headers import has_header

COOKIE_HOSTS = "SYSHTTP_COOKIE_HOSTS"
"""The setting declaring hosts that share cookies: hosts split by `,`, groups
by `;`."""

BY_HOST = "__by_host__"
"""The jar key that means: the origin's host, its alias group's first host."""


def cookie_aliases(cookie_hosts: "_ty.Iterable[_ty.Iterable[str]] | None", env: HTTPEnv) -> "dict[str, str]":
    """`cookie_hosts`, else `SYSHTTP_COOKIE_HOSTS`, as `cookies.host_aliases`
    maps them."""
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


def _is_ip(host: str) -> bool:
    try:
        _ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _with_host(url: str, host: str) -> str:
    """`url` with its host replaced by `host`, port kept."""
    parts = _urlparse.urlsplit(url)
    netloc = "[%s]" % host if ":" in host else host
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is not None:
        netloc += ":%d" % port
    return _urlparse.urlunsplit(parts._replace(netloc=netloc))


class Cookies:
    """The cookies of one client.

    Rows are `CookieSpec`s, set from `Set-Cookie` as RFC 6265 reads it
    (`set_cookie_specs`) and sent as `cookie_applies` decides. With a `jar`, the
    rows of a host are loaded from it the first time that host is asked for,
    and written back only when they differ from what was loaded or written
    last. `key` is `BY_HOST` (one entry per origin host) or one name for every
    host. `aliases` (`host_aliases`) makes groups of hosts one."""

    def __init__(self, jar: "CookieJar | None", key: str, aliases: "_ty.Mapping[str, str]"):
        self._jar = jar
        self._key = key
        self._aliases = dict(aliases)
        self._group_of: "dict[str, list[str]]" = {}
        for alias, first in self._aliases.items():
            self._group_of.setdefault(first, []).append(alias)
        self._rows: "dict[tuple[str, str, str], CookieSpec]" = {}
        self._loaded: "set[str]" = set()
        self._synced: "dict[str, frozenset[CookieSpec]]" = {}
        self._lock = _threading.RLock()

    # -- which hosts and keys a URL means

    def _host(self, url: str) -> str:
        """The host cookies of `url` are kept under: its alias group's first."""
        host = _urlparse.urlsplit(url).hostname or ""
        return self._aliases.get(host.lower(), host)

    def _keys(self, url: str) -> "list[str]":
        if self._key != BY_HOST:
            return [self._key]
        host = self._host(url)
        return [host] if host else []

    def _urls(self, url: str) -> "list[str]":
        """`url`, and the same URL for every other host of its alias group."""
        host = (_urlparse.urlsplit(url).hostname or "").lower()
        first = self._aliases.get(host)
        if first is None:
            return [url]
        return [url] + [_with_host(url, member) for member in self._group_of[first] if member != host]

    # -- the rows

    def _load(self, rows: "_ty.Iterable[CookieSpec]") -> None:
        for row in rows:
            bare = row.domain.lstrip(".").lower()
            if not bare:
                continue
            # An IP address matches only itself, whatever the flag says.
            subdomains = bool((row.subdomains or row.domain.startswith(".")) and not _is_ip(bare))
            spec = _dataclasses.replace(
                row, domain=bare, subdomains=subdomains, path=row.path or "/", expires=row.expires or None
            )
            self._rows[(bare, spec.path, spec.name)] = spec

    @staticmethod
    def _covers(row: CookieSpec, host: str) -> bool:
        # A row's domain is bare; its include-subdomains flag is the dot.
        return domain_covers("." + row.domain if row.subdomains else row.domain, host)

    def _rows_for(self, key: str, host: str) -> "list[CookieSpec]":
        """The rows written under `key`: a by-host key keeps only the rows
        whose domain covers its host (or group), so a client that talked to two
        hosts never copies one's cookies into the other's file; a named key keeps
        everything."""
        rows = list(self._rows.values())
        if key != host:
            return rows
        hosts = self._group_of.get(key, [key])
        return [row for row in rows if any(self._covers(row, h) for h in hosts)]

    # -- what a hop does

    def before(self, url: str) -> None:
        """Loads the jar's rows for the keys of `url` that were not yet loaded."""
        if self._jar is None:
            return
        with self._lock:
            for key in self._keys(url):
                if key in self._loaded:
                    continue
                try:
                    self._load(self._jar.get(key, []))
                except Exception:
                    pass  # an unreadable jar is an empty one
                self._synced[key] = frozenset(self._rows_for(key, self._host(url)))
                self._loaded.add(key)

    def header(self, url: str, now: "float | None" = None) -> "str | None":
        """The `Cookie` header for a request to `url`, or `None`. Longer paths
        come first (RFC 6265 5.4)."""
        moment = _time.time() if now is None else now
        urls = self._urls(url)
        with self._lock:
            chosen = [row for row in self._rows.values() if any(cookie_applies(row, u, moment) for u in urls)]
        chosen.sort(key=lambda row: -len(row.path))
        return "; ".join("%s=%s" % (row.name, row.value) for row in chosen) or None

    def store(self, url: str, values: "_ty.Iterable[str]") -> None:
        """Keeps the cookies of `Set-Cookie` `values` a response from `url` sent,
        deletes the ones it expires, and writes the jar when rows changed."""
        parts = _urlparse.urlsplit(url)
        found = set_cookie_specs(values, parts.hostname or "", request_path=parts.path or "/", aliases=self._aliases)
        with self._lock:
            for spec, gone in found:
                key = (spec.domain, spec.path, spec.name)
                if gone:
                    self._rows.pop(key, None)
                else:
                    self._rows[key] = spec
            self._write(url)

    def _write(self, url: str) -> None:
        if self._jar is None:
            return
        host = self._host(url)
        for key in self._keys(url):
            rows = self._rows_for(key, host)
            state = frozenset(rows)
            if self._synced.get(key) == state:
                continue
            try:
                self._jar[key] = rows
            except Exception:
                continue
            self._synced[key] = state


class Tokens:
    """The tokens of one client: `Authorization` values chosen by the origin's
    host, or one key for every host. A secret: never logged or put in a
    message."""

    def __init__(self, jar: TokenJar, key: str):
        self._jar = jar
        self._key = key

    def authorization(self, url: str) -> "str | None":
        """The `Authorization` value for `url`'s host, or `None`. A token that
        already names its scheme (`Basic ...`, `token ...`) is sent verbatim; a
        bare one is a bearer token. One with a CR, LF or NUL is a
        `ConfigurationError` naming the key, never the value."""
        key = self._key if self._key != BY_HOST else (_urlparse.urlsplit(url).hostname or "")
        if not key:
            return None
        try:
            token = self._jar.get(key)
        except Exception:
            return None
        if not token:
            return None
        token = str(token).strip()
        if any(ch in token for ch in "\r\n\0"):
            raise ConfigurationError("the token for %r contains a carriage return, line feed or NUL character" % key)
        return token if _re.match(r"^[A-Za-z][\w-]*\s+\S", token) else "Bearer " + token


def make_cookies(cookies: "bool | str | CookieJar | None", env: HTTPEnv, aliases: "_ty.Mapping[str, str]") -> Cookies:
    """The `cookies=` argument of a client as its `Cookies`: `True` is a file
    jar under the state directory keyed by host, a string one key for every
    host, a jar object is used as given, `False` or `None` keeps cookies in
    memory only."""
    if cookies is True:
        return Cookies(FileCookieJar(env=env), BY_HOST, aliases)
    if isinstance(cookies, str):
        return Cookies(FileCookieJar(env=env), cookies, aliases)
    if cookies is None or cookies is False:
        return Cookies(None, BY_HOST, aliases)
    return Cookies(cookies, BY_HOST, aliases)  # `is not False`, not truthiness: an empty jar is a jar


def make_tokens(tokens: "bool | str | TokenJar | None", env: HTTPEnv) -> "Tokens | None":
    """The `tokens=` argument of a client as its `Tokens`, read as `cookies=`
    is; `None` for no tokens."""
    if tokens is True:
        return Tokens(FileTokenJar(env=env), BY_HOST)
    if isinstance(tokens, str):
        return Tokens(FileTokenJar(env=env), tokens)
    if tokens is None or tokens is False:
        return None
    return Tokens(tokens, BY_HOST)


class StateTransport:
    """A transport as the client sends through it: the cookies for each URL go
    with the request and the ones the response sets are kept. The transport it
    wraps stays the caller's."""

    def __init__(self, transport: _ty.Any, cookies: Cookies):
        self._transport = transport
        self._cookies = cookies

    def send(
        self,
        method: str,
        url: str,
        *,
        headers: "_ty.Mapping[str, str]",
        body: _ty.Any = None,
        timeout: _ty.Any,
        stream: bool = False,
    ) -> _ty.Any:
        sent = headers
        self._cookies.before(url)
        if not has_header(headers, "Cookie"):
            cookie = self._cookies.header(url)
            if cookie is not None:
                sent = dict(headers)
                sent["Cookie"] = cookie
        response = self._transport.send(method, url, headers=sent, body=body, timeout=timeout, stream=stream)
        values = response.headers.get_all("Set-Cookie")
        if values:
            self._cookies.store(url, values)
        return response

    def close(self) -> None:
        """Nothing of its own: the transport it wraps is closed by whoever made it."""

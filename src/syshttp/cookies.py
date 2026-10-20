"""Netscape cookie-file I/O and curl's cookie rules: ``CookieSpec``,
``load_netscape``, ``save_netscape``, ``cookie_applies``, ``set_cookie_specs``
and the host groups of ``host_aliases``. The client keeps its cookies as these
rows; a curl front end's ``-b`` / ``-c`` run on them too."""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Protocol, Tuple
from urllib.parse import urlparse

from ._fileio import read_text, write_private
from ._parse import ascii_int, http_date

__all__ = (
    "CookieLike",
    "CookieSpec",
    "HTTP_ONLY_PREFIX",
    "MAX_COOKIE_AGE",
    "cookie_applies",
    "domain_covers",
    "host_aliases",
    "load_netscape",
    "save_netscape",
    "set_cookie_specs",
)


class CookieLike(Protocol):
    """What :func:`save_netscape` reads off a cookie: a ``CookieSpec``, an
    ``http.cookiejar.Cookie`` or any object with these attributes."""

    @property
    def domain(self) -> str: ...
    @property
    def path(self) -> str: ...
    @property
    def secure(self) -> bool: ...
    @property
    def expires(self) -> Optional[int]: ...
    @property
    def name(self) -> str: ...
    @property
    def value(self) -> str: ...


@dataclass(frozen=True)
class CookieSpec:
    domain: str
    path: str
    secure: bool
    expires: Optional[int]
    name: str
    value: str
    #: Written as curl writes it: the domain field prefixed ``#HttpOnly_``.
    http_only: bool = False
    #: The Netscape include-subdomains flag (``TRUE``), for a domain written
    #: without the leading dot that says the same.
    subdomains: bool = False


HTTP_ONLY_PREFIX = "#HttpOnly_"

#: What no cookie name or value may hold (RFC 6265bis 5.6): the controls but
#: the tab. A header that holds one is ignored, and a row that holds one is
#: neither read nor written, so a value cannot end a line of a jar file.
_CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
#: What a jar file's row cannot carry in a field: every control, the tab (the
#: separator) included.
_UNSAFE_FIELD = re.compile(r"[\x00-\x1f\x7f]")


def load_netscape(path: Path) -> List[CookieSpec]:
    """The rows of the Netscape cookie file ``path`` (``[]`` when it is
    missing). Lines end at ``\\n`` only, one trailing ``\\r`` taken off, and a
    row whose name or value holds a control character is skipped: other
    characters ``str.splitlines`` honours (``\\x0b``, ``\\x0c``, ``\\x85``) are
    part of a value, not the end of a row."""
    try:
        text = read_text(path)
    except FileNotFoundError:
        return []
    cookies: List[CookieSpec] = []
    for line in text.split("\n"):
        if line.endswith("\r"):
            line = line[:-1]
        # Only the leading blanks go: a trailing tab separates an empty value.
        line = line.lstrip(" ")
        # curl writes an HttpOnly cookie's domain as `#HttpOnly_<domain>`; any
        # other `#` line is a comment.
        if not line.strip() or (line.startswith("#") and not line.startswith(HTTP_ONLY_PREFIX)):
            continue
        parts = line.split("\t")
        if len(parts) == 6:  # an editor trimmed the empty value's tab
            parts.append("")
        if len(parts) < 7:
            continue
        domain, flag, cpath, secure, expires, name, value = parts[:7]
        if _CONTROL.search(name) or _CONTROL.search(value):
            continue
        http_only = domain.startswith(HTTP_ONLY_PREFIX)
        if http_only:
            domain = domain[len(HTTP_ONLY_PREFIX) :]
        cookies.append(
            CookieSpec(
                domain=domain,
                path=cpath or "/",
                secure=secure.strip().upper() == "TRUE",
                # `0` is how the format writes a session cookie: no expiry.
                expires=ascii_int(expires) or None,
                name=name,
                value=value,
                http_only=http_only,
                subdomains=flag.strip().upper() == "TRUE",
            )
        )
    return cookies


#: Hosts curl treats as a secure context: ``Secure`` cookies go to them over
#: plain http too.
_SECURE_HOSTS = ("localhost", "127.0.0.1", "::1")


def _path_matches(cookie_path: str, path: str) -> bool:
    """RFC 6265 path-match: ``/admin`` covers ``/admin`` and ``/admin/x``,
    not ``/adminx``."""
    if path == cookie_path or cookie_path == "/":
        return True
    return path.startswith(cookie_path) and (cookie_path.endswith("/") or path[len(cookie_path)] == "/")


def cookie_applies(cookie: CookieSpec, url: str, now: Optional[float] = None) -> bool:
    """Does ``cookie`` go with a request to ``url``, as curl decides: the
    domain (the host itself, or a subdomain for a leading dot or the
    include-subdomains flag -- never for an IP address, which only matches
    itself), the path (RFC 6265 path-match), ``Secure`` only over https or to
    localhost / a loopback address, and not expired (``0`` / ``None`` is a
    session cookie)."""
    parts = urlparse(url)
    host = (parts.hostname or "").lower()
    domain = cookie.domain
    try:
        ipaddress.ip_address(host)
        if domain.lstrip(".").lower() != host:
            return False
    except ValueError:
        if cookie.subdomains and not domain.startswith("."):
            domain = "." + domain
        if not domain_covers(domain, host):
            return False
    if not _path_matches(cookie.path or "/", parts.path or "/"):
        return False
    if cookie.secure and parts.scheme != "https" and host not in _SECURE_HOSTS:
        return False
    if cookie.expires and cookie.expires <= (time.time() if now is None else now):
        return False
    return True


#: Longest lifetime a cookie keeps (RFC 6265bis section 5.5): a later expiry is
#: cut to it.
MAX_COOKIE_AGE = 400 * 24 * 3600

#: Second-level labels under a two-letter country code that are registries,
#: not owners (``co.uk``): the list ``http.cookiejar`` uses.
_REGISTRY_LABELS = frozenset(
    "co ac com edu org net gov mil int aero biz cat coop info jobs mobi museum name pro travel eu".split()
)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _is_public_suffix(domain: str) -> bool:
    """A domain no site owns, judged without the Public Suffix List: a top
    level domain (no dot, which makes ``localhost`` one) or a registry under a
    country code (``co.uk``). Others (``github.io``) are not recognised."""
    labels = domain.split(".")
    return len(labels) == 1 or (len(labels) == 2 and labels[0] in _REGISTRY_LABELS and len(labels[1]) == 2)


def _cookie_domain(host: str, attribute: Optional[str]) -> Optional[Tuple[str, bool]]:
    """RFC 6265 section 5.3 steps 4-6: ``(domain, subdomains)`` for a cookie
    set by ``host`` with the Domain ``attribute``, or ``None`` to drop it. No
    attribute, an IP host, and a public-suffix Domain equal to the host
    (``localhost``) give a host-only cookie."""
    host = host.lower()
    domain = (attribute or "").strip()
    domain = (domain[1:] if domain.startswith(".") else domain).lower()
    if not domain:
        return host, False
    if _is_ip(host):
        return (host, False) if domain == host else None
    if "" in domain.split(".") or _is_ip(domain):
        return None
    if host != domain and not host.endswith("." + domain):
        return None
    if _is_public_suffix(domain):
        return (host, False) if domain == host else None
    return domain, True


_HOST_NAME = re.compile(r"[a-z0-9_-]+(\.[a-z0-9_-]+)*")


def _normal_host(host: str) -> str:
    """``host`` as the alias table keys it: lower case, without IPv6 brackets
    or a trailing dot."""
    host = host.strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host[:-1] if host.endswith(".") else host


def host_aliases(groups: Iterable[Iterable[str]]) -> Dict[str, str]:
    """Each host of ``groups`` mapped to its group's first host: hosts a user
    declares to be one for cookies. A group of one host is no alias. A host
    that is not a name or an IP address (a port, a path, a blank), or that
    appears in two groups, raises ``ValueError``."""
    aliases: Dict[str, str] = {}
    for group in groups:
        if isinstance(group, str):
            raise TypeError("a cookie host group is a list of hosts, not the string %r" % group)
        hosts = []
        for raw in group:
            host = _normal_host(raw)
            if not (_is_ip(host) or _HOST_NAME.fullmatch(host)):
                raise ValueError("%r is not a host name or an IP address" % raw)
            if host in aliases:
                raise ValueError("%r is in two cookie host groups" % raw)
            if host not in hosts:
                hosts.append(host)
        if len(hosts) > 1:
            aliases.update((host, hosts[0]) for host in hosts)
    return aliases


def _placed_for(
    host: str, attribute: Optional[str], aliases: Optional[Mapping[str, str]]
) -> Optional[Tuple[str, bool]]:
    """:func:`_cookie_domain` with ``host``'s alias group as one host: a
    cookie with no Domain, or a Domain naming a host of the group, belongs to
    the group's first host. A Domain outside the group is judged on ``host``."""
    target = aliases.get(_normal_host(host)) if aliases else None
    if target is None:
        return _cookie_domain(host, attribute)
    named = _normal_host((attribute or "").strip().lstrip("."))
    if not named:
        return target, False
    if aliases.get(named) == target:  # type: ignore[union-attr]
        return _cookie_domain(target, target)
    return _cookie_domain(host, attribute)


def _default_path(request_path: str) -> str:
    """RFC 6265 section 5.1.4: the directory of the request path."""
    path = request_path.split("?", 1)[0].split("#", 1)[0]
    if not path.startswith("/") or path.count("/") == 1:
        return "/"
    return path[: path.rindex("/")]


def _parse_set_cookie(header: str, now: float) -> "Optional[Tuple[str, str, Dict[str, str]]]":
    """RFC 6265 section 5.2: ``(name, value, attributes)`` of one header, the
    attribute names lower-case; an expiry is resolved into ``expires`` (a unix
    time as text). ``None`` when the header holds no cookie, or holds a
    control character (the tab apart), which RFC 6265bis 5.6 and curl ignore
    the whole cookie for."""
    if _CONTROL.search(header):
        return None
    pair, _, rest = header.partition(";")
    name, eq, value = pair.partition("=")
    name, value = name.strip(), value.strip()
    if not eq or not name:
        return None
    attrs: Dict[str, str] = {}
    expires: Optional[float] = None
    max_age: Optional[int] = None
    for item in rest.split(";"):
        key, _, val = item.partition("=")
        key, val = key.strip().lower(), val.strip()
        if key == "expires":
            when = http_date(val)
            if when is not None:
                expires = when
        elif key == "max-age":
            seconds = ascii_int(val[1:] if val.startswith("-") else val)
            if seconds is not None:
                max_age = -seconds if val.startswith("-") else seconds
        elif key in ("domain", "path"):
            if val:
                attrs[key] = val
        elif key in ("secure", "httponly"):
            attrs[key] = "1"
    if max_age is not None:  # Max-Age beats Expires, whatever the order
        expires = now + max_age if max_age > 0 else now
    if expires is not None:
        attrs["expires"] = str(int(min(expires, now + MAX_COOKIE_AGE)))
    return name, value, attrs


def set_cookie_specs(
    values: Iterable[str],
    default_domain: str,
    now: Optional[float] = None,
    *,
    request_path: str = "/",
    aliases: Optional[Mapping[str, str]] = None,
) -> List[Tuple[CookieSpec, bool]]:
    """``(cookie, gone)`` for every cookie the ``Set-Cookie`` header
    ``values`` carry, read as RFC 6265 section 5.2 does.

    ``default_domain`` is the host asked. A ``Domain`` attribute is kept only
    when that host domain-matches it and it is not a public suffix (judged
    without the Public Suffix List: a top level domain or a ``co.uk``-style
    registry); it then covers subdomains (``subdomains=True``). Without one
    the cookie is host-only. A cookie with no ``Path`` gets the directory of
    ``request_path``. ``gone`` marks a cookie the server expires: an empty
    value, ``Max-Age`` of zero or less, a past date. A header that is not a
    cookie, or names a foreign domain, is skipped. An expiry beyond 400 days
    is cut to 400 days. ``aliases`` (:func:`host_aliases`) makes a group of
    hosts one: a cookie a member sets with no Domain, or with a Domain naming
    a member, belongs to the group's first host."""
    now = time.time() if now is None else now
    out: List[Tuple[CookieSpec, bool]] = []
    for header in values:
        parsed = _parse_set_cookie(header, now)
        if parsed is None:
            continue
        name, value, attrs = parsed
        placed = _placed_for(default_domain, attrs.get("domain"), aliases)
        if placed is None:
            continue
        domain, subdomains = placed
        path = attrs.get("path", "")
        expires = int(attrs["expires"]) if "expires" in attrs else None
        spec = CookieSpec(
            domain=domain,
            path=path if path.startswith("/") else _default_path(request_path),
            secure="secure" in attrs,
            expires=expires,
            name=name,
            value=value,
            http_only="httponly" in attrs,
            subdomains=subdomains,
        )
        out.append((spec, not value or (expires is not None and expires <= int(now))))
    return out


def domain_covers(domain: str, host: str) -> bool:
    """Does a cookie ``domain`` apply to ``host``: the host itself, or a
    subdomain when the domain has a leading dot (the Netscape flag)."""
    d = (domain or "").lower()
    h = (host or "").lower()
    if not d or not h:
        return False
    bare = d.lstrip(".")
    return h == bare or (d.startswith(".") and h.endswith("." + bare))


def save_netscape(session_cookies: "Iterable[CookieLike]", path: Path) -> None:
    """Writes ``session_cookies`` to ``path`` as a Netscape cookie file, owner
    only and replaced whole. A cookie with no name, or with a control character
    or a tab in a field, is not written: it would split its row."""
    lines = ["# Netscape HTTP Cookie File\n"]
    for cookie in session_cookies:
        domain = getattr(cookie, "domain", "") or ""
        flag = "TRUE" if domain.startswith(".") or getattr(cookie, "subdomains", False) else "FALSE"
        if getattr(cookie, "http_only", False):
            domain = HTTP_ONLY_PREFIX + domain
        cpath = getattr(cookie, "path", "/") or "/"
        secure = "TRUE" if bool(getattr(cookie, "secure", False)) else "FALSE"
        expires_val = getattr(cookie, "expires", None)
        expires = str(int(expires_val)) if expires_val else "0"
        name = getattr(cookie, "name", "")
        value = getattr(cookie, "value", "")
        if not name or any(_UNSAFE_FIELD.search(str(field)) for field in (domain, cpath, name, value)):
            continue
        lines.append("%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (domain, flag, cpath, secure, expires, name, value))
    write_private(path, "".join(lines).encode("utf-8"))

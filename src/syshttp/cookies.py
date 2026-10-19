"""Netscape cookie-file I/O, curl's cookie rules, and requests-session
cookie merging. The requests-free half (``CookieSpec``, ``load_netscape``,
``save_netscape``, ``cookie_applies``, ``set_cookie_specs``) is what the curl
fallback's ``-b`` / ``-c`` run on."""

from __future__ import annotations

import http.cookiejar
import ipaddress
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional, Protocol, Tuple
from urllib.parse import urlparse

from ._fileio import read_text, write_private
from ._parse import ascii_int, http_date

if TYPE_CHECKING:  # requests is optional at runtime: types only
    import requests


__all__ = (
    "CookieLike",
    "CookieSpec",
    "HTTP_ONLY_PREFIX",
    "MAX_COOKIE_AGE",
    "apply_to_session",
    "cookie_applies",
    "domain_covers",
    "host_only_policy",
    "load_netscape",
    "merge_set_cookie_headers",
    "save_netscape",
    "set_cookie_specs",
)


class CookieLike(Protocol):
    """What :func:`save_netscape` reads off a cookie: ``http.cookiejar.Cookie``
    (a requests session's) or any object with these attributes."""

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


def load_netscape(path: Path) -> List[CookieSpec]:
    try:
        text = read_text(path)
    except FileNotFoundError:
        return []
    cookies: List[CookieSpec] = []
    for line in text.splitlines():
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


def _default_path(request_path: str) -> str:
    """RFC 6265 section 5.1.4: the directory of the request path."""
    path = request_path.split("?", 1)[0].split("#", 1)[0]
    if not path.startswith("/") or path.count("/") == 1:
        return "/"
    return path[: path.rindex("/")]


def _parse_set_cookie(header: str, now: float) -> "Optional[Tuple[str, str, Dict[str, str]]]":
    """RFC 6265 section 5.2: ``(name, value, attributes)`` of one header, the
    attribute names lower-case; an expiry is resolved into ``expires`` (a unix
    time as text). ``None`` when the header holds no cookie."""
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
    is cut to 400 days."""
    now = time.time() if now is None else now
    out: List[Tuple[CookieSpec, bool]] = []
    for header in values:
        parsed = _parse_set_cookie(header, now)
        if parsed is None:
            continue
        name, value, attrs = parsed
        placed = _cookie_domain(default_domain, attrs.get("domain"))
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


def _local_name(host: str) -> str:
    """The name ``http.cookiejar`` keys a host-only cookie by: a host with no
    dot (``localhost``, ``wiki``, an IPv6 literal) gets ``.local`` appended."""
    return host if "." in host else host + ".local"


def _session_cookie(row: CookieSpec) -> "http.cookiejar.Cookie":
    bare = row.domain.lstrip(".").lower()
    if not bare:
        raise ValueError("a cookie row without a domain")
    # An IP address matches only itself, whatever the flag says.
    domain_cookie = (row.subdomains or row.domain.startswith(".")) and not _is_ip(bare)
    return http.cookiejar.Cookie(
        version=0,
        name=row.name,
        value=row.value,
        port=None,
        port_specified=False,
        domain="." + bare if domain_cookie else _local_name(bare),
        domain_specified=domain_cookie,
        domain_initial_dot=domain_cookie,
        path=row.path or "/",
        path_specified=True,
        secure=bool(row.secure),
        expires=row.expires or None,
        discard=not row.expires,
        comment=None,
        comment_url=None,
        rest={"HttpOnly": None} if row.http_only else {},  # type: ignore[dict-item]
        rfc2109=False,
    )


def apply_to_session(session: "requests.Session", cookies: Iterable[CookieSpec]) -> None:
    """Load jar rows into the session with their flags: a ``Secure`` row
    stays secure (never sent over http), an expiry stays an expiry, and a row
    that is not a domain cookie (no leading dot, include-subdomains flag
    ``FALSE``) is sent to its host only, ``localhost`` and other single-label
    hosts included. ``new_session`` gives its session
    :func:`host_only_policy`, which the last needs."""
    for row in cookies:
        try:
            session.cookies.set_cookie(_session_cookie(row))
        except Exception:
            continue


def _spec_from_cookie(cookie: "http.cookiejar.Cookie", host: str) -> CookieSpec:
    """The jar row for a session cookie: the include-subdomains flag from
    how the cookie was set, ``HttpOnly`` from its attributes, and a
    ``.local`` suffix that ``http.cookiejar`` added to ``host`` (a
    single-label name) taken off again."""
    domain = (getattr(cookie, "domain", "") or "").lower()
    specified = bool(getattr(cookie, "domain_specified", False)) or domain.startswith(".")
    bare = domain.lstrip(".")
    if not specified and "." not in host.lower() and bare == host.lower() + ".local":
        bare = host.lower()
    rest = getattr(cookie, "_rest", None) or {}
    return CookieSpec(
        domain=bare,
        path=getattr(cookie, "path", "/") or "/",
        secure=bool(getattr(cookie, "secure", False)),
        expires=getattr(cookie, "expires", None),
        name=getattr(cookie, "name", ""),
        value=getattr(cookie, "value", ""),
        http_only=any(str(key).lower() == "httponly" for key in rest),
        subdomains=specified,
    )


def host_only_policy() -> "http.cookiejar.DefaultCookiePolicy":
    """A cookie policy that keeps a cookie set without ``Domain`` on its own
    host, as RFC 6265 and curl do (``http.cookiejar``'s default also sends it
    to subdomains)."""
    return http.cookiejar.DefaultCookiePolicy(strict_ns_domain=http.cookiejar.DefaultCookiePolicy.DomainStrictNonDomain)


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
        if not name:
            continue
        lines.append("%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (domain, flag, cpath, secure, expires, name, value))
    write_private(path, "".join(lines).encode("utf-8"))


def _forget(session: "requests.Session", cookie: CookieSpec) -> None:
    """Remove the session's cookie of the same name, path and domain,
    whether it was stored host-only or as a domain cookie (and, for a
    single-label host, under its ``.local`` effective host)."""
    domains = [cookie.domain, "." + cookie.domain]
    if "." not in cookie.domain:
        domains.append(cookie.domain + ".local")
    for domain in domains:
        try:
            session.cookies.clear(domain=domain, path=cookie.path, name=cookie.name)
        except KeyError:
            continue


def merge_set_cookie_headers(session: "requests.Session", response: "requests.Response") -> None:
    """Apply the deletions that ``Set-Cookie`` headers of ``response`` (and of
    the redirect hops before it) ask for and requests' own extraction misses:
    one that names its ``Domain`` differently from how the cookie was stored,
    and an empty value. Cookies that are set are left to requests, which has
    already stored each once against the URL the caller asked for. A header
    for a domain the response's host does not own is ignored, as on a set."""
    for hop in [*getattr(response, "history", ()), response]:
        raw_headers = getattr(getattr(hop, "raw", None), "headers", None)
        if raw_headers is None:
            continue
        try:
            set_cookies = raw_headers.get_all("Set-Cookie") or []
        except Exception:
            continue
        parts = urlparse(getattr(hop, "url", "") or "")
        for cookie, gone in set_cookie_specs(set_cookies, parts.hostname or "", request_path=parts.path):
            if gone:
                _forget(session, cookie)

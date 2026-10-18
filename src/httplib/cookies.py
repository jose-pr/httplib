"""Netscape cookie-file I/O, curl's cookie rules, and requests-session
cookie merging. The requests-free half (``CookieSpec``, ``load_netscape``,
``save_netscape``, ``cookie_applies``, ``set_cookie_specs``) is what the curl
fallback's ``-b`` / ``-c`` run on."""
from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from http.cookies import Morsel, SimpleCookie
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, List, Optional, Protocol, Tuple
from urllib.parse import urlparse

if TYPE_CHECKING:  # requests is optional at runtime: types only
    import requests


class CookieLike(Protocol):
    """What :func:`save_netscape` reads off a cookie: ``http.cookiejar.Cookie``
    (a requests session's) or any object with these attributes."""

    domain: str
    path: str
    secure: bool
    expires: Optional[int]
    name: str
    value: str


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
    if not path.exists():
        return []
    cookies: List[CookieSpec] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        # curl writes an HttpOnly cookie's domain as `#HttpOnly_<domain>`; any
        # other `#` line is a comment.
        if not line or (line.startswith("#") and not line.startswith(HTTP_ONLY_PREFIX)):
            continue
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        domain, flag, cpath, secure, expires, name, value = parts[:7]
        http_only = domain.startswith(HTTP_ONLY_PREFIX)
        if http_only:
            domain = domain[len(HTTP_ONLY_PREFIX):]
        cookies.append(
            CookieSpec(
                domain=domain,
                path=cpath or "/",
                secure=str(secure).upper() == "TRUE",
                # `0` is how the format writes a session cookie: no expiry.
                expires=int(expires) if str(expires).isdigit() and int(expires) else None,
                name=name,
                value=value,
                http_only=http_only,
                subdomains=flag.upper() == "TRUE",
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


def _morsel_expiry(morsel: "Morsel[str]", now: float) -> Optional[int]:
    """A Set-Cookie's expiry as a unix time: ``Max-Age`` (seconds from now)
    wins over ``Expires`` (an HTTP date); ``None`` for a session cookie or an
    unparseable value."""
    if morsel["max-age"]:
        try:
            return int(now) + int(morsel["max-age"])
        except ValueError:
            return None
    if morsel["expires"]:
        from email.utils import parsedate_to_datetime

        try:
            return int(parsedate_to_datetime(morsel["expires"]).timestamp())
        except (TypeError, ValueError, OverflowError):
            return None
    return None


def set_cookie_specs(
    values: Iterable[str], default_domain: str, now: Optional[float] = None
) -> List[Tuple[CookieSpec, bool]]:
    """``(cookie, gone)`` for every cookie the ``Set-Cookie`` header
    ``values`` carry: the domain defaults to ``default_domain`` (the host
    asked), the path to ``/``; ``gone`` when the server expires it (an empty
    value, ``Max-Age=0``, a past date). An unparseable header is skipped."""
    now = time.time() if now is None else now
    out: List[Tuple[CookieSpec, bool]] = []
    for header in values:
        parsed: "SimpleCookie" = SimpleCookie()
        try:
            parsed.load(header)
        except Exception:
            continue
        for morsel in parsed.values():
            expires = _morsel_expiry(morsel, now)
            spec = CookieSpec(
                domain=morsel["domain"] or default_domain,
                path=morsel["path"] or "/",
                secure=bool(morsel["secure"]),
                expires=expires,
                name=morsel.key,
                value=morsel.value,
                http_only=bool(morsel["httponly"]),
            )
            out.append((spec, not morsel.value or (expires is not None and expires <= int(now))))
    return out


def apply_to_session(session: "requests.Session", cookies: Iterable[CookieSpec]) -> None:
    """Load jar rows into the session with their flags: a ``Secure`` row
    stays secure (never sent over http), an expiry stays an expiry."""
    for c in cookies:
        try:
            session.cookies.set(
                c.name, c.value, domain=c.domain, path=c.path,
                secure=bool(c.secure), expires=c.expires or None,
            )
        except Exception:
            continue


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
        lines.append(
            "%s\t%s\t%s\t%s\t%s\t%s\t%s\n"
            % (domain, flag, cpath, secure, expires, name, value)
        )
    path.write_text("".join(lines), encoding="utf-8")


def merge_set_cookie_headers(session: "requests.Session", response: "requests.Response") -> None:
    try:
        session.cookies.update(response.cookies)
    except Exception:
        pass
    raw_headers = getattr(response.raw, "headers", None)
    if raw_headers is None:
        return
    try:
        set_cookies = raw_headers.get_all("Set-Cookie") or []
    except Exception:
        set_cookies = []
    if not set_cookies:
        return
    resp_host = urlparse(getattr(response, "url", "") or "").hostname or ""
    for cookie, gone in set_cookie_specs(set_cookies, resp_host):
        if gone:
            try:
                session.cookies.clear(domain=cookie.domain, path=cookie.path, name=cookie.name)
            except Exception:
                pass
            continue
        try:
            session.cookies.set(
                cookie.name,
                cookie.value,
                domain=cookie.domain,
                path=cookie.path,
                secure=cookie.secure,
                expires=cookie.expires,
            )
        except Exception:
            continue

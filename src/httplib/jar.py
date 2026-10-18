"""File-backed cookie/token jars, keyed by host.

Jars live under one root, :func:`store_root`: ``<P>_HOME`` (``HTTPLIB_HOME``
by default; see :mod:`httplib.env`), else the platform's per-user state
directory. Cookies go under ``<root>/cookies/<host>.txt`` (Netscape format),
tokens under ``<root>/tokens/<host>.token``.

Token values are secrets: this module never logs or prints them.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable, Optional, Protocol

from .cookies import CookieSpec, load_netscape, save_netscape
from .env import HTTPEnv

#: The setting naming the jar root, as ``<P>_HOME``.
HOME = "HOME"

_UNSAFE = '<>:"/\\|?*'


def safe_name(key: str) -> str:
    """A jar file name for a host: characters no filesystem takes (``:`` of an
    IPv6 literal on Windows, a ``/``) become ``_``."""
    return "".join("_" if ch in _UNSAFE else ch for ch in key)


def default_root(*, env: Optional[HTTPEnv] = None) -> Path:
    """The per-user state directory for jars when ``<P>_HOME`` is unset, a
    directory ``httplib`` under: ``%LOCALAPPDATA%`` on Windows,
    ``~/Library/Application Support`` on macOS, ``$XDG_STATE_HOME`` (else
    ``~/.local/state``) elsewhere."""
    env = HTTPEnv() if env is None else env
    if sys.platform == "win32":
        base = env.conventional("LOCALAPPDATA")
        return (Path(base) if base else Path.home() / "AppData" / "Local") / "httplib"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "httplib"
    base = env.conventional("XDG_STATE_HOME")
    return (Path(base) if base else Path.home() / ".local" / "state") / "httplib"


def store_root(*, env: Optional[HTTPEnv] = None) -> Path:
    """The jar root: ``<P>_HOME``, else :func:`default_root`."""
    env = HTTPEnv() if env is None else env
    home = env.get(HOME)
    return Path(home) if home else default_root(env=env)


class CookieJar(Protocol):
    def __getitem__(self, key: str) -> Iterable[CookieSpec]: ...
    def __setitem__(self, key: str, value: Iterable[CookieSpec]) -> None: ...
    def get(self, key: str, default=None): ...


class TokenJar(Protocol):
    def __getitem__(self, key: str) -> str: ...
    def __setitem__(self, key: str, value: str) -> None: ...
    def get(self, key: str, default=None): ...


class FileCookieJar:
    def __init__(self, root: "Path | None" = None, *, env: Optional[HTTPEnv] = None):
        self.root = Path(root) if root is not None else store_root(env=env)
        self.dir = self.root / "cookies"
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        return self.dir / ("%s.txt" % safe_name(key))

    def __getitem__(self, key: str) -> Iterable[CookieSpec]:
        return load_netscape(self._path(key))

    def __setitem__(self, key: str, value: Iterable[CookieSpec]) -> None:
        path = self._path(key)

        class _C:
            def __init__(self, c: CookieSpec):
                self.domain = c.domain
                self.path = c.path
                self.secure = c.secure
                self.expires = c.expires
                self.name = c.name
                self.value = c.value

        save_netscape([_C(c) for c in value], path)

    def get(self, key: str, default=None):
        try:
            return self[key]
        except Exception:
            return default


class FileTokenJar:
    def __init__(self, root: "Path | None" = None, *, env: Optional[HTTPEnv] = None):
        self.root = Path(root) if root is not None else store_root(env=env)
        self.dir = self.root / "tokens"
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        return self.dir / ("%s.token" % safe_name(key))

    def __getitem__(self, key: str) -> str:
        # Never logs the value read (secret).
        return self._path(key).read_text(encoding="utf-8").strip()

    def __setitem__(self, key: str, value: str) -> None:
        self._path(key).write_text(value.strip() + "\n", encoding="utf-8")

    def get(self, key: str, default=None):
        try:
            v = self[key]
            return v if v else default
        except Exception:
            return default


class MemoryCookieJar(dict):
    def __getitem__(self, key: str) -> Iterable[CookieSpec]:
        return super().get(key, [])


class MemoryTokenJar(dict):
    def __getitem__(self, key: str) -> str:
        return super().__getitem__(key)

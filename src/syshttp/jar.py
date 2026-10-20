"""File-backed cookie/token jars, keyed by host.

Jars live under one root, :func:`store_root`: ``SYSHTTP_HOME`` (under the
prefixes of :mod:`syshttp.env`), else the platform's per-user state
directory. Cookies go under ``<root>/cookies/<host>.txt`` (Netscape format),
tokens under ``<root>/tokens/<host>.token``.

Token values are secrets: this module never logs or prints them. Files are
written ``0o600`` (directories ``0o700``) and replaced whole, with LF line
ends; a directory is created at the first write, not when a jar is built.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable, Optional, Protocol

from ._fileio import read_text, write_private
from .cookies import CookieSpec, load_netscape, save_netscape
from .env import HTTPEnv

__all__ = (
    "CookieJar",
    "FileCookieJar",
    "FileTokenJar",
    "HOME",
    "MemoryCookieJar",
    "MemoryTokenJar",
    "TokenJar",
    "default_root",
    "safe_name",
    "store_root",
)

#: The setting naming the jar root.
HOME = "SYSHTTP_HOME"

_UNSAFE = '<>:"/\\|?*'


def safe_name(key: str) -> str:
    """A jar file name for a host: characters no filesystem takes (``:`` of an
    IPv6 literal on Windows, a ``/``) become ``_``."""
    return "".join("_" if ch in _UNSAFE else ch for ch in key)


def default_root(*, env: Optional[HTTPEnv] = None) -> Path:
    """The per-user state directory for jars when ``SYSHTTP_HOME`` is unset, a
    directory ``syshttp`` under: ``%LOCALAPPDATA%`` on Windows,
    ``~/Library/Application Support`` on macOS, ``$XDG_STATE_HOME`` (else
    ``~/.local/state``) elsewhere."""
    env = HTTPEnv() if env is None else env
    if sys.platform == "win32":
        base = (env.environ.get("LOCALAPPDATA") or "").strip()
        return (Path(base) if base else Path.home() / "AppData" / "Local") / "syshttp"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "syshttp"
    base = (env.environ.get("XDG_STATE_HOME") or "").strip()
    return (Path(base) if base else Path.home() / ".local" / "state") / "syshttp"


def store_root(*, env: Optional[HTTPEnv] = None) -> Path:
    """The jar root: ``SYSHTTP_HOME``, else :func:`default_root`."""
    env = HTTPEnv() if env is None else env
    home = env.get(HOME)
    return Path(home).expanduser() if home else default_root(env=env)


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

    def _path(self, key: str) -> Path:
        return self.dir / ("%s.txt" % safe_name(key))

    def __getitem__(self, key: str) -> Iterable[CookieSpec]:
        return load_netscape(self._path(key))

    def __setitem__(self, key: str, value: Iterable[CookieSpec]) -> None:
        save_netscape(value, self._path(key))

    def get(self, key: str, default=None):
        try:
            return self[key]
        except Exception:
            return default


class FileTokenJar:
    def __init__(self, root: "Path | None" = None, *, env: Optional[HTTPEnv] = None):
        self.root = Path(root) if root is not None else store_root(env=env)
        self.dir = self.root / "tokens"

    def _path(self, key: str) -> Path:
        return self.dir / ("%s.token" % safe_name(key))

    def __getitem__(self, key: str) -> str:
        # Never logs the value read (secret).
        return read_text(self._path(key)).strip()

    def __setitem__(self, key: str, value: str) -> None:
        write_private(self._path(key), (value.strip() + "\n").encode("utf-8"))

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

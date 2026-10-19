"""Writing files that hold secrets: owner-only and replaced whole."""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

#: ``os.replace`` onto a file another handle has open fails with
#: ``PermissionError`` on Windows until that handle closes, which a reader
#: does within microseconds.
_REPLACE_TRIES = 10
_REPLACE_WAIT = 0.01


def _make_directories(directory: Path) -> None:
    """Create ``directory`` and its missing parents with mode ``0o700``; a
    directory that exists is left as it is."""
    missing = []
    while not directory.exists() and directory != directory.parent:
        missing.append(directory)
        directory = directory.parent
    for created in reversed(missing):
        try:
            created.mkdir(mode=0o700)
        except FileExistsError:
            continue
        try:
            created.chmod(0o700)
        except OSError:  # a filesystem without modes
            pass


def read_text(path: Path) -> str:
    """The UTF-8 text of ``path`` (undecodable bytes dropped). On Windows a
    file being replaced refuses to open for an instant: that is retried."""
    for attempt in range(_REPLACE_TRIES):
        try:
            return Path(path).read_text(encoding="utf-8", errors="ignore")
        except PermissionError:
            if attempt == _REPLACE_TRIES - 1:
                raise
            time.sleep(_REPLACE_WAIT)
    raise AssertionError("unreachable")  # pragma: no cover


def _replace(source: str, target: Path) -> None:
    for attempt in range(_REPLACE_TRIES):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt == _REPLACE_TRIES - 1:
                raise
            time.sleep(_REPLACE_WAIT)


def write_private(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` so that a reader sees the old file or the
    new one, never part of either, and only the owner can read it (``0o600``;
    missing parent directories are ``0o700``). The bytes are written as
    given: no newline translation."""
    path = Path(path)
    _make_directories(path.parent)
    fd, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise

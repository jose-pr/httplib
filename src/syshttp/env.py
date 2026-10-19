"""Where syshttp's settings come from: one prefix, one environment mapping.

Every setting of this package is the variable ``<PREFIX>_<NAME>`` --
``SYSHTTP_PROXY``, ``SYSHTTP_PROXY_AUTH``, ``SYSHTTP_HOOKS_<KEY>`` -- and the
prefix itself comes from ``SYSHTTP_PREFIX`` (default ``SYSHTTP``), so a tool
embedding syshttp can give it a namespace of its own (``SYSHTTP_PREFIX=MYTOOL``
reads ``MYTOOL_PROXY``). Conventional variables keep their names under any
prefix: ``HTTPS_PROXY`` / ``HTTP_PROXY`` / ``ALL_PROXY``, ``NO_PROXY``.

An :class:`HTTPEnv` holds one such view. Two of them with different prefixes or
mappings never see each other's settings, which is how one process serves
several configurations; every function that reads a setting takes one as
``env=`` and builds a default ``HTTPEnv()`` when given none. Nothing is read at
import: a variable set later takes effect on the next call.

``prefix=""`` turns the package's own settings off -- only the conventional
variables are read. It is an argument only: an empty ``SYSHTTP_PREFIX`` counts
as unset. ``HTTP`` and any prefix starting ``HTTP_`` are refused: CGI exports
every request header as an ``HTTP_*`` variable, and a setting such as
``HOOKS_<KEY>_PY`` names code to import.
"""

from __future__ import annotations

import os
import re
from typing import Iterator, Mapping, Optional, Tuple

__all__ = ["DEFAULT_PREFIX", "PREFIX_VAR", "HTTPEnv"]

#: The variable naming the prefix of every other setting.
PREFIX_VAR = "SYSHTTP_PREFIX"
#: The prefix when neither an argument nor ``SYSHTTP_PREFIX`` gives one.
DEFAULT_PREFIX = "SYSHTTP"

_PREFIX_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)*\Z")


def _check_prefix(prefix: str, source: str) -> str:
    if prefix and not _PREFIX_RE.match(prefix):
        raise ValueError(
            "%s must be letters, digits and single inner underscores, starting with a letter, not %r" % (source, prefix)
        )
    # Upper case, as variable names are: Windows upper-cases os.environ's keys,
    # so a lower-case prefix would match there and nowhere else.
    prefix = prefix.upper()
    if prefix == "HTTP" or prefix.startswith("HTTP_"):
        raise ValueError(
            "%s must not be HTTP or start with HTTP_, not %r: CGI exports request headers as HTTP_* variables, "
            "so a client would choose the settings and the hooks" % (source, prefix)
        )
    return prefix


class HTTPEnv:
    """A view of the environment under one prefix.

    ``prefix`` -- ``None`` (read ``SYSHTTP_PREFIX`` at each lookup, default
    ``SYSHTTP``), a prefix such as ``"MYTOOL"``, or ``""`` for conventional
    variables only. ``environ`` -- the mapping to read, default ``os.environ``
    as it is at each lookup. A malformed prefix is a ``ValueError``: from the
    constructor for an argument, from the first lookup for ``SYSHTTP_PREFIX``;
    so is ``HTTP`` or a prefix starting ``HTTP_``.
    """

    __slots__ = ("_prefix", "_environ")

    def __init__(self, prefix: Optional[str] = None, environ: Optional[Mapping[str, str]] = None) -> None:
        self._prefix = None if prefix is None else _check_prefix(prefix, "prefix")
        self._environ = environ

    @property
    def environ(self) -> Mapping[str, str]:
        """The mapping settings are read from."""
        return os.environ if self._environ is None else self._environ

    @property
    def prefix(self) -> str:
        """The prefix in force: the argument, else ``SYSHTTP_PREFIX``, else
        ``SYSHTTP``. ``""`` means the package's own settings are off."""
        if self._prefix is not None:
            return self._prefix
        raw = (self.environ.get(PREFIX_VAR) or "").strip()
        return _check_prefix(raw, PREFIX_VAR) if raw else DEFAULT_PREFIX

    def name(self, setting: str) -> Optional[str]:
        """The variable for ``setting`` (``"PROXY"`` -> ``"SYSHTTP_PROXY"``),
        or ``None`` when the prefix is ``""``."""
        prefix = self.prefix
        return "%s_%s" % (prefix, setting) if prefix else None

    def get(self, setting: str) -> Optional[str]:
        """The value of ``setting``, stripped; ``None`` when unset or empty."""
        name = self.name(setting)
        return self.conventional(name) if name else None

    def conventional(self, *names: str) -> Optional[str]:
        """The first of ``names`` (variables read as named, under no prefix)
        that is set and not empty, stripped; else ``None``."""
        env = self.environ
        for name in names:
            value = (env.get(name) or "").strip()
            if value:
                return value
        return None

    def family(self, stem: str) -> Iterator[Tuple[str, str]]:
        """``(rest, value)`` for every variable named ``<PREFIX>_<stem><rest>``
        with a non-empty ``rest`` and a value that is not blank (stripped, as
        :meth:`get` strips), in name order; nothing when the prefix is ``""``."""
        head = self.name(stem)
        if not head:
            return
        env = self.environ
        for name in sorted(env):
            if name.startswith(head) and len(name) > len(head):
                value = (env[name] or "").strip()
                if value:
                    yield name[len(head) :], value

    def __repr__(self) -> str:
        prefix = "from %s" % PREFIX_VAR if self._prefix is None else repr(self._prefix)
        source = "os.environ" if self._environ is None else "a mapping"
        return "HTTPEnv(prefix %s, %s)" % (prefix, source)

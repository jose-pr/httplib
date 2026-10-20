"""Where syshttp's settings come from: a list of prefixes, one environment
mapping.

Every setting is a variable with a full name -- syshttp's own carry
``SYSHTTP_`` (``SYSHTTP_PROXY``, ``SYSHTTP_HOME``, ``SYSHTTP_HOOKS_<KEY>``),
conventional ones keep theirs (``HTTPS_PROXY``, ``NO_PROXY``, ``CA_BUNDLE``)
-- read as ``<PREFIX><NAME>`` for each prefix in turn, the first one set
winning. The prefixes come from ``SYSHTTP_PREFIX``, a ``:``-separated list
taken literally (``AGENTS_`` reads ``AGENTS_HTTPS_PROXY``); blank or unset is
one empty prefix, the names as written. A tool embedding syshttp therefore
opts out of the defaults with ``SYSHTTP_PREFIX=MYTOOL_`` or layers its own over
them with ``MYTOOL_:`` (the empty entry last).

An :class:`HTTPEnv` holds one such view. Two of them with different prefixes or
mappings never see each other's settings, which is how one process serves
several configurations; every function that reads a setting takes one as
``env=`` and builds a default ``HTTPEnv()`` when given none. Nothing is read at
import: a variable set later takes effect on the next call.

A CGI program gets every request header as an ``HTTP_*`` variable, so a
client could choose ``HTTP_PROXY`` and its kin: under CGI, set a prefix list
without the empty entry.
"""

from __future__ import annotations

import os
import re
from typing import Iterable, Iterator, Mapping, Optional, Tuple, Union

from .exceptions import ConfigurationError

__all__ = ["PREFIX_VAR", "HTTPEnv"]

#: The variable naming the prefixes, ``:``-separated. Read as written: it has
#: no prefix of its own.
PREFIX_VAR = "SYSHTTP_PREFIX"

_PREFIX_RE = re.compile(r"[A-Za-z0-9_]*\Z")


def _check_prefix(prefix: str, source: str) -> str:
    # The argument is a caller's mistake (ValueError); the variable is a setting.
    prefix = prefix.strip()
    if not _PREFIX_RE.match(prefix):
        error = ConfigurationError if source == PREFIX_VAR else ValueError
        raise error("%s holds letters, digits and underscores only, not %r" % (source, prefix))
    # Upper case, as variable names are: Windows upper-cases os.environ's keys,
    # so a lower-case prefix would match there and nowhere else.
    return prefix.upper()


def _prefix_list(prefixes: Iterable[str], source: str) -> Tuple[str, ...]:
    found = []
    for prefix in prefixes:
        prefix = _check_prefix(prefix, source)
        if prefix not in found:
            found.append(prefix)
    return tuple(found)


class HTTPEnv:
    """A view of the environment through a list of prefixes.

    ``prefixes`` -- ``None`` (read ``SYSHTTP_PREFIX`` at each lookup; blank or
    unset is ``("",)``), a ``:``-separated string, or an iterable of prefixes;
    each is used literally and upper-cased, ``""`` meaning the names as
    written, and an empty iterable reading nothing. ``environ`` -- the mapping
    to read, default ``os.environ`` as it is at each lookup. A malformed
    prefix is a ``ValueError``: from the constructor for an argument, from
    the first lookup for ``SYSHTTP_PREFIX`` (a ``ConfigurationError``).
    """

    __slots__ = ("_prefixes", "_environ")

    def __init__(
        self, prefixes: Union[str, Iterable[str], None] = None, environ: Optional[Mapping[str, str]] = None
    ) -> None:
        if isinstance(prefixes, str):
            prefixes = prefixes.split(":")
        self._prefixes = None if prefixes is None else _prefix_list(prefixes, "prefixes")
        self._environ = environ

    @property
    def environ(self) -> Mapping[str, str]:
        """The mapping settings are read from."""
        return os.environ if self._environ is None else self._environ

    @property
    def prefixes(self) -> Tuple[str, ...]:
        """The prefixes in force, in lookup order: the argument, else
        ``SYSHTTP_PREFIX``, else ``("",)``."""
        if self._prefixes is not None:
            return self._prefixes
        raw = (self.environ.get(PREFIX_VAR) or "").strip()
        return _prefix_list(raw.split(":"), PREFIX_VAR) if raw else ("",)

    def name(self, name: str) -> str:
        """The variable for ``name`` under the first prefix: what a message
        names when nothing is set, and what a child process is given."""
        prefixes = self.prefixes
        return (prefixes[0] if prefixes else "") + name

    def find(self, *names: str) -> Optional[Tuple[str, str]]:
        """``(variable, value)`` for the first of ``names`` set, not blank,
        under the first prefix that has one (every name is tried under a
        prefix before the next prefix); the value stripped. ``None`` when
        none is."""
        env = self.environ
        for prefix in self.prefixes:
            for name in names:
                variable = prefix + name
                value = (env.get(variable) or "").strip()
                if value:
                    return variable, value
        return None

    def get(self, *names: str) -> Optional[str]:
        """The value :meth:`find` finds, or ``None``."""
        found = self.find(*names)
        return found[1] if found else None

    def family(self, stem: str) -> Iterator[Tuple[str, str, str]]:
        """``(rest, value, variable)`` for every variable named
        ``<PREFIX><stem><rest>`` with a non-empty ``rest`` and a value that is
        not blank (stripped), the first prefix winning for a ``rest`` (compared
        upper-cased); in prefix order, then name order."""
        env = self.environ
        seen = set()
        for prefix in self.prefixes:
            head = prefix + stem
            for variable in sorted(env):
                if not variable.startswith(head) or len(variable) == len(head):
                    continue
                rest = variable[len(head) :]
                value = (env[variable] or "").strip()
                if value and rest.upper() not in seen:
                    seen.add(rest.upper())
                    yield rest, value, variable

    def __repr__(self) -> str:
        prefixes = "from %s" % PREFIX_VAR if self._prefixes is None else repr(":".join(self._prefixes))
        source = "os.environ" if self._environ is None else "a mapping"
        return "HTTPEnv(prefixes %s, %s)" % (prefixes, source)

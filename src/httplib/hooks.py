"""URL hooks: a wrapper the curl shim runs, or a callable ``httplib`` calls,
for requests whose URL matches a pattern -- declared in the environment.
``NET_HOOKS_<KEY>`` (plural) declares a hook; ``NET_HOOK_<NAME>`` (singular)
is a variable one hook RUN exports to its wrapper.

    NET_HOOKS_<KEY>=<regex>            matched (re.search) against the URL the
                                             caller asked for -- the origin URL, never
                                             the proxy's or a prefix gateway's rewrite
    NET_HOOKS_<KEY>_CURL=<command>     the curl shim runs THIS instead of itself,
                                             with the shim's own argv appended
    NET_HOOKS_<KEY>_PY=<module:callable>   httplib calls it before the request:
                                             callable(session, method, url, kwargs)

A hook does what it wants with the session (log in, set a header in
``kwargs["headers"]``, refresh a token in the jar) and returns ``None`` to
let the request proceed; anything else it returns is used AS the response
(a cached or synthetic one). ``kwargs`` is the request's keyword arguments,
mutable in place. ``<module:callable>`` is importable from ``PYTHONPATH``
(every overlay's ``lib/`` is, in a ``dotagents env`` session) or a
``<path>.py:callable`` file.

The curl wrapper is a shell-quoted command line -- a program and its own
arguments -- that the shim's whole argv is appended to::

    NET_HOOKS_X_CURL='cmd fetch --'        ->   cmd fetch -- "$@"

Quote (single or double) what has spaces; a backslash is literal on every
platform, so a Windows path needs no doubling. A first word that is a
``.py`` file runs under the shim's own interpreter. The wrapper receives
``NET_HOOK_URL`` (the requested URL, so it need not parse argv),
``NET_HOOK_KEY`` (which hook matched), ``NET_HOOK_CURL`` naming the shim so
it can call curl back after its own work, and ``NET_HOOK_SKIP`` carrying
its KEY, so that call does not run the same wrapper again. A hook with
only a ``_PY`` target is ignored by the shim, one with only ``_CURL`` by
httplib.

Several hooks may match one URL: httplib calls each in KEY order (sorted),
the first returning a response ends the chain; the shim runs the first
``_CURL`` in that order. A pattern that does not compile is a configuration
error (``ValueError`` naming the KEY) the first time it would be consulted.
"""
from __future__ import annotations

import importlib
import importlib.util
import os
import re
import shlex
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

if TYPE_CHECKING:  # requests is optional at runtime: types only
    import requests

#: What a ``_PY`` hook is: ``(session, method, url, kwargs) -> None | response``.
PyHook = Callable[["requests.Session", str, str, Dict[str, Any]], "Optional[requests.Response]"]

PREFIX = "NET_HOOKS_"
CURL_SUFFIX = "_CURL"
PY_SUFFIX = "_PY"
SKIP_ENV = "NET_HOOK_SKIP"
URL_ENV = "NET_HOOK_URL"
KEY_ENV = "NET_HOOK_KEY"
CURL_ENV = "NET_HOOK_CURL"


class Hook(object):
    __slots__ = ("key", "pattern", "curl", "py")

    def __init__(self, key: str, pattern: "re.Pattern[str]", curl: Optional[str], py: Optional[str]):
        self.key = key
        self.pattern = pattern
        self.curl = curl
        self.py = py

    def matches(self, url: str) -> bool:
        return self.pattern.search(url) is not None

    def __repr__(self) -> str:
        return "Hook(%s, %r%s%s)" % (
            self.key, self.pattern.pattern, ", curl" if self.curl else "", ", py" if self.py else "")


def hooks_from_env(environ: "Optional[Dict[str, str]]" = None) -> List[Hook]:
    """Every configured hook, in KEY order. A ``_CURL``/``_PY`` variable whose
    KEY has no pattern is ignored (nothing to match)."""
    env = os.environ if environ is None else environ
    hooks = []
    for name in sorted(env):
        if not name.startswith(PREFIX) or name.endswith((CURL_SUFFIX, PY_SUFFIX)):
            continue
        key = name[len(PREFIX):]
        if not key or not env[name]:
            continue
        try:
            pattern = re.compile(env[name])
        except re.error as exc:
            raise ValueError("%s%s is not a valid regular expression: %s" % (PREFIX, key, exc))
        curl = env.get(PREFIX + key + CURL_SUFFIX) or None
        py = env.get(PREFIX + key + PY_SUFFIX) or None
        if curl or py:
            hooks.append(Hook(key, pattern, curl, py))
    return hooks


def skipped(environ: "Optional[Dict[str, str]]" = None) -> "set[str]":
    env = os.environ if environ is None else environ
    return {k.strip() for k in (env.get(SKIP_ENV) or "").split(",") if k.strip()}


def matching(url: str, environ: "Optional[Dict[str, str]]" = None, *, kind: Optional[str] = None) -> List[Hook]:
    """The hooks for ``url`` (the caller's URL), KEY order, minus the skipped
    ones; ``kind`` (``"curl"`` / ``"py"``) keeps only hooks with that target."""
    skip = skipped(environ)
    out = []
    for hook in hooks_from_env(environ):
        if hook.key in skip or not hook.matches(url):
            continue
        if kind and not getattr(hook, kind):
            continue
        out.append(hook)
    return out


def load_callable(spec: str) -> "PyHook":
    """``module:attr`` (importable) or ``<file>.py:attr``. ``attr`` may be dotted."""
    target, sep, attr = spec.rpartition(":")
    if not sep or not target or not attr:
        raise ValueError("a hook callable is written <module or file.py>:<callable>, not %r" % spec)
    if target.endswith(".py") and Path(target).is_file():
        path = Path(target).resolve()
        name = "agents_net_hook_" + re.sub(r"\W", "_", path.stem)
        module_spec = importlib.util.spec_from_file_location(name, str(path))
        if module_spec is None or module_spec.loader is None:
            raise ValueError("%s is not loadable as a Python module" % path)
        module = importlib.util.module_from_spec(module_spec)
        sys.modules[name] = module
        module_spec.loader.exec_module(module)
    else:
        module = importlib.import_module(target)
    obj: Any = module
    for part in attr.split("."):
        obj = getattr(obj, part)
    if not callable(obj):
        raise ValueError("%s is not callable" % spec)
    return obj


def call_py_hooks(
    session: "requests.Session", method: str, url: str, kwargs: Dict[str, Any],
    environ: Optional[Dict[str, str]] = None,
) -> "Optional[requests.Response]":
    """Run every ``_PY`` hook matching ``url`` in order; the first non-None
    result is returned (the caller uses it as the response), else ``None``."""
    for hook in matching(url, environ, kind="py"):
        if not hook.py:  # `kind="py"` already filtered; for the type checker
            continue
        try:
            fn = load_callable(hook.py)
            result = fn(session, method, url, kwargs)
        except Exception as exc:
            # The variable, so the failure is traceable to its declaration
            # (the URL is the caller's; the exception carries the rest).
            raise RuntimeError(
                "%s%s%s (%s) failed for %s %s: %s" % (PREFIX, hook.key, PY_SUFFIX, hook.py, method, url, exc)
            ) from exc
        if result is not None:
            return result
    return None


def split_command(value: str) -> List[str]:
    """A shell-quoted command line into argv: single and double quotes group
    words with spaces, a backslash is literal (no escaping on any platform,
    so ``C:\\Tools\\wrap.exe`` stays what it is), ``#`` starts no comment."""
    lex = shlex.shlex(value, posix=True)
    lex.whitespace_split = True
    lex.escape = ""
    lex.commenters = ""
    return list(lex)


def curl_command(hook: Hook, python: Optional[str] = None) -> List[str]:
    """The argv prefix a ``_CURL`` target means, the shim's argv to be
    appended: the shell-quoted command line split; a bare path to an existing
    file (spaces and all) is that one program; a first word that is a ``.py``
    file runs under ``python`` (default: this interpreter)."""
    value = (hook.curl or "").strip()
    if not value:
        raise ValueError("%s%s%s is empty" % (PREFIX, hook.key, CURL_SUFFIX))
    argv = [value] if Path(value).is_file() else split_command(value)
    if not argv:
        raise ValueError("%s%s%s holds no command" % (PREFIX, hook.key, CURL_SUFFIX))
    if argv[0].lower().endswith(".py") and Path(argv[0]).is_file():
        argv = [python or sys.executable, *argv]
    return argv

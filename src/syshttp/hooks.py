"""URL hooks: a wrapper a curl front end runs, or a callable ``syshttp``
calls, for requests whose URL matches a pattern -- declared in the
environment, under the prefix of an :class:`~syshttp.env.HTTPEnv` (``<P>``,
``SYSHTTP`` by default). ``<P>_HOOKS_<KEY>`` (plural) declares a hook;
``<P>_HOOK_<NAME>`` (singular) is a variable one hook RUN exports to its
wrapper. With the prefix ``""`` no hook is read.

    <P>_HOOKS_<KEY>=<regex>               matched (re.search) against the URL the
                                          caller asked for -- the origin URL, never
                                          the proxy's or a prefix gateway's rewrite
    <P>_HOOKS_<KEY>_CURL=<command>        a curl front end runs THIS instead of
                                          itself, with its own argv appended
    <P>_HOOKS_<KEY>_PY=<module:callable>  syshttp calls it before the request:
                                          callable(session, method, url, kwargs)

A hook does what it wants with the session (log in, set a header in
``kwargs["headers"]``, refresh a token in the jar) and returns ``None`` to
let the request proceed; anything else it returns is used AS the response
(a cached or synthetic one). ``kwargs`` is the request's keyword arguments,
mutable in place. ``<module:callable>`` is importable from ``sys.path`` or
a ``<path>.py:callable`` file.

The curl wrapper is a shell-quoted command line -- a program and its own
arguments -- that the front end's whole argv is appended to::

    SYSHTTP_HOOKS_X_CURL='cmd fetch --'   ->   cmd fetch -- "$@"

Quote (single or double) what has spaces; a backslash is literal on every
platform, so a Windows path needs no doubling. A first word that is a
``.py`` file runs under the front end's interpreter. The wrapper receives
(:func:`wrapper_environment`) ``<P>_HOOK_URL`` (the requested URL, so it need
not parse argv), ``<P>_HOOK_KEY`` (which hook matched), ``<P>_HOOK_CURL``
naming the front end so it can call curl back after its own work, and
``<P>_HOOK_SKIP`` carrying its KEY, so that call does not run the same
wrapper again. A hook with only a ``_PY`` target is ignored by a curl front
end, one with only ``_CURL`` by syshttp.

Several hooks may match one URL: syshttp calls each in KEY order (sorted),
the first returning a response ends the chain; a curl front end runs the
first ``_CURL`` in that order. A pattern that does not compile is a
configuration error (``ValueError`` naming the variable) the first time it
would be consulted.
"""

from __future__ import annotations

import importlib
import importlib.util
import re
import shlex
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

from .env import HTTPEnv

if TYPE_CHECKING:  # requests is optional at runtime: types only
    import requests

#: What a ``_PY`` hook is: ``(session, method, url, kwargs) -> None | response``.
PyHook = Callable[["requests.Session", str, str, Dict[str, Any]], "Optional[requests.Response]"]

#: The settings, as ``<P>_<NAME>``: ``HOOKS`` + KEY declares a hook, the
#: ``HOOK_*`` ones are what a hook run exports to its wrapper.
HOOKS = "HOOKS_"
CURL_SUFFIX = "_CURL"
PY_SUFFIX = "_PY"
HOOK_SKIP = "HOOK_SKIP"
HOOK_URL = "HOOK_URL"
HOOK_KEY = "HOOK_KEY"
HOOK_CURL = "HOOK_CURL"


def _env(env: Optional[HTTPEnv]) -> HTTPEnv:
    return HTTPEnv() if env is None else env


class Hook(object):
    """One declared hook. ``variable`` is the name of the variable declaring
    it (``SYSHTTP_HOOKS_X``), which every message about the hook names."""

    __slots__ = ("key", "pattern", "curl", "py", "variable")

    def __init__(
        self,
        key: str,
        pattern: "re.Pattern[str]",
        curl: Optional[str],
        py: Optional[str],
        variable: Optional[str] = None,
    ):
        self.key = key
        self.pattern = pattern
        self.curl = curl
        self.py = py
        self.variable = variable or HOOKS + key

    def matches(self, url: str) -> bool:
        return self.pattern.search(url) is not None

    def __repr__(self) -> str:
        return "Hook(%s, %r%s%s)" % (
            self.key,
            self.pattern.pattern,
            ", curl" if self.curl else "",
            ", py" if self.py else "",
        )


def hooks_from_env(*, env: Optional[HTTPEnv] = None) -> List[Hook]:
    """Every configured hook, in KEY order. A ``_CURL``/``_PY`` variable whose
    KEY has no pattern is ignored (nothing to match)."""
    env = _env(env)
    found = dict(env.family(HOOKS))
    hooks = []
    for key, value in found.items():
        if key.endswith((CURL_SUFFIX, PY_SUFFIX)):
            continue
        variable = env.name(HOOKS + key) or HOOKS + key
        try:
            pattern = re.compile(value)
        except re.error as exc:
            raise ValueError("%s is not a valid regular expression: %s" % (variable, exc))
        curl = found.get(key + CURL_SUFFIX) or None
        py = found.get(key + PY_SUFFIX) or None
        if curl or py:
            hooks.append(Hook(key, pattern, curl, py, variable))
    return hooks


def skipped(*, env: Optional[HTTPEnv] = None) -> "set[str]":
    """The KEYs ``<P>_HOOK_SKIP`` (a comma list) says not to run."""
    return {k.strip() for k in (_env(env).get(HOOK_SKIP) or "").split(",") if k.strip()}


def matching(url: str, *, kind: Optional[str] = None, env: Optional[HTTPEnv] = None) -> List[Hook]:
    """The hooks for ``url`` (the caller's URL), KEY order, minus the skipped
    ones; ``kind`` (``"curl"`` / ``"py"``) keeps only hooks with that target."""
    skip = skipped(env=env)
    out = []
    for hook in hooks_from_env(env=env):
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
        name = "syshttp_hook_" + re.sub(r"\W", "_", path.stem)
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
    session: "requests.Session",
    method: str,
    url: str,
    kwargs: Dict[str, Any],
    *,
    env: Optional[HTTPEnv] = None,
) -> "Optional[requests.Response]":
    """Run every ``_PY`` hook matching ``url`` in order; the first non-None
    result is returned (the caller uses it as the response), else ``None``."""
    for hook in matching(url, kind="py", env=env):
        if not hook.py:  # `kind="py"` already filtered; for the type checker
            continue
        try:
            fn = load_callable(hook.py)
            result = fn(session, method, url, kwargs)
        except Exception as exc:
            # The variable, so the failure is traceable to its declaration
            # (the URL is the caller's; the exception carries the rest).
            raise RuntimeError(
                "%s%s (%s) failed for %s %s: %s" % (hook.variable, PY_SUFFIX, hook.py, method, url, exc)
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
    """The argv prefix a ``_CURL`` target means, the front end's argv to be
    appended: the shell-quoted command line split; a bare path to an existing
    file (spaces and all) is that one program; a first word that is a ``.py``
    file runs under ``python`` (default: this interpreter)."""
    value = (hook.curl or "").strip()
    if not value:
        raise ValueError("%s%s is empty" % (hook.variable, CURL_SUFFIX))
    argv = [value] if Path(value).is_file() else split_command(value)
    if not argv:
        raise ValueError("%s%s holds no command" % (hook.variable, CURL_SUFFIX))
    if argv[0].lower().endswith(".py") and Path(argv[0]).is_file():
        argv = [python or sys.executable, *argv]
    return argv


def wrapper_environment(hook: Hook, url: str, entry: str, *, env: Optional[HTTPEnv] = None) -> Dict[str, str]:
    """The variables a ``_CURL`` wrapper run adds to its environment:
    ``<P>_HOOK_URL`` (``url``), ``<P>_HOOK_KEY``, ``<P>_HOOK_CURL`` (``entry``,
    the front end to call back) and ``<P>_HOOK_SKIP`` with this KEY added, so
    the call back does not run the wrapper again. Empty under the prefix ``""``."""
    env = _env(env)
    names = [env.name(setting) for setting in (HOOK_URL, HOOK_KEY, HOOK_CURL, HOOK_SKIP)]
    url_var, key_var, curl_var, skip_var = names
    if not (url_var and key_var and curl_var and skip_var):
        return {}
    skip = ",".join(sorted(skipped(env=env) | {hook.key}))
    return {url_var: url, key_var: hook.key, curl_var: entry, skip_var: skip}

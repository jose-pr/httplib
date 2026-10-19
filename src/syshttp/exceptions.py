"""What syshttp raises when something goes wrong at run time.

A caller's mistake -- a bad argument, two options that contradict -- is a plain
``ValueError`` or ``TypeError``, not one of these. Every message names the
setting or the key involved and never a secret's value."""

from __future__ import annotations

__all__ = ("ConfigurationError", "HookError", "ResponseError", "SysHTTPError")


class SysHTTPError(Exception):
    """The base of every error syshttp raises for what went wrong at run time
    (proxylib's and requests' own errors pass through as they are)."""


class ConfigurationError(SysHTTPError, ValueError):
    """A setting, or a stored credential, that cannot be used: a malformed
    environment variable, a hook that is not loadable, a token with a line
    break in it. The message names the variable or the key."""


class HookError(SysHTTPError, RuntimeError):
    """A ``_PY`` URL hook failed. The hook's own exception is the ``__cause__``."""


class ResponseError(SysHTTPError, ValueError):
    """A response whose body is not what the helper was asked for (JSON that is
    not JSON)."""

"""The transport a client uses when it is given none: the one the
`SYSHTTP_DEFAULT_TRANSPORT` setting names, else syshttp's own."""

from __future__ import annotations

import typing as _ty

from ..env import HTTPEnv
from ..exceptions import ConfigurationError
from ..hooks import load_object
from ._transport import HTTPTransport, Transport

DEFAULT_TRANSPORT = "SYSHTTP_DEFAULT_TRANSPORT"
"""The setting naming the transport of a client given none: an object reference
`module:attr` or `<file>.py:attr` (a dotted `attr` is allowed). The object is
the transport when it has `send()`; otherwise it is called with no arguments
to build one (a class, a factory). It names code to import: never let an
untrusted party set it."""


def _resolve(value: str) -> _ty.Any:
    """The object a setting value names. Short names for known transports
    would be resolved here."""
    return load_object(value, "a transport")


def transport_source(env: HTTPEnv, options: "_ty.Mapping[str, _ty.Any]") -> "tuple[_ty.Callable[[], Transport], bool]":
    """How a client with no `transport=` gets one: `(make, owned)`, where
    `make()` returns the transport and `owned` says whether the client built
    it and so closes it. `options` are the keywords of `HTTPTransport`.

    Without the setting `make` builds an `HTTPTransport` from `options`. With
    it, `options` must be left at their defaults: they configure syshttp's own
    transport. Anything that cannot be loaded, called or used as a transport is
    a `ConfigurationError` naming the variable."""
    found = env.find(DEFAULT_TRANSPORT)
    if found is None:
        return (lambda: HTTPTransport(env=env, **options)), True
    variable, value = found
    given = sorted(name for name, option in options.items() if option is not (True if name == "verify" else None))
    if given:
        raise ConfigurationError(
            "%s names a transport of its own: %s configure syshttp's, not that one" % (variable, ", ".join(given))
        )
    try:
        named = _resolve(value)
    except ConfigurationError as error:
        raise ConfigurationError("%s: %s" % (variable, error)) from None
    except Exception as error:
        raise ConfigurationError(
            "%s names %r, which cannot be loaded (%s: %s)" % (variable, value, type(error).__name__, error)
        ) from error
    if not isinstance(named, type) and callable(getattr(named, "send", None)):
        return (lambda: named), False
    if not callable(named):
        raise ConfigurationError(
            "%s names %r, which is neither a transport nor something that makes one" % (variable, value)
        )

    def make() -> Transport:
        try:
            made = named()
        except Exception as error:
            raise ConfigurationError(
                "%s names %r, which failed to make a transport (%s: %s)"
                % (variable, value, type(error).__name__, error)
            ) from error
        if not callable(getattr(made, "send", None)):
            raise ConfigurationError("%s names %r, which makes no object with send()" % (variable, value))
        return made

    return make, True

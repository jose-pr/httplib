"""Text/JSON request helpers and a retry-once-on-auth-failure wrapper.

Every helper returns the response's status with its body; a status is never
an exception (a session built by :func:`~syshttp.session.new_session` returns
the last response when its retries run out). A connection that never
succeeds, or a timeout, still raises requests' exception."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, Tuple, Union

from .auth import AuthProvider
from .exceptions import ResponseError
from .session import new_session

if TYPE_CHECKING:  # requests is optional at runtime: types only
    import requests

__all__ = (
    "request_json",
    "request_json_auto",
    "request_text",
    "request_text_auto",
    "request_with_reauth",
)

VerifyT = Union[bool, str, Path]
#: What requests accepts: seconds, or a ``(connect, read)`` pair.
TimeoutT = Union[float, Tuple[float, float]]


def request_text(
    session: "requests.Session",
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    data: Any = None,
    json_body: Any = None,
    timeout: TimeoutT = 60,
    verify: Optional[VerifyT] = None,
) -> Tuple[int, str]:
    """Send one request through ``session`` and return ``(status, text)``.

    ``json_body`` is sent as JSON, ``data`` as the body otherwise. ``verify``
    is requests' per-request value (``None``: the session's); beside a
    session's ``ssl_context`` it raises ``ValueError``. The session is left
    open."""
    req_kwargs: Dict[str, Any] = {"headers": headers or {}, "timeout": timeout}
    if data is not None:
        req_kwargs["data"] = data
    if json_body is not None:
        req_kwargs["json"] = json_body
    if verify is not None:
        req_kwargs["verify"] = str(verify) if isinstance(verify, Path) else verify
    resp = session.request(method=method, url=url, **req_kwargs)
    return int(resp.status_code), resp.text


def request_json(
    session: "requests.Session",
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    data: Any = None,
    json_body: Any = None,
    timeout: TimeoutT = 60,
    verify: Optional[VerifyT] = None,
) -> Tuple[int, Any]:
    """:func:`request_text` with the body parsed as JSON: ``(status, value)``,
    ``(status, None)`` for an empty body. A body that is not JSON raises
    ``ValueError`` naming the status."""
    status, text = request_text(
        session,
        method,
        url,
        headers=headers,
        data=data,
        json_body=json_body,
        timeout=timeout,
        verify=verify,
    )
    if not text:
        return status, None
    try:
        return status, json.loads(text)
    except json.JSONDecodeError as e:
        raise ResponseError("response was not valid JSON (HTTP %d)" % status) from e


def request_with_reauth(
    session: "requests.Session",
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    data: Any = None,
    json_body: Any = None,
    timeout: TimeoutT = 60,
    verify: Optional[VerifyT] = None,
    auth_fail_statuses=(401, 403),
    reauth_cb: Optional[Callable[[], None]] = None,
    auth_provider: Optional[AuthProvider] = None,
) -> Tuple[int, str]:
    """:func:`request_text`, sent a second time after a status in
    ``auth_fail_statuses`` once ``auth_provider.ensure(session, url)`` and
    then ``reauth_cb()`` have run (with neither, the first answer is
    returned). The session is left open."""
    status, text = request_text(
        session,
        method,
        url,
        headers=headers,
        data=data,
        json_body=json_body,
        timeout=timeout,
        verify=verify,
    )
    if (reauth_cb or auth_provider) and status in set(auth_fail_statuses):
        if auth_provider:
            auth_provider.ensure(session, url)
        if reauth_cb:
            reauth_cb()
        status, text = request_text(
            session,
            method,
            url,
            headers=headers,
            data=data,
            json_body=json_body,
            timeout=timeout,
            verify=verify,
        )
    return status, text


def request_text_auto(
    method: str,
    url: str,
    *,
    session: "Optional[requests.Session]" = None,
    headers: Optional[Dict[str, str]] = None,
    data: Any = None,
    json_body: Any = None,
    timeout: TimeoutT = 60,
    **session_options: Any,
) -> Tuple[int, str]:
    """:func:`request_text` on ``session``, or on a session built from
    ``session_options`` (any keyword of :func:`~syshttp.session.new_session`:
    ``env``, ``proxies``, ``retries``, ``ssl_context``, ...; ignored when
    ``session`` is given). A session built here is closed after the call; a
    session passed in is left open."""
    if session is not None:
        return request_text(session, method, url, headers=headers, data=data, json_body=json_body, timeout=timeout)
    with new_session(**session_options) as own:
        return request_text(own, method, url, headers=headers, data=data, json_body=json_body, timeout=timeout)


def request_json_auto(
    method: str,
    url: str,
    *,
    session: "Optional[requests.Session]" = None,
    headers: Optional[Dict[str, str]] = None,
    data: Any = None,
    json_body: Any = None,
    timeout: TimeoutT = 60,
    **session_options: Any,
) -> Tuple[int, Any]:
    """:func:`request_json` on ``session``, or on a session built from
    ``session_options`` as :func:`request_text_auto` does, and closed after
    the call."""
    if session is not None:
        return request_json(session, method, url, headers=headers, data=data, json_body=json_body, timeout=timeout)
    with new_session(**session_options) as own:
        return request_json(own, method, url, headers=headers, data=data, json_body=json_body, timeout=timeout)

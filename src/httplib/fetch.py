"""Text/JSON request helpers and a retry-once-on-auth-failure wrapper."""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, Tuple, Union

from .auth import AuthProvider
from .jar import CookieJar, TokenJar
from .session import new_session

if TYPE_CHECKING:  # requests is optional at runtime: types only
    import requests

VerifyT = Union[bool, str, Path]


def request_text(
    session: "requests.Session",
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    data: Any = None,
    json_body: Any = None,
    timeout: int = 60,
    verify: Optional[VerifyT] = None,
) -> Tuple[int, str]:
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
    timeout: int = 60,
    verify: Optional[VerifyT] = None,
) -> Tuple[int, Any]:
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
        raise ValueError("response was not valid JSON (HTTP %d)" % status) from e


def request_with_reauth(
    session: "requests.Session",
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    data: Any = None,
    json_body: Any = None,
    timeout: int = 60,
    verify: Optional[VerifyT] = None,
    auth_fail_statuses=(401, 403),
    reauth_cb: Optional[Callable[[], None]] = None,
    auth_provider: Optional[AuthProvider] = None,
) -> Tuple[int, str]:
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
    user_agent: Optional[str] = None,
    proxies: Optional[dict] = None,
    verify: VerifyT = True,
    retries: int = 3,
    backoff: float = 1,
    status_forcelist=(429, 500, 502, 503, 504),
    cookies: Union[bool, str, CookieJar] = False,
    tokens: Union[bool, str, TokenJar] = False,
    auth_provider: Optional[AuthProvider] = None,
    headers: Optional[Dict[str, str]] = None,
    data: Any = None,
    json_body: Any = None,
    timeout: int = 60,
) -> Tuple[int, str]:
    if session is None:
        session = new_session(
            user_agent=user_agent,
            proxies=proxies,
            verify=verify,
            retries=retries,
            backoff=backoff,
            status_forcelist=status_forcelist,
            cookies=cookies,
            tokens=tokens,
            auth_provider=auth_provider,
        )
    return request_text(
        session,
        method,
        url,
        headers=headers,
        data=data,
        json_body=json_body,
        timeout=timeout,
    )


def request_json_auto(
    method: str,
    url: str,
    *,
    session: "Optional[requests.Session]" = None,
    user_agent: Optional[str] = None,
    proxies: Optional[dict] = None,
    verify: VerifyT = True,
    retries: int = 3,
    backoff: float = 1,
    status_forcelist=(429, 500, 502, 503, 504),
    cookies: Union[bool, str, CookieJar] = False,
    tokens: Union[bool, str, TokenJar] = False,
    auth_provider: Optional[AuthProvider] = None,
    headers: Optional[Dict[str, str]] = None,
    data: Any = None,
    json_body: Any = None,
    timeout: int = 60,
) -> Tuple[int, Any]:
    if session is None:
        session = new_session(
            user_agent=user_agent,
            proxies=proxies,
            verify=verify,
            retries=retries,
            backoff=backoff,
            status_forcelist=status_forcelist,
            cookies=cookies,
            tokens=tokens,
            auth_provider=auth_provider,
        )
    return request_json(
        session,
        method,
        url,
        headers=headers,
        data=data,
        json_body=json_body,
        timeout=timeout,
    )

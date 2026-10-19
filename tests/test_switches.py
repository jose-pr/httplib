"""SYSHTTP_PROXY_AUTH_HEADER names the header the proxy credential rides in;
syshttp's typing imports requests only under TYPE_CHECKING."""

import subprocess
import sys
from pathlib import Path

import pytest

from syshttp import proxy as agent_proxy
from test_jars_proxy import _Gateway, gateway, origin  # noqa: F401  (fixtures reused)
from test_proxy_auth import BEARER, _clean_env  # noqa: F401

SRC = Path(__file__).resolve().parents[1] / "src"


def test_auth_header_name_defaults_and_validates(monkeypatch):
    assert agent_proxy.auth_header() == "Proxy-Authorization"
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH_HEADER", " X-Proxy-Token ")
    assert agent_proxy.auth_header() == "X-Proxy-Token"
    monkeypatch.setenv("SYSHTTP_PROXY_AUTH_HEADER", "")
    assert agent_proxy.auth_header() == "Proxy-Authorization"
    for bad in ("X-Token: x", "two words"):
        monkeypatch.setenv("SYSHTTP_PROXY_AUTH_HEADER", bad)
        with pytest.raises(ValueError, match="SYSHTTP_PROXY_AUTH_HEADER"):
            agent_proxy.auth_header()


def test_session_uses_the_configured_header_name(origin, gateway, monkeypatch):
    pytest.importorskip("requests")
    from syshttp.session import new_session

    monkeypatch.setenv("SYSHTTP_PROXY_AUTH_HEADER", "X-Proxy-Token")
    session = new_session(retries=0)
    # connect: the header the proxy entry carries to the proxy alone
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "connect")
    adapter = session.get_adapter("https://api.example.com/")
    (entry,) = adapter.route("https://api.example.com/")
    assert entry.headers == {"X-Proxy-Token": BEARER}
    monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "prefix:/fetch/")
    # prefix: a header of the gateway request
    session.get(origin + "/x", timeout=5)
    seen = _Gateway.seen[-1][1]
    assert seen.get("X-Proxy-Token") == BEARER and "Proxy-Authorization" not in seen


def test_syshttp_typing_never_imports_requests_at_runtime():
    """The annotations name requests' types under TYPE_CHECKING only: the
    dependency-free modules stay dependency-free, and session/fetch import
    requests lazily, inside new_session."""
    code = (
        "import sys; sys.path.insert(0, %r); "
        "import syshttp.session, syshttp.fetch, syshttp.hooks, syshttp.cookies, syshttp.auth, syshttp.jar; "
        "print('requests' in sys.modules)" % str(SRC)
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout.strip()
    assert out == "False"


def test_syshttp_type_checks_clean():
    """The annotations hold: mypy over src/syshttp reports nothing (skipped
    where mypy is not installed)."""
    mypy_api = pytest.importorskip("mypy.api")
    try:
        out, err, rc = mypy_api.run(
            [
                "--python-version",
                "3.10",
                "--ignore-missing-imports",
                "--no-error-summary",
                str(SRC / "syshttp"),
            ]
        )
    except AssertionError as exc:
        # mypy itself failing, not a type error: the newest types-requests names
        # urllib3 modules (urllib3.http2) that urllib3's own floor lacks.
        pytest.skip("mypy cannot read the installed stubs against this urllib3: %s" % exc)
    assert rc == 0, out + err

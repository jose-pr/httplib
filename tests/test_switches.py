"""SYSHTTP_PROXY_AUTH_HEADER names the header the proxy credential rides in;
requests is the business of syshttp.autopatch alone."""

import ast
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


def test_the_client_uses_the_configured_header_name(origin, gateway, monkeypatch):
    from syshttp.client import HTTPClient

    monkeypatch.setenv("SYSHTTP_PROXY_AUTH_HEADER", "X-Proxy-Token")
    with HTTPClient() as client:
        # connect: the header goes to the proxy, on its plain-http request
        monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "connect")
        client.request("GET", origin + "/x", timeout=5)
        seen = _Gateway.seen[-1][1]
        assert seen.get("X-Proxy-Token") == BEARER and "Proxy-Authorization" not in seen
        # prefix: a header of the gateway request
        monkeypatch.setenv("SYSHTTP_PROXY_TYPE", "prefix:/fetch/")
        client.request("GET", origin + "/y", timeout=5)
        path, seen = _Gateway.seen[-1]
        assert path == "/fetch/" + origin + "/y"
        assert seen.get("X-Proxy-Token") == BEARER and "Proxy-Authorization" not in seen


def test_syshttp_typing_never_imports_requests_at_runtime():
    """The client, the hooks and the jars never import requests: only
    syshttp.autopatch does, for the program that imports it."""
    code = (
        "import sys; sys.path.insert(0, %r); "
        "import syshttp, syshttp.client, syshttp.hooks, syshttp.cookies, syshttp.auth, syshttp.jar; syshttp.fetch; "
        "print('requests' in sys.modules)" % str(SRC)
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout.strip()
    assert out == "False"


def test_no_module_but_autopatch_names_requests_or_urllib3_at_runtime():
    """No import of requests or urllib3, and no import by name, outside
    syshttp.autopatch (a docstring or a TYPE_CHECKING block may name them)."""
    found = []
    for path in sorted((SRC / "syshttp").rglob("*.py")):
        if path.name == "autopatch.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        guarded = {
            id(child)
            for node in ast.walk(tree)
            if isinstance(node, ast.If) and "TYPE_CHECKING" in ast.dump(node.test)
            for child in ast.walk(node)
        }
        for node in ast.walk(tree):
            if id(node) in guarded:
                continue
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                names = [node.value] if node.value.split(".")[0] in ("requests", "urllib3") else []
            else:
                continue
            if any(name.split(".")[0] in ("requests", "urllib3") for name in names):
                found.append("%s:%d" % (path.relative_to(SRC), node.lineno))
    assert found == []


_WITHOUT_REQUESTS = """
import sys, threading
sys.path.insert(0, %r)
sys.modules["requests"] = None
sys.modules["urllib3"] = None
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()

import syshttp.client, syshttp.hooks, syshttp.cookies, syshttp.auth, syshttp.jar, syshttp.proxy, syshttp.tls
from syshttp import fetch

response = fetch("http://127.0.0.1:%%d/" %% server.server_port, retries=0, cookies=False)
print(response.status, response.json())
server.shutdown()
server.server_close()
"""


def test_fetch_works_with_requests_and_urllib3_absent():
    """The done-when of dropping the session: the client and fetch() run with
    neither package importable."""
    out = subprocess.run(
        [sys.executable, "-c", _WITHOUT_REQUESTS % str(SRC)], capture_output=True, text=True, timeout=120
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "200 {'ok': True}"


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

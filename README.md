# syshttp

[![Version](https://img.shields.io/pypi/v/syshttp.svg)](https://pypi.org/project/syshttp/)
[![Python versions](https://img.shields.io/pypi/pyversions/syshttp.svg)](https://pypi.org/project/syshttp/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jose-pr/syshttp/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://jose-pr.github.io/syshttp/)
[![CI](https://img.shields.io/github/actions/workflow/status/jose-pr/syshttp/test.yml)](https://github.com/jose-pr/syshttp/actions/workflows/test.yml)

**HTTP plumbing that behaves the same in every client you build on it**:
which proxy to use, with which credential, for which hosts; how a prefix
gateway is spoken to; which cookies and tokens go with which origin; and TLS
through the operating system's own certificate verifier. By default it
routes the way the system does: the system's proxy configuration, PAC scripts
and WPAD included, unless a proxy variable says otherwise. An optional
`requests` session puts all of them
together. Documentation: <https://jose-pr.github.io/syshttp/>.

## Features

- **The system's proxy, by default** — with no proxy variable set, the
  system's configuration decides per URL: WinHTTP on Windows, CFNetwork on
  macOS, libproxy or the desktop's settings elsewhere, PAC and WPAD included
  (through [proxylib](https://pypi.org/project/proxylib/)).
- **Proxies with credentials** — a proxy URL from `SYSHTTP_PROXY` or the
  usual `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`. The `Proxy-Authorization`
  value is sent verbatim, so any scheme works (`Basic`, `Bearer`,
  `Negotiate`). `NO_PROXY` is honoured, and every redirect hop is decided
  again.
- **Prefix gateways** — `SYSHTTP_PROXY_TYPE=prefix:/fetch/` sends
  `GET https://api.example.com/x` to `<proxy>/fetch/https://api.example.com/x`.
  Responses, redirects and cookies still use the caller's URL.
- **One prefix for every setting** — `SYSHTTP_PREFIX=MYTOOL` makes the
  package read `MYTOOL_PROXY`, `MYTOOL_HOME` and so on. An `HTTPEnv(prefix=...)`
  object keeps one configuration apart from another in the same process.
- **Cookie and token jars** — Netscape cookie files with curl's matching
  rules, plus per-host token files. Both are chosen by the origin's host,
  never by the proxy's or the gateway's.
- **URL hooks** — `SYSHTTP_HOOKS_<KEY>=<regex>` plus `_PY=module:callable`
  runs your code before matching requests: a login, a signature, a canned
  response.
- **The system's TLS client, or your own TLS context** — by default
  [sslcontext](https://pypi.org/project/sslcontext/)'s system context: the
  operating system verifies certificates (CryptoAPI, the Security framework),
  with no `certifi` bundle involved, and a server that asks for a client
  certificate gets one from the OS store (smart cards included), chosen as a
  browser chooses. Or `new_session(ssl_context=...)` for a given identity, a
  cipher list or a pinned protocol version.
- **A configured `requests.Session`** — retry with backoff, all of the above
  applied in one transport adapter.

## Installation

```bash
pip install syshttp
```

| Extra | Adds | Needed for |
| --- | --- | --- |
| `session` | `requests` (with `urllib3`) | `syshttp.session` and `syshttp.fetch` |
| `pac` | a JavaScript engine for proxylib | PAC scripts proxylib evaluates itself (Linux without libproxy) |

syshttp depends on proxylib (the system proxy) and sslcontext (the system's
TLS client: the OS verifier through truststore on Python 3.10+, OpenSSL over
the default store on 3.9).

## Quick start

Resolve the proxy and its credential the way every client here does:

```python
from syshttp import proxy

plan = proxy.plan()            # None when no proxy is configured
if plan and not plan.bypasses("https://api.example.com/"):
    print(proxy.redact(plan.proxy), plan.auth_header)
```

A session with file-backed cookies and tokens (`pip install 'syshttp[session]'`):

```python
from syshttp.session import new_session
from syshttp.fetch import request_json

s = new_session(cookies=True, tokens=True)
status, body = request_json(s, "GET", "https://api.example.com/thing")
```

A separate configuration, isolated from the process environment:

```python
from syshttp import HTTPEnv
from syshttp.session import new_session

env = HTTPEnv("MYTOOL", environ={"MYTOOL_PROXY": "http://proxy.internal:3128"})
s = new_session(env=env)
```

## API overview

| Module | Purpose |
| --- | --- |
| `syshttp.env` | `HTTPEnv`: the prefix and mapping every setting is read from |
| `syshttp.proxy` | the proxy, its credential, its kind, `NO_PROXY`; `plan()` decides all of it |
| `syshttp.session` | `new_session()`: a configured `requests.Session` |
| `syshttp.fetch` | text and JSON request helpers, retry once after a 401/403 |
| `syshttp.jar` | file and memory cookie/token jars |
| `syshttp.cookies` | Netscape cookie files and curl's cookie rules |
| `syshttp.hooks` | URL hooks declared in the environment |
| `syshttp.tls` | the OS verifier as an `SSLContext` |
| `syshttp.retry` | the transient statuses, `Retry-After` |

## Settings

Every setting is `<PREFIX>_<NAME>`, with the prefix from `SYSHTTP_PREFIX`
(default `SYSHTTP`). The full list is on the docs site:
<https://jose-pr.github.io/syshttp/settings/>.

| Variable | Sets |
| --- | --- |
| `SYSHTTP_PREFIX` | the prefix of every other setting |
| `SYSHTTP_PROXY` | the proxy URL; else `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, else the system's |
| `SYSHTTP_SYSTEM_PROXY` | `0` to stop consulting the system's proxy configuration |
| `SYSHTTP_PROXY_AUTH` | the proxy credential, sent verbatim; else `HTTP_PROXY_AUTH` |
| `SYSHTTP_PROXY_AUTH_HEADER` | the header it is sent in (default `Proxy-Authorization`) |
| `SYSHTTP_PROXY_TYPE` | `connect` (default) or `prefix[:/endpoint]` |
| `SYSHTTP_HOME` | the jar directory (default: the per-user state directory) |
| `SYSHTTP_HOOKS_<KEY>` | a URL hook's pattern, with `_PY` / `_CURL` targets |

## Development

```bash
dotagents pyvenv            # or any Python 3.9+ virtual environment
.pyvenv/<tag>/Scripts/python -m pip install -e ".[dev]"
.pyvenv/<tag>/Scripts/python -m pytest -q
```

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](https://github.com/jose-pr/syshttp/blob/main/CHANGELOG.md).
Pushing a tag matching `v*` triggers the release workflow: test gate → build
(checking the tag names the version built) → a strict docs build as a gate →
GitHub release → publish. The release workflow never deploys the docs site
itself: for a final release its last job dispatches the docs workflow at the
tag, which owns every Pages deploy.

## License

MIT — see [LICENSE](https://github.com/jose-pr/syshttp/blob/main/LICENSE).

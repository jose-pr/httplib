# httplib

[![Version](https://img.shields.io/pypi/v/httplib.svg)](https://pypi.org/project/httplib/)
[![Python versions](https://img.shields.io/pypi/pyversions/httplib.svg)](https://pypi.org/project/httplib/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jose-pr/httplib/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://jose-pr.github.io/httplib/)
[![CI](https://img.shields.io/github/actions/workflow/status/jose-pr/httplib/test.yml)](https://github.com/jose-pr/httplib/actions/workflows/test.yml)

**HTTP plumbing that behaves the same in every client you build on it**:
which proxy to use, with which credential, for which hosts; how a prefix
gateway is spoken to; which cookies and tokens go with which origin; and TLS
through the operating system's trust store. The building blocks need only
the standard library, and an optional `requests` session puts all of them
together. Documentation: <https://jose-pr.github.io/httplib/>.

## Features

- **Proxies with credentials** — a proxy URL from `HTTPLIB_PROXY` or the
  usual `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`. The `Proxy-Authorization`
  value is sent verbatim, so any scheme works (`Basic`, `Bearer`,
  `Negotiate`). `NO_PROXY` is honoured, and every redirect hop is decided
  again.
- **Prefix gateways** — `HTTPLIB_PROXY_TYPE=prefix:/fetch/` sends
  `GET https://api.example.com/x` to `<proxy>/fetch/https://api.example.com/x`.
  Responses, redirects and cookies still use the caller's URL.
- **One prefix for every setting** — `HTTPLIB_PREFIX=MYTOOL` makes the
  package read `MYTOOL_PROXY`, `MYTOOL_HOME` and so on. An `HTTPEnv(prefix=...)`
  object keeps one configuration apart from another in the same process.
- **Cookie and token jars** — Netscape cookie files with curl's matching
  rules, plus per-host token files. Both are chosen by the origin's host,
  never by the proxy's or the gateway's.
- **URL hooks** — `HTTPLIB_HOOKS_<KEY>=<regex>` plus `_PY=module:callable`
  runs your code before matching requests: a login, a signature, a canned
  response.
- **OS trust store, or your own TLS context** — an `ssl.SSLContext` from the
  system's certificates with no `certifi` bundle involved, or
  `new_session(ssl_context=...)` for mutual TLS, a cipher list or a pinned
  protocol version (for example a keystore identity built with
  `sslcontext`).
- **A configured `requests.Session`** — retry with backoff, all of the above
  applied in one transport adapter.

## Installation

```bash
pip install httplib
```

| Extra | Adds | Needed for |
| --- | --- | --- |
| `session` | `requests` (with `urllib3`) | `httplib.session` and `httplib.fetch` |

## Quick start

Resolve the proxy and its credential the way every client here does:

```python
from httplib import proxy

plan = proxy.plan()            # None when no proxy is configured
if plan and not plan.bypasses("https://api.example.com/"):
    print(proxy.redact(plan.proxy), plan.auth_header)
```

A session with file-backed cookies and tokens (`pip install 'httplib[session]'`):

```python
from httplib.session import new_session
from httplib.fetch import request_json

s = new_session(cookies=True, tokens=True)
status, body = request_json(s, "GET", "https://api.example.com/thing")
```

A separate configuration, isolated from the process environment:

```python
from httplib import HTTPEnv
from httplib.session import new_session

env = HTTPEnv("MYTOOL", environ={"MYTOOL_PROXY": "http://proxy.internal:3128"})
s = new_session(env=env)
```

## API overview

| Module | Purpose |
| --- | --- |
| `httplib.env` | `HTTPEnv`: the prefix and mapping every setting is read from |
| `httplib.proxy` | the proxy, its credential, its kind, `NO_PROXY`; `plan()` decides all of it |
| `httplib.session` | `new_session()`: a configured `requests.Session` |
| `httplib.fetch` | text and JSON request helpers, retry once after a 401/403 |
| `httplib.jar` | file and memory cookie/token jars |
| `httplib.cookies` | Netscape cookie files and curl's cookie rules |
| `httplib.hooks` | URL hooks declared in the environment |
| `httplib.tls` | the OS trust store as an `SSLContext` |
| `httplib.retry` | the transient statuses, `Retry-After` |

## Settings

Every setting is `<PREFIX>_<NAME>`, with the prefix from `HTTPLIB_PREFIX`
(default `HTTPLIB`). The full list is on the docs site:
<https://jose-pr.github.io/httplib/settings/>.

| Variable | Sets |
| --- | --- |
| `HTTPLIB_PREFIX` | the prefix of every other setting |
| `HTTPLIB_PROXY` | the proxy URL; else `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` |
| `HTTPLIB_PROXY_AUTH` | the proxy credential, sent verbatim; else `HTTP_PROXY_AUTH` |
| `HTTPLIB_PROXY_AUTH_HEADER` | the header it is sent in (default `Proxy-Authorization`) |
| `HTTPLIB_PROXY_TYPE` | `connect` (default) or `prefix[:/endpoint]` |
| `HTTPLIB_HOME` | the jar directory (default: the per-user state directory) |
| `HTTPLIB_HOOKS_<KEY>` | a URL hook's pattern, with `_PY` / `_CURL` targets |

## Development

```bash
dotagents pyvenv            # or any Python 3.9+ virtual environment
.pyvenv/<tag>/Scripts/python -m pip install -e ".[dev]"
.pyvenv/<tag>/Scripts/python -m pytest -q
```

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](https://github.com/jose-pr/httplib/blob/main/CHANGELOG.md).
Pushing a tag matching `v*` triggers the release workflow: test gate → build
(checking the tag names the version built) → a strict docs build as a gate →
GitHub release → publish. The release workflow never deploys the docs site
itself: for a final release its last job dispatches the docs workflow at the
tag, which owns every Pages deploy.

## License

MIT — see [LICENSE](https://github.com/jose-pr/httplib/blob/main/LICENSE).

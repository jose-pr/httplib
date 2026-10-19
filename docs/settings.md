# Settings

Every setting is the environment variable `<P>_<NAME>`. `<P>` is the prefix:
the `prefix` given to an `HTTPEnv`, else `SYSHTTP_PREFIX`, else `SYSHTTP`. A
setting given as an argument wins over its variable, and the variable wins
over the built-in default. Variables are read when they are needed, never at
import.

| Variable | Sets | Default |
| --- | --- | --- |
| `SYSHTTP_PREFIX` | the prefix of every variable below | `SYSHTTP` |
| `<P>_PROXY` | the proxy URL | the request's scheme's `*_PROXY` variable, else `ALL_PROXY` (lowercase first); with none set, the system's configuration for the URL |
| `<P>_SYSTEM_PROXY` | whether the system's proxy configuration is consulted (`0`/`false`/`no`/`off` to stop) | on |
| `<P>_PROXY_AUTH` | `<P>_PROXY`'s credential, a header value sent verbatim to it only (a secret) | the URL's userinfo as Basic |
| `HTTP_PROXY_AUTH` | the machine's proxy's credential (a `*_PROXY` variable's or the system's), sent as `Proxy-Authorization` (a secret) | the URL's userinfo as Basic |
| `<P>_PROXY_AUTH_HEADER` | the header `<P>_PROXY_AUTH` rides in | `Proxy-Authorization` |
| `<P>_PROXY_TYPE` | `connect`, or `prefix[:/endpoint]` for a URL-prefix gateway | `connect` |
| `<P>_HOME` | the directory of the cookie and token jars | the per-user state directory |
| `SYSHTTP_IMPORTPATCH` | client libraries patched as they are imported to use the system proxy and TLS: `1` for all, or `:`-separated names from `requests`, `urllib`, `httpx`, `aiohttp`, `pip`. Not `<P>_IMPORTPATCH`: under a prefix of a tool's own it is `<P>_SYSHTTP_IMPORTPATCH`, under the default or empty prefix `SYSHTTP_IMPORTPATCH` | none |
| `<P>_HOOKS_<KEY>` | a URL hook's pattern; `_PY` and `_CURL` name its targets | none |
| `<P>_HOOK_SKIP` | KEYs of hooks not to run | none |
| `NO_PROXY` / `no_proxy` | hosts that never go through the proxy | none |

## One prefix per tool

A tool that embeds syshttp can give it a namespace of its own:

```sh
SYSHTTP_PREFIX=MYTOOL MYTOOL_PROXY=http://proxy.internal:3128 mytool ...
```

Inside one process, separate configurations use separate `HTTPEnv` objects:

```python
from syshttp import HTTPEnv, proxy

corp = HTTPEnv("CORP")                       # CORP_PROXY, CORP_PROXY_AUTH, ...
lab = HTTPEnv("LAB", environ={"LAB_PROXY": "http://lab:8080"})
proxy.proxy_map(env=corp), proxy.proxy_map(env=lab)
```

`HTTPEnv("")` reads only the conventional variables (the `*_PROXY` family,
`NO_PROXY`, `HTTP_PROXY_AUTH`): no package setting and no hook. There is no
default without a prefix, because CGI exports every request header as an
`HTTP_*` variable, and a hook setting names code to import.

## Prefix gateways

```sh
SYSHTTP_PROXY=https://gw.example SYSHTTP_PROXY_TYPE=prefix:/fetch/
```

With these set, `GET https://api.example.com/x` is sent to
`https://gw.example/fetch/https://api.example.com/x`, with the credential as a
header of that request. Redirects, cookies and `response.url` still use the
caller's URL. requests, httpx and urllib follow a gateway; aiohttp is not
offered one (proxylib's `UnsupportedProxyError`).

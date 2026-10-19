# Settings

Every setting is the environment variable `<P>_<NAME>`. `<P>` is the prefix:
the `prefix` given to an `HTTPEnv`, else `SYSHTTP_PREFIX`, else `SYSHTTP`. A
setting given as an argument wins over its variable, and the variable wins
over the built-in default. Variables are read when they are needed, never at
import.

| Variable | Sets | Default |
| --- | --- | --- |
| `SYSHTTP_PREFIX` | the prefix of every variable below | `SYSHTTP` |
| `<P>_PROXY` | the proxy URL | `HTTPS_PROXY` → `HTTP_PROXY` → `ALL_PROXY`, either case, then the system's configuration for the URL |
| `<P>_SYSTEM_PROXY` | whether the system's proxy configuration is consulted (`0`/`false`/`no`/`off` to stop) | on |
| `<P>_PROXY_AUTH` | the proxy credential, a header value sent verbatim (a secret) | `HTTP_PROXY_AUTH`, else the URL's userinfo as Basic |
| `<P>_PROXY_AUTH_HEADER` | the header the credential rides in | `Proxy-Authorization` |
| `<P>_PROXY_TYPE` | `connect`, or `prefix[:/endpoint]` for a URL-prefix gateway | `connect` |
| `<P>_HOME` | the directory of the cookie and token jars | the per-user state directory |
| `<P>_IMPORTPATCH` | client libraries patched as they are imported to use the system proxy and TLS: `1` for all, or names from `requests`, `urllib`, `httpx`, `aiohttp` | none |
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
proxy.plan(env=corp), proxy.plan(env=lab)
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
caller's URL.

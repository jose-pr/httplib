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
| `<P>_COOKIE_HOSTS` | groups of hosts that share cookies: hosts split by `,`, groups by `;` | none |
| `SYSHTTP_IMPORTPATCH` | client libraries patched as they are imported to use the system proxy and TLS: `1` for all, or `:`-separated names from `requests`, `urllib`, `httpx`, `aiohttp`, `pip`. Not `<P>_IMPORTPATCH`: under a prefix of a tool's own it is `<P>_SYSHTTP_IMPORTPATCH`, under the default or empty prefix `SYSHTTP_IMPORTPATCH` | none |
| `<P>_HOOKS_<KEY>` | a URL hook's pattern; `_PY` and `_CURL` name its targets | none |
| `<P>_HOOK_SKIP` | KEYs of hooks not to run | none |
| `NO_PROXY` / `no_proxy` | hosts that never go through the proxy | none |

### Read under their own names

| Variable | Read by | For |
| --- | --- | --- |
| `http_proxy`, `https_proxy`, `ftp_proxy`, `ws_proxy`, `wss_proxy`, `all_proxy` (either case) | the proxy map (proxylib's `EnvProxyConfig`) | the machine's proxy, per scheme |
| `REQUEST_METHOD` | the proxy map | set means CGI: an uppercase `HTTP_PROXY` is then a request header, ignored |
| `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` | `new_session` (and requests) | a CA bundle named in the environment |
| `LOCALAPPDATA` (Windows), `XDG_STATE_HOME` (Linux and other POSIX) | `jar.default_root` | the per-user state directory |
| `IMPORTPATCH_DISABLE` | importpatch | `1` turns every import-time patch off |
| `PROXYLIB_IMPORTPATCH`, `PROXYLIB_AUTOPROXY` | proxylib | proxylib's own patching, beside syshttp's |

A `_CURL` hook's wrapper runs with `<P>_HOOK_URL`, `<P>_HOOK_KEY`,
`<P>_HOOK_CURL` and `<P>_HOOK_SKIP` set (`hooks.wrapper_environment`); a curl
front end reads them back.

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

## Hosts that share cookies

A response may set or delete cookies only for its own host and that host's
parent domains (RFC 6265). When two names reach one service, declare them a
group:

```sh
SYSHTTP_COOKIE_HOSTS="app.example.com,app.example.net;localhost,127.0.0.1"
```

or `new_session(cookie_hosts=[["app.example.com", "app.example.net"]])`.
In a group, a cookie a member sets for itself or for another member belongs
to the first host, every member's requests carry the group's cookies, and
any member can delete them. A `Domain` outside the group is still judged on
the host that sent it.

## Prefix gateways

```sh
SYSHTTP_PROXY=https://gw.example SYSHTTP_PROXY_TYPE=prefix:/fetch/
```

With these set, `GET https://api.example.com/x` is sent to
`https://gw.example/fetch/https://api.example.com/x`, with the credential as a
header of that request. Redirects, cookies and `response.url` still use the
caller's URL. requests, httpx and urllib follow a gateway; aiohttp is not
offered one (proxylib's `UnsupportedProxyError`).

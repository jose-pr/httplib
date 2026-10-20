# `syshttp` — public API header

Header-file-style reference for the `syshttp` package: every public export with
its signature, arguments, contract and gotchas, so the package can be used
without reading its source. It ships inside the package and is
self-contained. Development documentation lives with the source at
<https://github.com/jose-pr/syshttp>.

Import names from their modules: `syshttp.env`, `syshttp.proxy`,
`syshttp.session`, `syshttp.fetch`, `syshttp.jar`, `syshttp.cookies`,
`syshttp.hooks`, `syshttp.tls`, `syshttp.retry`, `syshttp.auth`,
`syshttp.exceptions`, `syshttp.autopatch`. Each declares `__all__`: a name
outside it is not API, and a module whose name starts with `_` is private.
The root re-exports `HTTPEnv`, the exceptions, `NoReachableProxyError`,
`proxy_map`, `configured_proxy` and `proxy_type`.

`pip install syshttp` brings proxylib 2.0.2+ (proxy routing and the system's proxy configuration),
sslcontext (the system's TLS client; truststore on Python 3.10+) and
importpatch (import-time patching of other HTTP clients, off unless
`SYSHTTP_IMPORTPATCH` asks for it). The extra `pac`
adds a JavaScript engine for PAC scripts proxylib evaluates itself (Linux
without libproxy). The extra `session` adds `requests` 2.32.5+ and `urllib3` 2.6.3+ (each
floor is the newest release that supports Python 3.9), which
`syshttp.session` and
`syshttp.fetch` import when a session is built. Without it, `new_session()`
raises `ImportError` saying `pip install 'syshttp[session]'`. Every other
module works without it.

`syshttp.__version__` is the installed distribution's version.

## Settings (`syshttp.env`)

Every setting is a variable with a full name: syshttp's own carry
`SYSHTTP_` (`SYSHTTP_PROXY`, `SYSHTTP_HOME`, `SYSHTTP_HOOKS_<KEY>`),
conventional ones keep theirs (`HTTPS_PROXY`, `NO_PROXY`, `CA_BUNDLE`). Each
is read as `<PREFIX><NAME>` for every prefix in turn, the first one set (and
not blank) winning, each name on its own. The prefixes are the `prefixes`
argument of an `HTTPEnv`, else `SYSHTTP_PREFIX` (a `:`-separated list), else
one empty prefix: the names as written. A prefix is used literally, so it
carries its own separator (`AGENTS_`). Order: an explicit argument, then the
variable, then the built-in default. Nothing is read at import; each call
reads the environment as it is then. Below, every name is given as written,
under the empty prefix.

```python
class HTTPEnv:
    def __init__(self, prefixes: str | Iterable[str] | None = None,
                 environ: Mapping[str, str] | None = None) -> None
    environ: Mapping[str, str]          # property: the mapping read (os.environ when None)
    prefixes: tuple[str, ...]           # property: the prefixes in force, in lookup order
    def name(self, name: str) -> str
    def find(self, *names: str) -> tuple[str, str] | None
    def get(self, *names: str) -> str | None
    def family(self, stem: str) -> Iterator[tuple[str, str, str]]
PREFIX_VAR = "SYSHTTP_PREFIX"
```

- `SYSHTTP_PREFIX=MYTOOL_` reads `MYTOOL_SYSHTTP_PROXY`, `MYTOOL_HTTPS_PROXY`,
  `MYTOOL_CA_BUNDLE` and so on, and nothing unprefixed: a tool opts out of
  the defaults. `MYTOOL_:` reads `MYTOOL_<NAME>` first, then `<NAME>`: a tool
  layers its own settings over them. `SYSHTTP_PREFIX` itself has no prefix.
- `prefixes=None` reads `SYSHTTP_PREFIX` at every lookup; blank or unset is
  `("",)`. A string is split at `:`; an iterable is taken as the list; an
  empty iterable reads nothing. A prefix is letters, digits and underscores
  (possibly none), upper-cased; one listed twice counts once. A malformed
  argument raises `ValueError` in the constructor; a malformed
  `SYSHTTP_PREFIX` raises `ConfigurationError` naming it at the first lookup.
- A CGI program receives every request header as an `HTTP_*` variable, so a
  client could set `HTTP_PROXY`, `HTTP_PROXY_AUTH` and the like: under CGI,
  set a prefix list without the empty entry.
- `environ` isolates an instance: two `HTTPEnv`s with different prefixes or
  mappings never see each other's settings.
- `find(*names)` returns `(variable, value)` for the first of `names` set
  under the first prefix that has one (every name tried under a prefix before
  the next prefix), the value stripped; `None` when none is. `get` returns
  the value only. `name(name)` is `name` under the first prefix: what a
  message names when nothing is set, and what a child process is given.
- `family(stem)` yields `(rest, value, variable)` for every variable named
  `<PREFIX><stem><rest>` with a non-empty `rest` and a value that is not
  blank, the first prefix winning for a `rest` (compared upper-cased).

Every function below that reads a setting takes `env: HTTPEnv | None = None`
(keyword-only) and uses `HTTPEnv()` when it is `None`.

## Proxy (`syshttp.proxy`)

Routing is proxylib's (2.x): syshttp turns its settings into one proxylib
proxy map, and proxylib's client integrations send through it. Read an
answer with `proxylib.lookup(m, url)`; every proxylib integration takes the
map (`ProxyMapAdapter`, `ProxyMapHandler`, `ProxyTransport`, `ProxySession`).

```python
def proxy_map(proxy: str | None = None, noproxy: str | None = None, proxy_user: str | None = None,
              *, env=None) -> proxylib.ProxyMap
def configured_proxy(*, env=None) -> proxylib.Proxy | None
def system_map() -> proxylib.ProxyMap | None
def system_proxy_enabled(*, env=None) -> bool
def auth_header(*, env=None) -> str
def proxy_type(*, env=None) -> tuple[str, str | None]
NoReachableProxyError = proxylib.NoReachableProxyError
SYSTEM_PROXY_MAX_AGE = 60
PROXY = "PROXY"; PROXY_AUTH = "PROXY_AUTH"; PROXY_AUTH_HEADER = "PROXY_AUTH_HEADER"
PROXY_TYPE = "PROXY_TYPE"; SYSTEM_PROXY = "SYSTEM_PROXY"   # setting names, as `SYSHTTP_<NAME>`
DEFAULT_AUTH_HEADER = "Proxy-Authorization"; MACHINE_AUTH_VAR = "HTTP_PROXY_AUTH"
```

- `proxy_map()` reads the settings at every lookup, so one map serves a
  long-lived client, and always answers (never `KeyError`). Its answer is a
  tuple of entries to try in order, `None` for DIRECT:
  1. `NO_PROXY` / `no_proxy` hosts: DIRECT (proxylib's `BypassRules`:
     suffixes, CIDR, ports, `*`; loopback always).
  2. `SYSHTTP_PROXY` (`configured_proxy()`), alone.
  3. Else the machine's proxy: when any of `HTTP_PROXY`, `HTTPS_PROXY`,
     `FTP_PROXY`, `WS_PROXY`, `WSS_PROXY`, `ALL_PROXY` is set (either case),
     those variables alone decide, per scheme (proxylib's `EnvProxyConfig`:
     the lowercase spelling first under each prefix, a PAC result such as
     `PROXY a:1; DIRECT` read as a list); else the system's
     configuration for the URL (`system_map()`), unless `SYSHTTP_SYSTEM_PROXY`
     is off. `HTTP_PROXY_AUTH`, when set, is every such proxy's
     `Proxy-Authorization` (SOCKS entries excepted).
  4. Else DIRECT.
- `proxy` (curl's `-x`) replaces 2 and 3 with that proxy, a plain one whose
  credential is only its userinfo; `""` is DIRECT. `noproxy` (`--noproxy`)
  replaces `NO_PROXY`, the variables' own included; listing `<-loopback>`
  turns proxylib's implicit loopback bypass off, as curl has none. `proxy_user` (`-U user:password`) becomes the
  credential of whichever proxy answers.
- A malformed `SYSHTTP_PROXY`, `SYSHTTP_PROXY_TYPE` or `SYSHTTP_PROXY_AUTH_HEADER`
  raises `ConfigurationError` (proxylib's `ProxyParseError` for a URL) at
  lookup, only when `SYSHTTP_PROXY` is set (the header name only when
  `SYSHTTP_PROXY_AUTH` is too); a bad `SYSHTTP_SYSTEM_PROXY` only when the system
  would be asked.
- `configured_proxy()` is `SYSHTTP_PROXY` as a proxylib `Proxy` (a bare
  `host:port` is `http`). Its credential is `SYSHTTP_PROXY_AUTH`, a header value
  sent verbatim in `auth_header()` (`SYSHTTP_PROXY_AUTH_HEADER`, default
  `Proxy-Authorization`; a value with `:` or whitespace raises `ValueError`)
  in place of the userinfo, else the userinfo as Basic. A credential (this
  or `HTTP_PROXY_AUTH`) containing a CR, LF or NUL raises `ValueError` naming
  the variable, never the value. It goes to that proxy only: a `CONNECT`, or a plain-http request to it, never through the tunnel.
  `SYSHTTP_PROXY_TYPE=prefix[:/endpoint]` (`proxy_type()`) makes it a
  `prefix+http(s)` gateway: the request for `T` goes to
  `<proxy><endpoint>T`, the credential a header of that request.
- `system_map()` is `proxylib.auto_proxy(environ={})` (the OS resolver --
  WinHTTP, CFNetwork, libproxy -- then the OS settings, PAC and WPAD
  included), built once per `SYSTEM_PROXY_MAX_AGE` seconds, each URL's
  answer cached as long. A configuration that cannot be read is `None`, and
  a lookup that fails is no opinion: DIRECT, logged at DEBUG, never a failed
  request.
- Proxies never print their secrets: a `Proxy`'s `repr()` hides the password
  and headers, `.url` has no credentials.
- How an answer is used is the client integration's: requests, httpx and
  aiohttp try the entries in order and move on when one does not connect
  (the last error is raised; a DIRECT entry reached is direct); a client
  that sends once takes the first reachable entry through
  `proxylib.Probed(proxy_map())`, which raises `NoReachableProxyError` (a
  `LookupError`) when none answers and the list holds no DIRECT.

## Session (`syshttp.session`, extra `session`)

```python
def new_session(*, user_agent: str | None = None, proxies: dict | None = None,
                verify: bool | str | Path = True, retries: int = 3, backoff: float = 1,
                status_forcelist: Iterable[int] = TRANSIENT_STATUSES,
                cookies: bool | str | CookieJar = False, tokens: bool | str | TokenJar = False,
                auth_provider: AuthProvider | None = None, env: HTTPEnv | None = None,
                ssl_context: ssl.SSLContext | None = None,
                proxy_ssl_context: ssl.SSLContext | None = None,
                cookie_hosts: Iterable[Iterable[str]] | None = None) -> requests.Session
COOKIE_HOSTS = "COOKIE_HOSTS"   # setting name, as `SYSHTTP_COOKIE_HOSTS`
```

- One transport adapter, `ProxyAdapter` (a subclass of proxylib's
  `ProxyMapAdapter` that adds only the TLS below), routes every request,
  including a bare `session.send()` and every redirect hop, by
  `proxy.proxy_map(env=env)`: the environment as it is then, and the
  system's answer host by host. `adapter.route(url)` returns the entries it
  will try (`session.get_adapter(url).route(url)`). They are tried in order,
  the next when one does not connect; the last error is raised
  (`requests.exceptions.ProxyError` for a proxy). The environment's
  `HTTP_PROXY` cannot win through `trust_env`. A prefix gateway's response
  keeps the caller's request and URL, so redirects and cookies belong to the
  target.
- `proxies=` given by you is handed to requests unchanged: the map then has
  no opinion, and no syshttp credential is added.
- `verify=True` verifies through `tls.os_ssl_context()` (the OS verifier)
  and names no CA file. A path, or the `CA_BUNDLE` setting (read at each
  request), names a bundle; requests' own `REQUESTS_CA_BUNDLE` /
  `CURL_CA_BUNDLE` are not read. `verify=False` is left to requests.
- A client certificate passed as `cert=` (a path, or a `(certificate, key)`
  pair) with `verify=True` is loaded into a context of the session's own,
  cached per file and modification time, never into the shared OS context
  and so never into another session's. Without `ssl_context`; beside it,
  `cert=` raises `ValueError`: load the identity into the context.
- `ssl_context` is used as given for every https origin. Its own
  `verify_mode`, trust store, client identity (mutual TLS, including a key
  held in an OS keystore), ciphers and protocol versions decide. The session
  never changes it. Beside it, `verify` must stay `True`, or `new_session`
  raises `ValueError`; so does a request-level `verify=` (`False`, or a
  bundle), which includes `fetch.request_text(verify=...)`. A non-`SSLContext` raises
  `TypeError`. `proxy_ssl_context` does the same for the TLS to an `https://`
  proxy and to an `https://` URL-prefix gateway: the gateway never gets
  `ssl_context` or a client certificate meant for the origin, and
  `CA_BUNDLE` is not consulted (without
  `proxy_ssl_context`, the system's verifier).
  The `sslcontext` package builds such contexts (keystore identities,
  PEM/PKCS#12 from memory), but any `ssl.SSLContext` works.
- `cookies` / `tokens`: `True` uses a file jar under `jar.store_root(env=env)`
  keyed by the origin's host. A string names one key for every host. A jar
  object is used as given. A token is sent as a per-request `Authorization`:
  `Bearer <token>`, or verbatim when it already names a scheme. An explicit
  `Authorization` header or `auth=` wins. A token containing a CR, LF or NUL
  raises `ValueError` naming the jar key, never the value.
- `cookie_hosts`: groups of hosts the user declares to be one for cookies
  (`cookies.host_aliases`); default `SYSHTTP_COOKIE_HOSTS`, read when the session
  is built (groups split by `;`, hosts by `,`:
  `app.example.com,app.example.net;wiki,wiki.corp.example`); `[]` for none.
  A malformed variable raises `ConfigurationError` naming it; a malformed
  argument `ValueError` (`TypeError` for a group given as one string).
  Within a group:
  - a host-only cookie a member sets, and one whose `Domain` names a member,
    belongs to the group's first host (stored there, kept in its jar file);
  - a request to any member carries what a request to any member would,
    `Secure` and the path still applying per request;
  - a member deletes such a cookie as the first host would;
  - a `Domain` outside the group is judged on the host that sent it, so a
    group never lets a host set a cookie for a domain that is not its own.
  Without groups the RFC 6265 rule stands: no host sets or deletes another
  host's cookie. Hosts are names or IP addresses, without a port; a host in
  two groups raises. A by-host jar file of a member other than the first is
  not read. Tokens stay per host.
- `user_agent` replaces the session's `User-Agent` header.
- A status in `status_forcelist` that outlasts `retries` is returned as the
  response (`raise_on_status=False`), as plain requests returns it; a
  connection that never succeeds still raises.
- Cookies, tokens, `_PY` hooks and `auth_provider` belong to `session.request`
  (`get`, `post`, ...) only. A bare `session.send(prepared)` gets the proxy
  decision and TLS (the adapter) and none of them.
- `_PY` URL hooks run inside `session.request`, on the caller's URL. Requests
  a hook makes through the session do not run hooks again; the guard is per
  thread, so another thread's requests still run them.
- `auth_provider.ensure(session, url)` runs before each request, and its
  errors are swallowed.

## Exceptions (`syshttp.exceptions`)

```python
class SysHTTPError(Exception)
class ConfigurationError(SysHTTPError, ValueError)
class HookError(SysHTTPError, RuntimeError)
class ResponseError(SysHTTPError, ValueError)
```

- `SysHTTPError` is the base of what goes wrong at run time. proxylib's and
  requests' own errors (`NoReachableProxyError`, `ProxyParseError`,
  `requests.exceptions.*`) pass through as they are.
- `ConfigurationError`: a setting or stored credential that cannot be used
  (a malformed `SYSHTTP_PROXY_TYPE`, a regular expression that does not compile,
  a hook that cannot be loaded, a token with a line break, a malformed
  `SYSHTTP_PREFIX`). The message names the variable or key, never a secret.
- `HookError`: a `_PY` hook failed; the hook's own exception is `__cause__`.
- `ResponseError`: a body that is not the JSON `request_json` was asked for.
- A caller's own mistake is a plain `ValueError` or `TypeError`, not one of
  these: a malformed `prefixes=` argument, `verify=False` beside `ssl_context`,
  `cert=` beside `ssl_context`, an unknown patch target.

## Fetch helpers (`syshttp.fetch`, extra `session`)

```python
def request_text(session, method, url, *, headers=None, data=None, json_body=None, timeout=60, verify=None) -> tuple[int, str]
def request_json(session, method, url, *, ...same...) -> tuple[int, Any]
def request_with_reauth(session, method, url, *, ...same..., auth_fail_statuses=(401, 403), reauth_cb=None, auth_provider=None) -> tuple[int, str]
def request_text_auto(method, url, *, session=None, headers=None, data=None, json_body=None, timeout=60, **session_options) -> tuple[int, str]
def request_json_auto(method, url, *, ...same...) -> tuple[int, Any]
```

- `timeout` is seconds or a `(connect, read)` pair, as requests takes it.
- A status is never an exception: a status in the session's `status_forcelist`
  that outlasts its retries comes back as `(status, text)`. A connection that
  never succeeds, or a timeout, raises requests' exception.
- `request_json` returns `(status, None)` for an empty body. A body that is
  not JSON raises `ValueError` naming the status.
- `verify=` is requests' per-request value; beside a session's `ssl_context`
  it raises `ValueError`.
- `request_with_reauth` retries once after a status in `auth_fail_statuses`,
  calling `auth_provider.ensure()` and then `reauth_cb()` first.
- The `*_auto` helpers send through `session` when it is given (left open),
  else through `new_session(**session_options)`, which they close after the
  call: `session_options` is any keyword of `new_session` (`env`, `proxies`,
  `retries`, `ssl_context`, ...), and the defaults are `new_session`'s.

## Jars (`syshttp.jar`)

```python
def store_root(*, env=None) -> Path
def default_root(*, env=None) -> Path
def safe_name(key: str) -> str
class FileCookieJar:  def __init__(self, root: Path | None = None, *, env=None)
class FileTokenJar:   def __init__(self, root: Path | None = None, *, env=None)
class MemoryCookieJar(dict)
class MemoryTokenJar(dict)
class CookieJar(Protocol); class TokenJar(Protocol)   # __getitem__, __setitem__, get
```

- `store_root()` returns `SYSHTTP_HOME` (a leading `~` expanded), else
  `default_root()`: a directory `syshttp` under `%LOCALAPPDATA%` (Windows),
  `~/Library/Application Support` (macOS) or `$XDG_STATE_HOME` /
  `~/.local/state` (elsewhere).
- Cookies live in `<root>/cookies/<host>.txt` (Netscape), tokens in
  `<root>/tokens/<host>.token`.
- Both are secrets and are written as such: mode `0600` (directories this
  library creates `0700`; an existing directory keeps its mode), replaced
  whole by a rename so a reader sees the old file or the new one, with LF line
  ends on every platform. `cookies.save_netscape` does the same. The
  constructors do nothing on disk: the directory is created at the first
  write.
- `get()` returns the default on any read error. Token values are never
  logged.
- A session saves a host's cookie file only when its cookies differ from
  those last loaded or saved, and never after failing to read its own. A
  token file is read at every request.

## Cookies (`syshttp.cookies`)

```python
@dataclass(frozen=True)
class CookieSpec: domain: str; path: str; secure: bool; expires: int | None; name: str; value: str; http_only: bool = False; subdomains: bool = False
def load_netscape(path: Path) -> list[CookieSpec]
def save_netscape(session_cookies: Iterable[CookieLike], path: Path) -> None
def cookie_applies(cookie: CookieSpec, url: str, now: float | None = None) -> bool
def set_cookie_specs(values: Iterable[str], default_domain: str, now: float | None = None, *,
                     request_path: str = "/",
                     aliases: Mapping[str, str] | None = None) -> list[tuple[CookieSpec, bool]]
def domain_covers(domain: str, host: str) -> bool
def apply_to_session(session, cookies: Iterable[CookieSpec]) -> None
def merge_set_cookie_headers(session, response, *, aliases: Mapping[str, str] | None = None) -> None
def host_only_policy(aliases: Mapping[str, str] | None = None) -> http.cookiejar.DefaultCookiePolicy
def host_aliases(groups: Iterable[Iterable[str]]) -> dict[str, str]
HTTP_ONLY_PREFIX = "#HttpOnly_"
MAX_COOKIE_AGE = 400 * 24 * 3600
```

- `load_netscape` returns `[]` for a missing file, reads `#HttpOnly_` rows,
  keeps a row whose value is empty and treats an unreadable expiry as a
  session cookie. `save_netscape` writes `#HttpOnly_` rows as curl does.
- `cookie_applies` decides as curl does: the domain (a subdomain only with a
  leading dot or the include-subdomains flag, and an IP only matches
  itself), the RFC 6265 path match, `Secure` only over https or to loopback,
  not expired (`0` / `None` is a session cookie).
- `set_cookie_specs` returns `(cookie, gone)` per `Set-Cookie` value, parsed
  as RFC 6265 section 5.2 reads it: the name and value up to the first `;`
  (a value may hold spaces, `=` or JSON), attribute names in any case,
  unknown attributes (`Priority`, `Partitioned`) ignored, `Max-Age` beating
  `Expires` in either order, an HTTP date in any of its three forms read as
  UTC, and an expiry beyond 400 days cut to `MAX_COOKIE_AGE`. A header with
  no `name=value` is skipped. `gone` marks a cookie the server expired (an
  empty value, `Max-Age` of zero or less, a past date).
  - `default_domain` is the host asked. A `Domain` attribute is kept only
    when that host domain-matches it, on a set and on a deletion alike;
    otherwise the cookie is skipped. It then gives `subdomains=True`. With no
    `Domain`, or with one equal to an IP-literal host, the cookie is
    host-only. A `Domain` that is a public suffix is skipped unless it
    equals the host (`localhost`, `wiki`), which gives a host-only cookie.
  - A public suffix is recognised without the Public Suffix List: a name
    with no dot (a top level domain) or a registry under a two-letter country
    code (`co.uk`, `com.au`). A shared suffix such as `github.io` is not
    recognised, so a site there can set a `Domain` cookie for it.
  - A cookie with no `Path` gets the directory of `request_path` (the
    request's path; RFC 6265 section 5.1.4: `/app/login` is `/app`).
- `apply_to_session` loads rows into a requests session with their flags. A
  row that is not a domain cookie (no leading dot, flag `FALSE`) stays on its
  host, `localhost` and other single-label hosts included. `new_session`
  gives its session `host_only_policy()`, which this needs: requests'
  default also sends such a cookie to subdomains.
- `merge_set_cookie_headers(session, response)` applies the deletions that
  requests' own extraction misses (a `Domain` that differs from how the
  cookie was stored, an empty value), for the response and its redirect
  hops. It sets nothing: requests stores each cookie once, against the URL
  the caller asked for.
- `FileCookieJar` keeps `HttpOnly` and the include-subdomains flag. A
  by-host file holds every cookie that applies to its host, one a host set
  for a parent domain (`Domain=example.com` from `www.example.com`) included.
- `host_aliases(groups)` maps each host of each group (lower case, IPv6
  brackets and a trailing dot removed) to the group's first host; a group of
  one host is no alias. A host that is not a name or an IP address (a port,
  a path, a blank) or that is in two groups raises `ValueError`; a group
  given as one string, `TypeError`. `set_cookie_specs`,
  `merge_set_cookie_headers` and `host_only_policy` take the mapping as
  `aliases` and apply `new_session`'s `cookie_hosts` rules.

## URL hooks (`syshttp.hooks`)

```
SYSHTTP_HOOKS_<KEY>=<regex>                re.search against the caller's URL
SYSHTTP_HOOKS_<KEY>_PY=<module:callable>   syshttp calls callable(session, method, url, kwargs)
SYSHTTP_HOOKS_<KEY>_CURL=<command>         a curl front end runs this in its place, its argv appended
```

```python
class Hook:  key, pattern, curl, py, variable; matches(url) -> bool
def hooks_from_env(*, env=None) -> list[Hook]
def matching(url: str, *, kind: str | None = None, env=None) -> list[Hook]
def skipped(*, env=None) -> set[str]
def call_py_hooks(session, method, url, kwargs, *, env=None) -> requests.Response | None
def load_callable(spec: str) -> PyHook
def split_command(value: str) -> list[str]
def curl_command(hook: Hook, python: str | None = None) -> list[str]
def wrapper_environment(hook: Hook, url: str, entry: str, *, env=None) -> dict[str, str]
```

- Hooks run in KEY order. A `_PY` hook returning non-`None` is used as the
  response and ends the chain. `kwargs` is mutable. A hook declared without
  a `_PY` or `_CURL` target is ignored, and so is a target without a
  pattern, or a blank one.
- KEYs are compared without regard to case (`Hook.key` is upper-case, as
  Windows holds variable names): `HOOKS_mykey` and `HOOKS_MYKEY` are one
  hook, and `HOOK_SKIP=mykey` suppresses it.
- `SYSHTTP_HOOK_SKIP` (a comma list of KEYs) suppresses hooks.
- `load_callable` accepts `module:attr` or `<file>.py:attr` (`attr` may be
  dotted). A file is loaded once per process, by its resolved path, as a
  `module` is imported once: its module-level state lives on between requests
  and a later edit is not picked up. Two files named alike are two modules.
- A failing `_PY` hook raises `RuntimeError` naming the variable, the target,
  the method and the URL as scheme, host, port and path (no userinfo, query
  or fragment); the hook's own exception is chained and not rewritten.
- `curl_command` splits a shell-quoted command line. Backslashes are
  literal, a bare existing path is one program, and a leading `.py` runs
  under `python`.
- `wrapper_environment` returns the `SYSHTTP_HOOK_URL`, `SYSHTTP_HOOK_KEY`,
  `SYSHTTP_HOOK_CURL` and `SYSHTTP_HOOK_SKIP` (this KEY added) variables a
  `_CURL` wrapper run needs, each under the first prefix.

## TLS and retry (`syshttp.tls`, `syshttp.retry`)

```python
def new_os_context(cafile: str | None = None, capath: str | None = None, *,
                   client_certificates: bool = True) -> ssl.SSLContext
def os_ssl_context() -> ssl.SSLContext
OS_CONTEXT_MAX_AGE = 60
TRANSIENT_STATUSES = (408, 429, 500, 502, 503, 504)
def retry_after(headers: Iterable[tuple[str, str]], now: float | None = None) -> float | None
```

- `new_os_context()` without `cafile`/`capath` is
  `sslcontext.system_context()`. On Python 3.10+ it is a
  `truststore.SSLContext`: the operating system verifies the chain
  (CryptoAPI on Windows, the Security framework on macOS, OpenSSL over the
  system store elsewhere), so OpenSSL's CRL flags have no effect on it. On
  3.9 OpenSSL verifies over the default store. A server that asks for a
  client certificate gets one from the OS store (the Windows Personal store
  and smart cards, the macOS keychains, the default PKCS#11 module), chosen
  as a browser chooses (the remembered choice, the Edge/Chrome
  `AutoSelectCertificateForUrls` policy, the only candidate), or none.
  `client_certificates=False` never offers one: pass it before loading a
  certificate of your own, which a store certificate would otherwise
  replace. With `cafile`/`capath` it is a plain `ssl` context trusting only
  them, offering no store certificate.
- `os_ssl_context()` is shared for `OS_CONTEXT_MAX_AGE` seconds, because
  urllib3 pools by context object. Never load a client certificate into it;
  use `new_os_context(client_certificates=False)`.
- `retry_after` reads a number of seconds (the digits `0-9` only) or an HTTP
  date, a date without a zone being UTC. It returns `None` when the header
  is absent or unreadable.

## Import-time patching (`syshttp.autopatch`)

```python
SETTING = "SYSHTTP_IMPORTPATCH"
TARGETS = {"requests": "requests", "urllib": "urllib.request", "httpx": "httpx", "aiohttp": "aiohttp",
           "pip": "pip._vendor.requests"}
def setting_name(*, env=None) -> str
def enabled(*, env=None) -> frozenset[str]
def importpatch(name: str, module: ModuleType) -> None   # importpatch's entry point
def patch(targets: Iterable[str] | None = None) -> tuple[str, ...]
def unpatch() -> None
def patched() -> tuple[str, ...]
```

- `SYSHTTP_IMPORTPATCH` patches client libraries as they are imported, in
  any program run by an interpreter of the environment. It is read under the
  prefixes like every setting (`SYSHTTP_PREFIX=AGENTS_`:
  `AGENTS_SYSHTTP_IMPORTPATCH`; `setting_name()` is the variable found, else
  the name under the first prefix). Values:
  `1`/`true`/`yes`/`on` for every target, `0`/`false`/`no`/`off`, empty or
  unset for none, else target names separated by `:` (`requests:httpx`;
  `urllib.request` means `urllib`). An unknown name is
  logged at WARNING and skipped. Read when the library is imported.
- The mechanism is importpatch (a dependency): its `.pth` hooks imports at
  interpreter start, and syshttp's `importpatch` entry points name
  `syshttp.autopatch` for `requests`, `urllib.request`, `httpx` and
  `aiohttp`. `IMPORTPATCH_DISABLE=1` turns every importpatch hook off.
  `patch(targets=None)` applies the patches from code whatever the setting
  says (every installed target by default; a named one that is not installed
  raises its `ImportError`, an unknown name `ValueError`); `unpatch()` undoes
  them, though a client built while patched keeps what it was given.
- What a patched library does: routing is proxylib's integration for that
  client (`proxylib.patch(proxy.proxy_map(), targets=[name])`, the newest
  patch winning, as proxylib's own `PROXYLIB_IMPORTPATCH` would install it);
  TLS is syshttp's: with verification on and no TLS argument of the
  caller's, the system's context.
  - **requests**: new `Session`s mount proxylib's `ProxyMapAdapter`:
    entries tried in order. A proxy the caller gives (`proxies=` on the
    call, or `session.proxies`) is used as given, without syshttp's
    credential, and a session with `trust_env = False` is left to requests.
    Every `HTTPAdapter` with `verify=True` and no context of its own pool
    manager verifies with `tls.os_ssl_context()`.
  - **urllib**: proxylib's global opener (installed when the program has
    not installed its own) routes `urlopen`, through the first reachable
    entry (`Probed`; none reachable: `URLError` whose `reason` is
    `NoReachableProxyError`). A credential under another header than
    `Proxy-Authorization` cannot go to an https proxy:
    `proxylib.UnsupportedProxyError`. `ssl._create_default_https_context`
    returns a system context, so `http.client` and every caller that gives
    no context verify with it (one context of its own, shared 60 s:
    http.client sets ALPN on it).
  - **httpx**: `Client` / `AsyncClient` built without `transport`, `proxy`,
    `proxies` or `mounts` get proxylib's `ProxyTransport` /
    `AsyncProxyTransport`; `verify` left at `True` becomes the system
    context (a fresh one offering no store certificate when `cert=` is
    given).
  - **aiohttp**: `ClientSession` requests without `proxy=` are routed by
    proxylib, with failover. A URL-prefix gateway is not followed:
    `proxylib.UnsupportedProxyError`. `ssl` left at `True` with no
    `ssl_context` / `verify_ssl` / `fingerprint` becomes the system context.
  - **pip** (`pip._vendor.requests`): every adapter pip mounts routes
    through the map, as proxylib's `pip` target does; `pip --proxy` and
    `--no-proxy-env` keep pip's own choice. pip keeps its own TLS context
    (truststore).
- Not patched: urllib3 used directly, websocket libraries.
- proxylib's own `PROXYLIB_AUTOPROXY` names clients that use
  `proxylib.auto_proxy()`; a client syshttp patches uses syshttp's map
  instead (the newer patch wins).

## Environment variables

| Variable | Sets | Default |
| --- | --- | --- |
| `SYSHTTP_PREFIX` | the prefixes every variable below is read under, `:`-separated, in order; read as written | none (the names as written) |
| `SYSHTTP_PROXY` | the proxy URL (`http://`, `https://`, or a bare `host:port`) | the request's scheme's `*_PROXY` variable, else `ALL_PROXY` (lowercase first); with none set, the system's configuration for the URL |
| `SYSHTTP_SYSTEM_PROXY` | whether the system's proxy configuration is consulted (boolean) | on |
| `SYSHTTP_PROXY_AUTH` | **secret**: `SYSHTTP_PROXY`'s credential, a header value sent verbatim | the URL's userinfo as Basic |
| `HTTP_PROXY_AUTH` | **secret**: the machine's proxy's credential (a `*_PROXY` variable's or the system's), as `Proxy-Authorization` | the URL's userinfo as Basic |
| `SYSHTTP_PROXY_AUTH_HEADER` | the header name `SYSHTTP_PROXY_AUTH` rides in | `Proxy-Authorization` |
| `SYSHTTP_PROXY_TYPE` | `connect` or `prefix[:/endpoint]` | `connect` |
| `SYSHTTP_HOME` | the jar root | the per-user state directory |
| `SYSHTTP_COOKIE_HOSTS` | groups of hosts that share cookies: hosts split by `,`, groups by `;` (`new_session`) | none |
| `SYSHTTP_IMPORTPATCH` | which client libraries are patched on import (`1` for all, or `:`-separated names: `requests`, `urllib`, `httpx`, `aiohttp`, `pip`) | none |
| `SYSHTTP_HOOKS_<KEY>` (+ `_PY`, `_CURL`) | a URL hook | none |
| `SYSHTTP_HOOK_SKIP` | KEYs of hooks not to run, comma list | none |
| `HTTP_PROXY`, `HTTPS_PROXY`, `FTP_PROXY`, `WS_PROXY`, `WSS_PROXY`, `ALL_PROXY` (either case, lowercase first) | the machine's proxy, per scheme | none |
| `NO_PROXY` / `no_proxy` | hosts that go direct | none |
| `CA_BUNDLE` | the CA bundle a session's `verify=True` uses | the OS verifier |

Each of these is read under every prefix of `SYSHTTP_PREFIX`. A `_CURL`
hook's wrapper runs with `SYSHTTP_HOOK_URL`, `SYSHTTP_HOOK_KEY`,
`SYSHTTP_HOOK_CURL` and `SYSHTTP_HOOK_SKIP` set under the first prefix
(`hooks.wrapper_environment`); a curl front end reads them back.

Read as written, never prefixed: `LOCALAPPDATA` (Windows) and
`XDG_STATE_HOME` (Linux and other POSIX) for the per-user state directory;
importpatch's `IMPORTPATCH_DISABLE` (`1` turns every import-time patch off);
proxylib's own `PROXYLIB_IMPORTPATCH` and `PROXYLIB_AUTOPROXY`.

## Gotchas

- With no proxy variable set, the system's configuration routes requests:
  on a machine with a corporate PAC script, traffic goes where the browser's
  would. `SYSHTTP_SYSTEM_PROXY=0` stops that.
- `SYSHTTP_PREFIX=MYTOOL_` reads `MYTOOL_<NAME>` only: `SYSHTTP_PROXY` and
  the machine's `HTTPS_PROXY` are then ignored. Add the empty entry
  (`MYTOOL_:`) to fall back to them.
- A malformed `SYSHTTP_PROXY_TYPE` is harmless until `SYSHTTP_PROXY` is set.
- Pass `root=` to keep jar files out of the user's state directory.
- A client certificate loaded into the context you pass is used for every
  https host the session talks to, redirects included. Give a session an
  identity only for hosts that should see it.
- With `verify=False`, urllib3 warns (`InsecureRequestWarning`) as it does
  for any requests session: `new_session()` changes no warning filter.
- A `_PY` hook names code to import. Never let an untrusted party set the
  environment of a process using syshttp.

# `syshttp` — public API header

Header-file-style reference for the `syshttp` package: every public export with
its signature, arguments, contract and gotchas, so the package can be used
without reading its source. It ships inside the package and is
self-contained. Development documentation lives with the source at
<https://github.com/jose-pr/syshttp>.

Import names from their modules: `syshttp.env`, `syshttp.proxy`,
`syshttp.session`, `syshttp.fetch`, `syshttp.jar`, `syshttp.cookies`,
`syshttp.hooks`, `syshttp.tls`, `syshttp.retry`, `syshttp.auth`,
`syshttp.autopatch`. The
root re-exports `HTTPEnv`, `NoReachableProxyError`, `proxy_map`,
`configured_proxy` and `proxy_type`.

`pip install syshttp` brings proxylib 2 (proxy routing and the system's proxy configuration),
sslcontext (the system's TLS client; truststore on Python 3.10+) and
importpatch (import-time patching of other HTTP clients, off unless
`SYSHTTP_IMPORTPATCH` asks for it). The extra `pac`
adds a JavaScript engine for PAC scripts proxylib evaluates itself (Linux
without libproxy). The extra `session` adds `requests` (with `urllib3`), which
`syshttp.session` and
`syshttp.fetch` import when a session is built. Without it, `new_session()`
raises `ImportError` saying `pip install 'syshttp[session]'`. Every other
module works without it.

`syshttp.__version__` is the installed distribution's version.

## Settings (`syshttp.env`)

Every setting is the variable `<P>_<NAME>`, with `<P>` the prefix: the
`prefix` argument of an `HTTPEnv`, else `SYSHTTP_PREFIX`, else `SYSHTTP`.
Conventional variables (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY`,
`HTTP_PROXY_AUTH`) keep their names under every prefix. Order: an explicit
argument, then the variable, then the built-in default. Nothing is read at
import; each call reads the environment as it is then.

```python
class HTTPEnv:
    def __init__(self, prefix: str | None = None, environ: Mapping[str, str] | None = None) -> None
    environ: Mapping[str, str]          # property: the mapping read (os.environ when None)
    prefix: str                         # property: the prefix in force, upper case
    def name(self, setting: str) -> str | None
    def get(self, setting: str) -> str | None
    def conventional(self, *names: str) -> str | None
    def family(self, stem: str) -> Iterator[tuple[str, str]]
PREFIX_VAR = "SYSHTTP_PREFIX"
DEFAULT_PREFIX = "SYSHTTP"
```

- `prefix=None` reads `SYSHTTP_PREFIX` at every lookup. A value that is
  empty or whitespace counts as unset.
- `prefix=""` turns the package's own settings off: `name()` and `get()`
  return `None`, no hook is read, and only conventional variables count.
  This is available only as an argument.
- A prefix is letters, digits and single inner underscores, starting with a
  letter. It is upper-cased. A malformed argument raises `ValueError` in the
  constructor. A malformed `SYSHTTP_PREFIX` raises `ValueError` naming it at
  the first lookup.
- `environ` isolates an instance: two `HTTPEnv`s with different prefixes or
  mappings never see each other's settings.
- `get(setting)` returns the stripped value of `name(setting)`, or `None`
  when unset or empty. `conventional(*names)` does the same for the first set
  variable among `names`, read unprefixed.
- `family(stem)` yields `(rest, value)` for every non-empty variable named
  `<P>_<stem><rest>`, in name order.

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
```

- `proxy_map()` reads the settings at every lookup, so one map serves a
  long-lived client, and always answers (never `KeyError`). Its answer is a
  tuple of entries to try in order, `None` for DIRECT:
  1. `NO_PROXY` / `no_proxy` hosts: DIRECT (proxylib's `BypassRules`:
     suffixes, CIDR, ports, `*`; loopback always).
  2. `<P>_PROXY` (`configured_proxy()`), alone.
  3. Else the machine's proxy: when any of `HTTP_PROXY`, `HTTPS_PROXY`,
     `FTP_PROXY`, `WS_PROXY`, `WSS_PROXY`, `ALL_PROXY` is set (either case),
     those variables alone decide, per scheme (proxylib's `EnvProxyConfig`:
     lowercase first, an uppercase `HTTP_PROXY` ignored under CGI, a PAC
     result such as `PROXY a:1; DIRECT` read as a list); else the system's
     configuration for the URL (`system_map()`), unless `<P>_SYSTEM_PROXY`
     is off. `HTTP_PROXY_AUTH`, when set, is every such proxy's
     `Proxy-Authorization` (SOCKS entries excepted).
  4. Else DIRECT.
- `proxy` (curl's `-x`) replaces 2 and 3 with that proxy, a plain one whose
  credential is only its userinfo; `""` is DIRECT. `noproxy` (`--noproxy`)
  replaces `NO_PROXY`. `proxy_user` (`-U user:password`) becomes the
  credential of whichever proxy answers.
- A malformed `<P>_PROXY`, `<P>_PROXY_TYPE` or `<P>_PROXY_AUTH_HEADER`
  raises `ValueError` (proxylib's `ProxyParseError` for a URL) at lookup,
  only when `<P>_PROXY` is set; a bad `<P>_SYSTEM_PROXY` only when the
  system would be asked.
- `configured_proxy()` is `<P>_PROXY` as a proxylib `Proxy` (a bare
  `host:port` is `http`). Its credential is `<P>_PROXY_AUTH`, a header value
  sent verbatim in `auth_header()` (`<P>_PROXY_AUTH_HEADER`, default
  `Proxy-Authorization`; a value with `:` or whitespace raises `ValueError`)
  in place of the userinfo, else the userinfo as Basic. It goes to that proxy
  only: a `CONNECT`, or a plain-http request to it, never through the tunnel.
  `<P>_PROXY_TYPE=prefix[:/endpoint]` (`proxy_type()`) makes it a
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
                proxy_ssl_context: ssl.SSLContext | None = None) -> requests.Session
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
  and names no CA file. A path, or `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE`,
  names a bundle. `verify=False` is left to requests.
- `ssl_context` is used as given for every https origin. Its own
  `verify_mode`, trust store, client identity (mutual TLS, including a key
  held in an OS keystore), ciphers and protocol versions decide. The session
  never changes it. Beside it, `verify` must stay `True`, or `new_session`
  raises `ValueError`. A non-`SSLContext` raises `TypeError`.
  `proxy_ssl_context` does the same for the TLS to an `https://` proxy.
  The `sslcontext` package builds such contexts (keystore identities,
  PEM/PKCS#12 from memory), but any `ssl.SSLContext` works.
- `cookies` / `tokens`: `True` uses a file jar under `jar.store_root(env=env)`
  keyed by the origin's host. A string names one key for every host. A jar
  object is used as given. A token is sent as a per-request `Authorization`:
  `Bearer <token>`, or verbatim when it already names a scheme. An explicit
  `Authorization` header or `auth=` wins.
- `_PY` URL hooks run inside `session.request`, on the caller's URL. Requests
  a hook makes through the session do not run hooks again.
- `auth_provider.ensure(session, url)` runs before each request, and its
  errors are swallowed.

## Fetch helpers (`syshttp.fetch`, extra `session`)

```python
def request_text(session, method, url, *, headers=None, data=None, json_body=None, timeout=60, verify=None) -> tuple[int, str]
def request_json(session, method, url, *, ...same...) -> tuple[int, Any]
def request_with_reauth(session, method, url, *, ...same..., auth_fail_statuses=(401, 403), reauth_cb=None, auth_provider=None) -> tuple[int, str]
def request_text_auto(method, url, *, session=None, <new_session options>, env=None, ssl_context=None, proxy_ssl_context=None, headers=None, data=None, json_body=None, timeout=60) -> tuple[int, str]
def request_json_auto(method, url, *, ...same...) -> tuple[int, Any]
```

- `request_json` returns `(status, None)` for an empty body. A body that is
  not JSON raises `ValueError` naming the status.
- `request_with_reauth` retries once after a status in `auth_fail_statuses`,
  calling `auth_provider.ensure()` and then `reauth_cb()` first.
- The `*_auto` helpers build a `new_session(...)` when `session` is `None`.

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

- `store_root()` returns `<P>_HOME`, else `default_root()`: a directory
  `syshttp` under `%LOCALAPPDATA%` (Windows), `~/Library/Application Support`
  (macOS) or `$XDG_STATE_HOME` / `~/.local/state` (elsewhere).
- Cookies live in `<root>/cookies/<host>.txt` (Netscape), tokens in
  `<root>/tokens/<host>.token`. The constructors create the directory.
- `get()` returns the default on any read error. Token values are never
  logged.

## Cookies (`syshttp.cookies`)

```python
@dataclass(frozen=True)
class CookieSpec: domain: str; path: str; secure: bool; expires: int | None; name: str; value: str; http_only: bool = False; subdomains: bool = False
def load_netscape(path: Path) -> list[CookieSpec]
def save_netscape(session_cookies: Iterable[CookieLike], path: Path) -> None
def cookie_applies(cookie: CookieSpec, url: str, now: float | None = None) -> bool
def set_cookie_specs(values: Iterable[str], default_domain: str, now: float | None = None) -> list[tuple[CookieSpec, bool]]
def domain_covers(domain: str, host: str) -> bool
def apply_to_session(session, cookies: Iterable[CookieSpec]) -> None
def merge_set_cookie_headers(session, response) -> None
HTTP_ONLY_PREFIX = "#HttpOnly_"
```

- `load_netscape` returns `[]` for a missing file and reads `#HttpOnly_`
  rows. `save_netscape` writes them as curl does.
- `cookie_applies` decides as curl does: the domain (a subdomain only with a
  leading dot or the include-subdomains flag, and an IP only matches
  itself), the RFC 6265 path match, `Secure` only over https or to loopback,
  not expired (`0` / `None` is a session cookie).
- `set_cookie_specs` returns `(cookie, gone)` per `Set-Cookie` value. `gone`
  marks a cookie the server expired. Unparseable headers are skipped.

## URL hooks (`syshttp.hooks`)

```
<P>_HOOKS_<KEY>=<regex>                re.search against the caller's URL
<P>_HOOKS_<KEY>_PY=<module:callable>   syshttp calls callable(session, method, url, kwargs)
<P>_HOOKS_<KEY>_CURL=<command>         a curl front end runs this in its place, its argv appended
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
  pattern.
- `<P>_HOOK_SKIP` (a comma list of KEYs) suppresses hooks.
- `load_callable` accepts `module:attr` or `<file>.py:attr` (`attr` may be
  dotted).
- `curl_command` splits a shell-quoted command line. Backslashes are
  literal, a bare existing path is one program, and a leading `.py` runs
  under `python`.
- `wrapper_environment` returns the `<P>_HOOK_URL`, `<P>_HOOK_KEY`,
  `<P>_HOOK_CURL` and `<P>_HOOK_SKIP` (this KEY added) variables a `_CURL`
  wrapper run needs. It returns `{}` under the prefix `""`.

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
- `retry_after` reads a number of seconds or an HTTP date. It returns
  `None` when the header is absent or unreadable.

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
  any program run by an interpreter of the environment. Under a prefix of a
  tool's own the variable is `<PREFIX>_SYSHTTP_IMPORTPATCH`
  (`SYSHTTP_PREFIX=AGENTS`: `AGENTS_SYSHTTP_IMPORTPATCH`); under the default
  prefix or `""` it is `SYSHTTP_IMPORTPATCH` (`setting_name()`). Values:
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
    entries tried in order, a caller's `proxies` entry at the
    `scheme://hostname` key wins (a bare `"http"` key, or one requests adds
    from the environment, does not; `trust_env = False` is not an opt-out).
    Every `HTTPAdapter` with `verify=True` and no context of its own pool
    manager verifies with `tls.os_ssl_context()` (requests 2.32.2+).
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
  - **pip** (`pip._vendor.requests`): pip keeps its own TLS context
    (truststore). Routing needs a proxylib release with a `pip` patch
    target; until then naming `pip` changes nothing (logged at DEBUG).
- Not patched: urllib3 used directly, websocket libraries.

## Environment variables

| Variable | Sets | Default |
| --- | --- | --- |
| `SYSHTTP_PREFIX` | the prefix `<P>` of every variable below | `SYSHTTP` |
| `<P>_PROXY` | the proxy URL (`http://`, `https://`, or a bare `host:port`) | the request's scheme's `*_PROXY` variable, else `ALL_PROXY` (lowercase first); with none set, the system's configuration for the URL |
| `<P>_SYSTEM_PROXY` | whether the system's proxy configuration is consulted (boolean) | on |
| `<P>_PROXY_AUTH` | **secret**: `<P>_PROXY`'s credential, a header value sent verbatim | the URL's userinfo as Basic |
| `HTTP_PROXY_AUTH` | **secret**: the machine's proxy's credential (a `*_PROXY` variable's or the system's), as `Proxy-Authorization` | the URL's userinfo as Basic |
| `<P>_PROXY_AUTH_HEADER` | the header name `<P>_PROXY_AUTH` rides in | `Proxy-Authorization` |
| `<P>_PROXY_TYPE` | `connect` or `prefix[:/endpoint]` | `connect` |
| `<P>_HOME` | the jar root | the per-user state directory |
| `SYSHTTP_IMPORTPATCH` (`<PREFIX>_SYSHTTP_IMPORTPATCH` under a prefix of its own) | which client libraries are patched on import (`1` for all, or `:`-separated names: `requests`, `urllib`, `httpx`, `aiohttp`, `pip`) | none |
| `<P>_HOOKS_<KEY>` (+ `_PY`, `_CURL`) | a URL hook | none |
| `<P>_HOOK_SKIP` | KEYs of hooks not to run, comma list | none |
| `NO_PROXY` / `no_proxy` | hosts that go direct | none |

## Gotchas

- With no proxy variable set, the system's configuration routes requests:
  on a machine with a corporate PAC script, traffic goes where the browser's
  would. `<P>_SYSTEM_PROXY=0` stops that.
- `SYSHTTP_PREFIX=MYTOOL` renames every setting. `SYSHTTP_PROXY` is then
  ignored and `MYTOOL_PROXY` is read.
- A malformed `<P>_PROXY_TYPE` is harmless until `<P>_PROXY` is set.
- The jar constructors create their directory. Pass `root=` to keep them out
  of the user's state directory.
- A client certificate loaded into the context you pass is used for every
  https host the session talks to, redirects included. Give a session an
  identity only for hosts that should see it.
- `new_session()` turns off urllib3's `InsecureRequestWarning` for the whole
  process (`urllib3.disable_warnings`), whatever `verify` is.
- A `_PY` hook names code to import. Never let an untrusted party set the
  environment of a process using syshttp.

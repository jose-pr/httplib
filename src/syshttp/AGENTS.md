# `syshttp` — public API header

Header-file-style reference for the `syshttp` package: every public export with
its signature, arguments, contract and gotchas, so the package can be used
without reading its source. It ships inside the package and is
self-contained. Development documentation lives with the source at
<https://github.com/jose-pr/syshttp>.

Import names from their modules: `syshttp.env`, `syshttp.proxy`,
`syshttp.session`, `syshttp.fetch`, `syshttp.jar`, `syshttp.cookies`,
`syshttp.hooks`, `syshttp.tls`, `syshttp.retry`, `syshttp.auth`. The root
re-exports `HTTPEnv` and the proxy functions most callers need.

`pip install syshttp` brings proxylib (the system's proxy configuration) and
sslcontext (the system's TLS client; truststore on Python 3.10+). The extra `pac`
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

```python
def proxy_url(*, url: str | None = None, env=None) -> str | None
def configured_proxy_url(*, env=None) -> str | None
def system_proxy(url: str, *, env=None) -> str | None
def system_proxy_enabled(*, env=None) -> bool
def system_proxy_map() -> proxylib.ProxyMap | None
def first_reachable(answer: tuple) -> proxylib.Proxy | None   # proxylib.first_working_proxy
PROBE_MAX_AGE = 30; PROBE_TIMEOUT = 5.0
class NoReachableProxyError(ConnectionError):  # proxies: tuple[str, ...] (host:port)
def configured_authorization(*, env=None) -> str | None
def proxy_authorization(url: str | None = None, *, configured: bool = True, env=None, target: str | None = None) -> str | None
def resolve(url: str | None = None, *, configured: bool = True, env=None, target: str | None = None) -> tuple[str, str | None] | None
def auth_header(*, env=None) -> str
def proxy_type(*, env=None) -> tuple[str, str | None]
def prefix_url(target: str, proxy: str | None = None, endpoint: str | None = None, *, env=None) -> str
def no_proxy_from_env(*, env=None) -> str | None
def should_bypass(host_or_url: str, no_proxy=<from env>, *, env=None) -> bool
def bypassed_by(host: str, no_proxy: str | None) -> bool
def proxies_from_env(*, env=None) -> dict | None
def plan(proxy: str | None = None, noproxy: str | None = None, proxy_user: str | None = None, *, url: str | None = None, env=None) -> ProxyPlan | None
def basic_authorization(user: str, password: str) -> str
def userinfo(url: str | None) -> tuple[str, str] | None
def strip_auth(url: str) -> str
def redact(url: str | None) -> str | None
class ProxyPlan:  # proxy, authorization, endpoint, no_proxy, auth_header; bypasses(url); gateway_base
```

- `configured_proxy_url()` returns `<P>_PROXY`, else the first set of
  `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, `http_proxy`, `ALL_PROXY`,
  `all_proxy`. A bare `host:port` gets `http://`. Userinfo is kept as
  configured. `proxy_url(url=...)` returns that, else `system_proxy(url)`.
  Without `url` the system is not consulted: its answer depends on the URL.
- `system_proxy(url)` is the proxy the system's configuration names for
  `url`: WinHTTP on Windows, CFNetwork on macOS, libproxy or the desktop's
  settings elsewhere, PAC scripts and WPAD included (proxylib's OS engine).
  Its answer is a list (`PROXY a; PROXY b; DIRECT`): the first proxy whose
  port accepts a TCP connection is used (`first_reachable`, proxylib's
  `first_working_proxy`: `PROBE_TIMEOUT` seconds each, a proxy that did not
  answer skipped for 30 s process-wide), and the pick is reused for
  `PROBE_MAX_AGE` seconds per list. A DIRECT entry reached first is direct.
  No reachable proxy and no DIRECT raises `NoReachableProxyError` (a
  `ConnectionError`; also from `proxy_url()` and `plan()`), naming the proxies
  as `host:port`. It returns `None` for DIRECT, for no opinion, when the
  configuration cannot be read (logged at DEBUG, never raised), and when
  `<P>_SYSTEM_PROXY` is off. A probe checks only that the port answers: a
  proxy that accepts and then fails is not replaced by the next.
  `system_proxy_map()` is the configuration, read once per
  `SYSTEM_PROXY_MAX_AGE` (60) seconds.
  `system_proxy_enabled()` reads `<P>_SYSTEM_PROXY` (`1`/`true`/`yes`/`on`
  or their opposites; another value raises `ValueError` naming it).
- The credential is the header value, sent verbatim. Order:
  `<P>_PROXY_AUTH`, then `HTTP_PROXY_AUTH`, then the URL's userinfo as
  `Basic`. `configured=False` skips the variables, for a proxy the caller
  named (curl's `-x`).
- `resolve()` returns `(proxy URL without userinfo, header value or None)`,
  or `None` when no proxy is configured. Connect to the first half and send
  the second. Never send both userinfo and a header.
- `auth_header()` returns `<P>_PROXY_AUTH_HEADER`, default
  `Proxy-Authorization`. A value with `:` or whitespace raises `ValueError`.
- `proxy_type()` reads `<P>_PROXY_TYPE` and returns `("connect", None)`
  (the default) or `("prefix", "/endpoint")` (endpoint default `/`).
  Anything else raises `ValueError` naming the variable.
- `prefix_url(target)` returns `<proxy without userinfo><endpoint><target>`,
  with the target appended unchanged.
- `should_bypass()` applies `NO_PROXY` / `no_proxy` (curl's list:
  `host[:port]` suffixes, or `*`). Pass `no_proxy=` to replace the list, or
  `None` for "never bypass". A URL with an unparseable port is not bypassed.
- `plan(url=...)` makes the whole decision for a request to `url`. Order:
  `proxy` (curl's `-x`), `<P>_PROXY` and the `*_PROXY` variables, then --
  outside the bypass list -- the system's choice for `url`, which is always
  `connect` (`<P>_PROXY_TYPE` describes `<P>_PROXY`). `proxy` is always
  `connect` and never gets the configured credential. `proxy_user` (`-U`)
  becomes Basic and wins over the configured credential. `noproxy` replaces
  `NO_PROXY`. Returns `None` for direct. A malformed `<P>_PROXY_TYPE` or
  `<P>_PROXY_AUTH_HEADER` raises `ValueError`, but only when a proxy would
  be used.
- `redact(url)` replaces the password with `***`. Print proxy URLs only
  through it.

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

- One transport adapter decides the proxy for every request, including a
  bare `session.send()` and every redirect hop: `proxy.plan(url=<that URL>,
  env=env)`, so the environment is read as it is then and the system's answer
  follows a PAC script host by host. `adapter.route(url)` returns that
  decision (`session.get_adapter(url).route(url)`). When no proxy of the
  system's list answers and it holds no DIRECT, the request raises
  `requests.exceptions.ProxyError` (caused by `NoReachableProxyError`). A `NO_PROXY`
  host goes direct without the credential. A `connect` proxy is passed
  explicitly per request, so `HTTP_PROXY` cannot win through `trust_env`.
  The credential goes on the plain-http request and the https `CONNECT`,
  only to that proxy. A prefix gateway gets `<proxy><endpoint><url>` with
  the credential as a request header. `response.url`, `response.request`
  and `response.cookies` keep the caller's URL.
- `proxies=` given by you is handed to requests unchanged. It gets the
  configured credential only when one of its URLs is the configured proxy.
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

## Environment variables

| Variable | Sets | Default |
| --- | --- | --- |
| `SYSHTTP_PREFIX` | the prefix `<P>` of every variable below | `SYSHTTP` |
| `<P>_PROXY` | the proxy URL (`http://`, `https://`, or a bare `host:port`) | `HTTPS_PROXY` → `HTTP_PROXY` → `ALL_PROXY`, either case, then the system's configuration for the URL |
| `<P>_SYSTEM_PROXY` | whether the system's proxy configuration is consulted (boolean) | on |
| `<P>_PROXY_AUTH` | **secret**: the proxy credential, a header value sent verbatim | `HTTP_PROXY_AUTH`, else the URL's userinfo as Basic |
| `<P>_PROXY_AUTH_HEADER` | the header name the credential rides in | `Proxy-Authorization` |
| `<P>_PROXY_TYPE` | `connect` or `prefix[:/endpoint]` | `connect` |
| `<P>_HOME` | the jar root | the per-user state directory |
| `<P>_HOOKS_<KEY>` (+ `_PY`, `_CURL`) | a URL hook | none |
| `<P>_HOOK_SKIP` | KEYs of hooks not to run, comma list | none |
| `NO_PROXY` / `no_proxy` | hosts that go direct | none |

## Gotchas

- With no proxy variable set, the system's configuration routes requests:
  on a machine with a corporate PAC script, traffic goes where the browser's
  would. `<P>_SYSTEM_PROXY=0` stops that.
- `SYSHTTP_PREFIX=MYTOOL` renames every setting. `SYSHTTP_PROXY` is then
  ignored and `MYTOOL_PROXY` is read.
- A malformed `<P>_PROXY_TYPE` is harmless until a proxy is in use.
- The jar constructors create their directory. Pass `root=` to keep them out
  of the user's state directory.
- A client certificate loaded into the context you pass is used for every
  https host the session talks to, redirects included. Give a session an
  identity only for hosts that should see it.
- `new_session()` turns off urllib3's `InsecureRequestWarning` for the whole
  process (`urllib3.disable_warnings`), whatever `verify` is.
- A `_PY` hook names code to import. Never let an untrusted party set the
  environment of a process using syshttp.

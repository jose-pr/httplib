# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `syshttp.env.HTTPEnv(prefix=None, environ=None)`: every setting is
  `<PREFIX>_<NAME>`, with the prefix from `SYSHTTP_PREFIX` (default `SYSHTTP`).
  `prefix=""` reads only the conventional variables (`HTTPS_PROXY` and the
  rest of that family, `NO_PROXY`, `HTTP_PROXY_AUTH`). Every function that
  reads a setting takes `env=`, `new_session()` and the `fetch` `*_auto`
  helpers included.
- The system's proxy configuration is the last proxy source, decided for the
  URL being requested: WinHTTP on Windows, CFNetwork on macOS, libproxy or the
  desktop's settings elsewhere, PAC scripts and WPAD included (through
  proxylib, a new dependency). It comes after `<PREFIX>_PROXY` and the
  `*_PROXY` variables, after the `NO_PROXY` check, and is always spoken to as
  `connect`. `<PREFIX>_SYSTEM_PROXY=0` turns it off. `proxy.plan()`,
  `proxy_url()`, `resolve()` and `proxy_authorization()` take the request URL
  (`url=` / `target=`). `proxy.configured_proxy_url()` gives the
  environment's answer alone. The `pac` extra adds a JavaScript engine for PAC
  scripts proxylib evaluates itself (Linux without libproxy).
- `syshttp.autopatch`: `SYSHTTP_IMPORTPATCH=1` (or `:`-separated names:
  `requests`, `urllib`, `httpx`, `aiohttp`; `<PREFIX>_SYSHTTP_IMPORTPATCH`
  under a prefix of a tool's own) patches those libraries as they are imported,
  in any program of the environment, so requests without a proxy or TLS
  setting of the caller's route by syshttp and verify with the system's
  context. Through importpatch, a new dependency, and its entry points;
  `patch()` / `unpatch()` do it from code.
- The system's answer is a list (`PROXY a; PROXY b; DIRECT`): the first proxy
  that accepts a connection is used (proxylib's `first_working_proxy`), and a
  DIRECT reached first is direct. No reachable proxy and no DIRECT raises
  `proxy.NoReachableProxyError` (a `ConnectionError`, exported from the
  root); a session raises `requests.exceptions.ProxyError` for it.
- `new_session(ssl_context=..., proxy_ssl_context=...)` (and the same on the
  `fetch` `*_auto` helpers): a caller's `ssl.SSLContext` is used as given for
  every https origin, or for an `https://` proxy. That covers mutual TLS,
  ciphers and protocol versions. It cannot be combined with a `verify` other
  than `True`.
- `hooks.wrapper_environment()`: the `<PREFIX>_HOOK_*` variables a `_CURL`
  wrapper run receives.
- `jar.default_root()`: the per-user state directory used when
  `<PREFIX>_HOME` is unset.
- `syshttp.__version__`.

### Changed

- Routing is proxylib 2's (`proxylib>=2.0.2,<3`; 2.0.1 breaks pip's cached
  requests). `proxy.proxy_map(proxy,
  noproxy, proxy_user, *, env)` is the settings as one proxylib proxy map,
  read at each lookup; `proxy.configured_proxy()` is `<PREFIX>_PROXY` as a
  proxylib `Proxy`; `proxy.system_map()` is the system's configuration
  (`proxylib.auto_proxy`). The `*_PROXY` variables are read per scheme
  (lowercase first, httpoxy-safe), `NO_PROXY` takes CIDR entries, and curl's
  `-x ""` is direct. `<PREFIX>_PROXY_AUTH` goes to `<PREFIX>_PROXY` only and
  `HTTP_PROXY_AUTH` to the machine's proxies only.
- A list from the system (`PROXY a; PROXY b; DIRECT`) is tried in order by the
  session, httpx and aiohttp (proxylib's failover), replacing the probe of
  the entry above; urllib takes the first reachable entry. No proxy
  connecting and no DIRECT is the client's own connection error;
  `NoReachableProxyError` is proxylib's.
- The session's `ProxyAdapter` is proxylib's `ProxyMapAdapter` with the
  system's TLS; `adapter.route(url)` returns the entries it will try.
  `proxies=` given to `new_session` are requests' own, with no syshttp
  credential added.
- `syshttp.autopatch` routes through `proxylib.patch()` and patches TLS only;
  requests' TLS is a pool hook on every `HTTPAdapter`. A caller's own
  proxies and `trust_env = False` still win over syshttp (proxylib 2.0.2's
  rule). aiohttp is not offered
  URL-prefix gateways. New target `pip` (`pip._vendor.requests`, proxylib
  2.0.1's `pip` target): pip's adapters route through the map unless pip is
  given `--proxy` or `--no-proxy-env`; pip keeps its own TLS context.

- The jar constructors (`FileCookieJar`, `FileTokenJar`) no longer create
  their directory; it is created at the first write.

### Removed

- `proxy.proxy_url`, `configured_proxy_url`, `system_proxy`,
  `system_proxy_map`, `first_reachable`, `PROBE_MAX_AGE`, `PROBE_TIMEOUT`,
  `resolve`, `proxy_authorization`, `configured_authorization`, `userinfo`,
  `basic_authorization`, `strip_auth`, `redact`, `prefix_url`,
  `should_bypass`, `bypassed_by`, `no_proxy_from_env`, `proxies_from_env`,
  `plan` and `ProxyPlan`: `proxy_map()` and proxylib's `Proxy` replace them.

### Changed (earlier)

- The package stands alone as `syshttp`. It was previously the `httplib`
  library of the dotagents `net` overlay, which shipped with a curl-compatible
  command (`httplib.cli`, `python -m httplib`) that is now the `curlike`
  package. Imports move from `httplib` to `syshttp`, and settings from the
  dotagents names to the prefixed ones: `AGENTS_PROXY` → `SYSHTTP_PROXY`,
  `AGENTS_PROXY_AUTH` → `SYSHTTP_PROXY_AUTH`, `AGENTS_PROXY_AUTH_HEADER` →
  `SYSHTTP_PROXY_AUTH_HEADER`, `AGENTS_PROXY_TYPE` → `SYSHTTP_PROXY_TYPE`,
  `AGENTS_HOME` → `SYSHTTP_HOME`, `NET_HOOKS_<KEY>` → `SYSHTTP_HOOKS_<KEY>`,
  `NET_HOOK_*` → `SYSHTTP_HOOK_*`. To keep the `AGENTS_*` names, set
  `SYSHTTP_PREFIX=AGENTS` (hooks are then `AGENTS_HOOKS_<KEY>`).
- The system's TLS client by default: `tls.new_os_context()` (and so
  `os_ssl_context()` and every session with `verify=True`) returns
  `sslcontext.system_context()` (sslcontext 2 is a new dependency).
  Certificates are verified by the operating system on Python 3.10+
  (CryptoAPI on Windows, the Security framework on macOS, OpenSSL over the
  system store elsewhere), by OpenSSL over the default store on 3.9, and a
  server that asks for a client certificate gets one from the OS store,
  chosen as a browser chooses. `new_os_context(client_certificates=False)`
  offers none, for a caller loading its own. A `cafile` / `capath` still
  replaces the store with a plain `ssl` context.
- A session without caller `proxies` decides the proxy for every request and
  every redirect hop, from the environment as it is then and the system's
  answer for that URL. A direct decision is final: requests' `trust_env` cannot
  re-add a proxy. `adapter.route(url)` shows the decision.
- Without `<PREFIX>_HOME`, the jars live in the per-user state directory
  instead of the dotagents store directory.
- `proxy.resolve()` and `proxy.proxy_authorization()`: the keyword `env: bool`
  is now `configured: bool`.
- `hooks.hooks_from_env()`, `matching()`, `skipped()` and `call_py_hooks()`
  take `env: HTTPEnv` (keyword-only) instead of a mapping `environ`.
  `hooks.PREFIX`, `SKIP_ENV`, `URL_ENV`, `KEY_ENV` and `CURL_ENV` are
  replaced by the setting names `HOOKS`, `HOOK_SKIP`, `HOOK_URL`, `HOOK_KEY`
  and `HOOK_CURL`.
- `proxy.AUTH_VARS`, `AUTH_HEADER_VAR` and `TYPE_VAR` are replaced by the
  setting names `PROXY_AUTH`, `PROXY_AUTH_HEADER` and `PROXY_TYPE`.

### Fixed

- The proxy credential reaches a proxy whose host is configured in upper
  case. requests lower-cases the proxy URL it hands to `proxy_headers`, so the
  credential used to be dropped and the proxy answered 407.
- `Set-Cookie` is read as RFC 6265 section 5.2 reads it, not through
  `http.cookies.SimpleCookie`: a value with a space or JSON is kept, an
  unknown attribute (`Priority`, `Partitioned`) is no longer a cookie of its
  own, `Max-Age` beats `Expires`, and a header with no `name=value` is
  skipped. A `Domain` without a leading dot covers subdomains. A cookie with
  no `Path` gets the directory of the request path
  (`set_cookie_specs(..., request_path=)`).
- A session holds one copy of each cookie. `merge_set_cookie_headers` no
  longer re-sets what requests already stored (it used to add a second copy
  with path `/` and a dotless domain); it applies only the deletions requests
  misses, for redirect hops too.
- A cookie set without `Domain` stays on its host: rows loaded from a jar and
  cookies a server sets are no longer sent to subdomains
  (`new_session` uses `cookies.host_only_policy()`).
- A cookie for a single-label host (`localhost`, `wiki`) is loaded from its
  jar file, and is saved under its own name instead of `localhost.local`.
- `FileCookieJar` keeps `HttpOnly` and the include-subdomains flag.
- `load_netscape` keeps a row whose value is empty, and an expiry written
  with a non-ASCII digit is a session cookie instead of a `ValueError`.
  `retry_after` returns `None` for such a value, and reads an HTTP date
  written without a zone (`asctime`) as UTC.
- A cookie expiry beyond 400 days is cut to 400 days.
- Token and cookie files are replaced whole by a rename, so a reader never sees
  an empty or half-written file and concurrent savers no longer truncate each
  other's file.
- `<PREFIX>_HOME=~/jars` is expanded instead of creating a directory named `~`.
- Jar files are written with LF on Windows too, as curl writes them.
- A session whose cookie jar cannot be read (an error while iterating
  `session.cookies`) no longer saves an empty list over the host's cookies, and
  writes a host's file only when its cookies changed instead of after every
  response.

### Security

- A `Set-Cookie` can no longer name a domain its host does not own. Any
  host could set or delete another host's cookie (`Domain=bank.example` from
  `evil.example`) or one for a top level domain; such a header is now skipped
  on a set and on a deletion, in the session, in `FileCookieJar` and in
  `set_cookie_specs` (which curlike's `-c` uses). A public suffix is
  recognised without the Public Suffix List (a name with no dot, or a
  `co.uk`-style registry).
- Token and cookie files are created `0600`, and the directories this library
  creates `0700`, instead of world-readable under a usual umask.

[Unreleased]: https://github.com/jose-pr/syshttp/commits/main

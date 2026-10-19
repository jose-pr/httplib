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

- Routing is proxylib 2's (`proxylib>=2.0.1,<3`). `proxy.proxy_map(proxy,
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
  requests' TLS is a pool hook on every `HTTPAdapter`. A caller's
  `scheme://hostname` proxy entry wins over the system, a bare `"http"` key
  does not, and `trust_env = False` no longer opts out. aiohttp is not offered
  URL-prefix gateways. New target `pip` (`pip._vendor.requests`, proxylib
  2.0.1's `pip` target): pip's adapters route through the map unless pip is
  given `--proxy` or `--no-proxy-env`; pip keeps its own TLS context.

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

[Unreleased]: https://github.com/jose-pr/syshttp/commits/main

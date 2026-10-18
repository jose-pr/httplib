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
- Certificates are verified by the operating system by default:
  `tls.new_os_context()` (and so `os_ssl_context()` and every session with
  `verify=True`) returns a `truststore.SSLContext` on Python 3.10+ (truststore
  is a new dependency there): CryptoAPI on Windows, the Security framework on
  macOS, OpenSSL over the system store elsewhere. Python 3.9 keeps
  `ssl.create_default_context()`. A `cafile` / `capath` still replaces the
  store with a plain `ssl` context.
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

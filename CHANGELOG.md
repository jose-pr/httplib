# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `httplib.env.HTTPEnv(prefix=None, environ=None)`: every setting is
  `<PREFIX>_<NAME>`, with the prefix from `HTTPLIB_PREFIX` (default `HTTPLIB`).
  `prefix=""` reads only the conventional variables (`HTTPS_PROXY` and the
  rest of that family, `NO_PROXY`, `HTTP_PROXY_AUTH`). Every function that
  reads a setting takes `env=`, `new_session()` and the `fetch` `*_auto`
  helpers included.
- `hooks.wrapper_environment()`: the `<PREFIX>_HOOK_*` variables a `_CURL`
  wrapper run receives.
- `jar.default_root()`: the per-user state directory used when
  `<PREFIX>_HOME` is unset.
- `httplib.__version__`.

### Changed

- The package stands alone. It was previously the `httplib` library of the
  dotagents `net` overlay, which shipped with a curl-compatible command
  (`httplib.cli`, `python -m httplib`) that is now the `curlike` package.
  Settings move from the dotagents names to the prefixed ones:
  `AGENTS_PROXY` → `HTTPLIB_PROXY`, `AGENTS_PROXY_AUTH` →
  `HTTPLIB_PROXY_AUTH`, `AGENTS_PROXY_AUTH_HEADER` →
  `HTTPLIB_PROXY_AUTH_HEADER`, `AGENTS_PROXY_TYPE` → `HTTPLIB_PROXY_TYPE`,
  `AGENTS_HOME` → `HTTPLIB_HOME`, `NET_HOOKS_<KEY>` → `HTTPLIB_HOOKS_<KEY>`,
  `NET_HOOK_*` → `HTTPLIB_HOOK_*`. To keep the `AGENTS_*` names, set
  `HTTPLIB_PREFIX=AGENTS` (hooks are then `AGENTS_HOOKS_<KEY>`).
- Without `<PREFIX>_HOME`, the jars live in the per-user state directory
  instead of `~/.agents`.
- `proxy.resolve()` and `proxy.proxy_authorization()`: the keyword `env: bool`
  is now `configured: bool`.
- `hooks.hooks_from_env()`, `matching()`, `skipped()` and `call_py_hooks()`
  take `env: HTTPEnv` (keyword-only) instead of a mapping `environ`.
  `hooks.PREFIX`, `SKIP_ENV`, `URL_ENV`, `KEY_ENV` and `CURL_ENV` are
  replaced by the setting names `HOOKS`, `HOOK_SKIP`, `HOOK_URL`, `HOOK_KEY`
  and `HOOK_CURL`.
- `proxy.AUTH_VARS`, `AUTH_HEADER_VAR` and `TYPE_VAR` are replaced by the
  setting names `PROXY_AUTH`, `PROXY_AUTH_HEADER` and `PROXY_TYPE`.

[Unreleased]: https://github.com/jose-pr/httplib/commits/main

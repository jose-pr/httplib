# syshttp — contributor orientation

| Shipped header | Covers |
| --- | --- |
| [`src/syshttp/AGENTS.md`](src/syshttp/AGENTS.md) | the whole public API, its settings and gotchas |

## Layout

- `src/syshttp/` — the package. `env.py` is the only module that knows how a
  setting's name is built; every other module asks an `HTTPEnv`.
- `tests/` — pytest. `conftest.py` clears every `SYSHTTP_*` variable per test.
  `test_proxy_auth.py` and `test_jars_proxy.py` hold fake proxies, gateways
  and origins on 127.0.0.1 that other test modules import.
- `docs/` + `mkdocs.yml` — the docs site (MkDocs Material, mkdocstrings).

## Environment

Python 3.9 or later. One venv per interpreter, under
`.pyvenv/<version>-<os>-<arch>/` (`dotagents pyvenv`, `dotagents pyvenv 3.9`).
The 3.9 venv needs `pip install --upgrade pip` before an editable install
(pip 21.2 lacks PEP 660).

```bash
.pyvenv/<tag>/Scripts/python -m pip install -e ".[dev,docs]"
```

## Checks

```bash
.pyvenv/<tag>/Scripts/python -m pytest -q        # warnings are errors
.pyvenv/<tag>/Scripts/python -m black --check src tests
.pyvenv/<tag>/Scripts/mkdocs build --strict
```

`tests/test_switches.py` runs mypy over `src/syshttp` when mypy is installed.

## Conventions

- A setting is read through `HTTPEnv` at call time, never at import.
  Messages name the variable found (`env.find(...)`), else `env.name(...)`.
- `requests` is imported inside functions only, and under `TYPE_CHECKING` for
  annotations. `test_syshttp_typing_never_imports_requests_at_runtime`
  enforces this.
- Black, line length 120, target py39.

## Releasing

See `README.md` → Releasing. Bump `version` in `pyproject.toml` in the same
commit as the `CHANGELOG.md` entry.

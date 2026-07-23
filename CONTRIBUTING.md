# Contributing to Web3Guard

Thanks for your interest in contributing! Web3Guard is a security
research tool, and the most valuable contributions are usually:

1. **New vulnerability patterns** — add a new pattern to the catalog
   (`web3guard/utils/vuln_catalog.py`) and a vulnerable test contract
   under `test_contracts/vulnerable/` so the self-test exercises it.
2. **New language adapters** — write a `LanguageAdapter` subclass and
   register it in `web3guard/languages/__init__.py`. The protocol is
   documented in `web3guard/languages/base.py`.
3. **New discovery engines** — add a `DiscoveryEngineBase` subclass in
   `web3guard/discovery/` and add it to `ALL_ENGINES`.
4. **Better prompt-injection defenses** — patterns to detect, response
   markers to look for. See `web3guard/security/prompt_injection.py`.
5. **Tests** — every new pattern or engine should have a unit test in
   `tests/`.

## Development setup

```bash
git clone https://github.com/web3guard-bounty-hunter
cd web3guard-bounty-hunter
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e ".[dev]"
```

## Running tests

```bash
pytest tests/ -v
```

## Linting

```bash
ruff check .
mypy web3guard/
```

## Adding a new language

1. Create `web3guard/languages/<name>.py` with a `LanguageAdapter`
   subclass.
2. Register it in `web3guard/languages/__init__.py` (import + add to
   `_ADAPTERS` in `registry.py`).
3. Add a test contract under `test_contracts/vulnerable/`.
4. Add an entry in the `CATALOG_BY_LANGUAGE` dict in
   `web3guard/utils/vuln_catalog.py`.
5. Add a test in `tests/test_smoke.py` that verifies the adapter
   detects its language and chunks a file.
6. If the language needs a new test runner, implement a sandbox in
   `web3guard/sandbox/<name>.py` and wire it up in
   `web3guard/sandbox/base.py::create_sandbox`.

## Adding a new detection pattern

1. Add the pattern to `web3guard/utils/vuln_catalog.py` under the
   appropriate language.
2. If the pattern is for a specific category (e.g. ERC-4337), add a
   corresponding `DetectionEngine` subclass if needed.
3. Add a vulnerable test contract to verify the pattern triggers.

## Adding a new discovery engine

1. Implement a `DiscoveryEngineBase` subclass in
   `web3guard/discovery/<name>.py`.
2. Add it to `ALL_ENGINES` in `web3guard/discovery/__init__.py`.
3. Add a test in `tests/test_smoke.py` that verifies `is_installed()`
   returns the right value and `run()` doesn't crash on an empty
   target.

## Pull request process

1. Fork the repo and create your branch from `main`.
2. Run the test suite and linter locally; both must pass.
3. Add tests for any new functionality.
4. Update the README and docs as needed.
5. Submit a PR; expect a review cycle of 1-3 days.

## Reporting security issues

**Do not** open a public GitHub issue for security-sensitive problems.
See [SECURITY.md](SECURITY.md) for the disclosure process.

## License

By contributing, you agree that your contributions will be licensed
under the MIT License.

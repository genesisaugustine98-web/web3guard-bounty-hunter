# Web3Guard v3.6.1 — Dead Code & Wiring Audit
Date: 2026-09-28
Scope: full package cross-reference (AST), CLI surface, docs claims vs reality

## Method
- ruff (F401/F841/ARG/ERA/PLW): only interface-arg noise; zero unused imports/locals.
- AST cross-reference of every top-level def/class/constant + `__all__` export
  against all references in web3guard/, tests/, scripts/, pyproject.

## Dead code — REMOVED
1. `web3guard/routing/` (router.py + __init__.py, 271 lines) — never imported
   by any module, test, script, or entry point. `AIClient._role_models` +
   per-provider circuit breakers already provide the shipped behavior
   (static config wins, v3.3). Superseded design; safer to delete than wire.
2. `is_retryable_http` (utils/resilience.py) — zero references; docstring
   claimed "aligned with fetch.py" but fetch.py inlines its own 408/429 rule.
3. `routes_for_target` (utils/bounty.py) — zero references; CLI constructs
   ScopeAllowlist directly (cmd_scope).

## Unwired code — WIRED
1. `web3guard/accel` (PythonAccelerator/RustAccelerator/accelerator +
   native/web3guard-accel Rust crate, ~700 lines incl. crate):
   v3.5 feature, never imported outside itself. Wired into the Gitleaks
   discovery engine's builtin regex fallback via a single `secret_matches`
   helper on the accelerator — exact rule parity guaranteed:
   - native covers 7/8 SECRET_PATTERNS regexes (identical patterns verified);
   - the mnemonic rule needs Python-side BIP39 heuristics, so the wrapper
     re-runs `iter_secret_matches` and unions its mnemonic matches in.
   `extract_imports`/`hash_files` intentionally NOT wired: native implements
   only 2 of Python's import patterns (would drop graph edges = weaker
   dirty-propagation) and hashes raw bytes vs the graph's decoded text
   (would corrupt persisted hashes). Both parity gaps documented in code.
2. `python -m web3guard.accel` — accel_cli existed but the package lacked
   `__main__.py`; command 404'd. Added 6-line dispatcher.

## Exports cleaned
`web3guard/accel/__init__.py.__all__` no longer exports the two engine
classes (they are implementation details; `accelerator`/`reset_accelerator`
are the public surface).

## Kept (verified as intentionally supported surface)
- ALL_ENGINES discovery engines: iterated in scanner.py via the tuple.
- classify_error: covered by tests/test_v34_upgrade.py.
- sandbox protocol methods, CLI `price` handler, __init__ re-exports used
  via `from X import Y` elsewhere.

# Plan: Non-EVM runtime-impact honesty + Cairo harness

Date: 2026-09-13

## Goal

Make non-EVM exploit confirmation honest:

1. A test runner that cannot execute at runtime (compile-only or known-broken)
   must never produce `CONFIRMED EXPLOIT`.
2. A runner that does execute must prove runtime impact with a
   machine-readable marker before confirmation.
3. Deliver one real, locally-testable non-EVM harness (Cairo / `scarb`).

Feasibility findings (spike, 2026-09-13):

- `scarb test` executes tests and prints `println!` output, but the marker
  lands beyond the current 512-byte output cap.
- `blueprint create web3guard-sandbox` fails (hyphenated name is rejected,
  then a ts-node config error). `blueprint test` exits 0 without running the
  spec, so `test_func_sandbox_smoke` passes vacuously. TON is therefore marked
  non-confirmable until a real harness exists.

## Scope

- In: tail-preserving truncation; `TestRunner.runtime_confirmable`; shared
  impact-marker parser; scanner gate; Clarity + TON non-confirmable; Cairo
  extractor + pre-filter + template; real `scarb` e2e; CI wiring.
- Out: real TON/Blueprint harness; Move/Solana/anchor extractors (no local
  toolchains); differential mutators for non-Solidity.

## Global constraints

- Keep `ffi = false` and `fs_permissions = []` hardening untouched.
- Never expose provider API keys to sandboxes.
- TDD: failing test first, then implementation, then green + commit.
- Python is `python3`; add `PATH="$HOME/.foundry/bin:$PATH"` when forge is needed.

## Task 1: Preserve the tail of truncated sandbox output

**Files:** `web3guard/security/sandbox_guard.py`, `tests/test_smoke.py`

Runtime markers (e.g. `scarb test`) appear near the end of output. Keep the
head *and* the tail so markers survive, and raise the default cap.

- Raise `max_revert_reason_bytes` default `512 -> 8192`.
- `truncate_revert_reason` returns `head + "...[truncated by SandboxGuard]..." + tail`
  with each half `(limit - marker)//2`.
- Test: assert a tail-only marker is preserved; keep the existing length/`truncated` assertions.

## Task 2: `TestRunner.runtime_confirmable`

**Files:** `web3guard/languages/base.py`, `web3guard/languages/clarity_lang.py`,
`web3guard/languages/func_lang.py`, `web3guard/scanner.py`, `tests/test_exploit_confirmation.py`

- Add `runtime_confirmable: bool = True` to `TestRunner`.
- Clarinet runner and TON/Blueprint runner set `runtime_confirmable=False`.
- In `scanner._generate_poc`, after the sandbox reports success, if
  `not adapter.test_runner.runtime_confirmable` do not set `CONFIRMED EXPLOIT`;
  set `last_err = "runner cannot confirm at runtime (compile-only or no harness)"`.
- Test: a fake adapter whose runner is `runtime_confirmable=False` never confirms.

## Task 3: Shared impact-marker parser

**Files:** `web3guard/languages/base.py`, `web3guard/languages/solidity.py`,
`tests/test_impact_extraction.py`

- Add `parse_impact_marker(output) -> ImpactEvidence | None` parsing the
  existing `impact_gain:` / `impact_loss:` convention (values may use `_`).
- Solidity `extract_impact_solidity` delegates to it (behavior unchanged).
- Test: marker parsing, underscore thousands, missing marker => None, zero => not confirmed.

## Task 4: Cairo impact extraction + pre-filter + template

**Files:** `web3guard/languages/cairo_lang.py`, `tests/test_impact_extraction.py`

- `extract_impact_cairo = parse_impact_marker`; wire `extract_impact=` on `_CAIRO_RUNNER`.
- `_has_impact_assertion_cairo` additionally requires a `println!("impact_gain"...` or
  `println!("impact_loss"...` emit (mirrors Solidity Task 7).
- Append the marker instruction to `_CAIRO_EXPLOIT_TEMPLATE`.

## Task 5: Real `scarb` e2e

**Files:** `test_contracts/cairo_reward/src/reward.cairo` (new),
`tests/test_cairo_impact_e2e.py` (new), `.github/workflows/bounty-hunter.yml`

- Fixture: a plain-Cairo reward function that double-credits (accounting bug).
- E2E drives `Scanner._generate_poc` with a scripted PoC that emits
  `println!("impact_gain: ...")`; asserts `CONFIRMED EXPLOIT` +
  `metadata["impact_gain"] > 0`. Skips when `scarb` is absent.
- A second case with a marker-less PoC asserts no confirmation.
- Wire into the `toolchain-smoke` run line.

## Verification

- `python3 -m pytest tests/test_smoke.py tests/test_impact_extraction.py tests/test_exploit_confirmation.py -q`
- `python3 -m pytest tests/test_cairo_impact_e2e.py -q` (needs scarb)
- `PATH="$HOME/.foundry/bin:$PATH" python3 -m pytest -q`
- Push and poll CI.

## Follow-on #2: remaining runner honesty (done, df94aa8)

**Files:** `web3guard/languages/{vyper,move_lang,rust_solana,ts_sdk}.py`,
`tests/test_impact_extraction.py`, `tests/test_exploit_confirmation.py`

- Vyper shares `_FOUNDRY_RUNNER`, so it is runtime-confirmable, but its
  `_VYPER_EXPLOIT_TEMPLATE` never asked for the `impact_gain`/`impact_loss`
  log. Every Vyper PoC was rejected by the pre-filter and could never
  confirm. Added the marker instruction to the template.
- Move, Solana/Anchor, and ts-sdk have no verified runtime impact harness
  (and Solana/ts-node are not installed in CI). Set
  `runtime_confirmable=False` so they never emit `CONFIRMED EXPLOIT`.
- Pinned the confirmable/non-confirmable runner matrix in a test.
- Still out: real Move/Solana/ts-sdk harnesses; real TON/Blueprint harness.

# Design: Expand Language Toolchains and Benchmark Corpus

Date: 2026-08-28
Status: Approved

## Problem

Two gaps limit the tool's usefulness:

1. **Only Solidity/Vyper PoCs can confirm exploits on CI.** The runner
   installs Foundry and nothing else, so findings in Cairo, Clarity,
   FunC, Move, Solana/Rust, and TS-SDK are always `POTENTIAL` — either
   the toolchain is missing or the model returns nothing for them.
2. **The benchmark corpus is narrow.** `web3guard/bench/corpus.json`
   has 16 units: 14 vulnerable (one per non-EVM language) + 2 clean,
   both Solidity. The clean set does not exercise any non-Solidity
   language, and there is only one vulnerable variant per non-EVM
   language, so detector regressions are easy to miss.

## Goal

- Install every language toolchain on CI so non-Foundry sandboxes can
  actually build and run PoCs.
- Grow the corpus: a clean fixture per non-Solidity language plus 2–3
  additional vulnerable variants per language, all labeled within the
  static analyzer's `VALID_CATEGORIES` taxonomy.
- Gate regressions with a precision/recall bench test.

## Non-Goals

- Improving scan throughput (parallel chunking, sandbox reuse) — separate work.
- Wiring the Worker secrets / phone front door — separate work.
- Rewriting the exploit confirmation pipeline for non-Foundry languages.

## Architecture / Components

### 1. CI toolchain installation

New `scripts/setup-toolchains.sh` (idempotent, `set -e`, run from repo
root). Installs, per runner requirement:

| Tool | Needed for | Install path |
|------|-----------|--------------|
| Node.js LTS | ts-sdk, blueprint (func), anchor tests | `actions/setup-node` |
| `clarinet` | Clarity | pinned GitHub release binary |
| `scarb` | Cairo | official install script |
| `@ton-community/blueprint` | FunC (`blueprint` CLI) | npm global |
| `aptos` CLI | Move | pinned GitHub release binary |
| Solana toolchain + `anchor` | rust-solana | Solana install script + `cargo install` anchor-cli |

Both `scan-on-command` and `scan` jobs call the script right after
"Install Foundry". Add `actions/cache` for `~/.cargo`, the Solana
install directory, and the scarb registry so install time stays
bounded across runs.

Missing toolchain must degrade gracefully: the sandbox already returns
`POTENTIAL (sandbox init failed)` when a binary is absent, so a failed
install of one language must not block the rest of the scan. The script
fails the job loudly on its own install errors (`set -e`), but each
toolchain install is isolated in a function so a single bad URL does
not abort all the others.

### 2. Sandbox verification

End-to-end smoke test each runner's command set locally with its
toolchain:
- Clarity: `clarinet new` → `clarinet check` → `clarinet test --filter`
- Cairo: `scarb init` → `scarb build` → `scarb test -f`
- FunC: `blueprint create` → `blueprint build` → `blueprint test --filter`
- Move: `aptos move compile` → `aptos move test --filter`
- TS-SDK: `npm init -y` → `tsc --noEmit` → `npx ts-node poc.ts`
- Solana: `anchor init` → `anchor build` → `anchor test --skip-deploy`

Fix any runner command gaps discovered (e.g., blueprint requiring the
global npm package, missing node, missing SDK deps for ts-sdk/anchor
tests).

### 3. Corpus expansion

Fixtures are self-authored, compact, and placed under
`test_contracts/`. Update `web3guard/bench/corpus.json` labels.

**Clean fixtures (one per non-Solidity language):**
`SafeVault.vy`, `SafeVault.move`, `SafeVault.cairo`, `SafeVault.clar`,
`SafeVault.fc`, `safe_program/src/lib.rs` (Solana), `SafeClient.ts`
(ts-sdk). Labels: `[]`.

**Vulnerable variants (2–3 additional per language), using only classes
the analyzer already detects in that language** (based on existing
corpus labels) so recall stays measurable:

- Solidity (already well-covered): add `short-address` and `tx-origin`
  variants.
- Vyper: add an `arithmetic` and an `access-control` variant.
- Move: add a second `access-control`/`missing-acquires` variant.
- Cairo: add a `signature-replay` variant.
- Clarity: add an `unchecked-external-call` variant.
- FunC: add an `arithmetic` and an `access-control` variant.
- Solana/Rust: add an `unprotected-init` and an `access-control` variant.
- TS-SDK: add an `unlimited-approval` and a `slippage` variant.

Labels must only use categories in `VALID_CATEGORIES` in
`web3guard/bench/metrics.py`.

### 4. Bench scoring gate

New `tests/test_benchmark_gate.py` runs the CLI bench:

```
python -m web3guard bench --corpus web3guard/bench/corpus.json --fail-below PRECISION,RECALL
```

with floors starting at the current `1.000,1.000`. If a detector
legitimately misses a class in a new fixture, relax the floor per
language with an explicit justification comment in the test rather than
silently dropping the fixture.

### 5. Verification

- Local: `python -m web3guard bench` green; full pytest suite green;
  corpus manifest passes schema checks (paths exist, labels valid).
- CI: toolchain step smoke-tested with one repository-dispatch scan.

## Risk

- **Solana/Anchor install is heavy and flaky** on free-tier runners.
  Fallback if it proves too slow/brittle: isolate rust-solana
  confirmation into its own CI job so it cannot block the rest, or mark
  the Solana fixture as the only language that may relax its bench
  floor.
- Non-Foundry PoCs may still be poor quality (the model returns empty
  for some languages). Toolchain installs fix *runnability*, not *model
  output quality*; the existing `POTENTIAL` fallback still applies.

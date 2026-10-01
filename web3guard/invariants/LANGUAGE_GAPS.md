# Language support gaps — invariant fuzzing (Phase 6)

Web3Guard's invariant engine (LLM-drafted "must-always-hold" properties +
bounded fuzzing) supports a language only when **both** halves exist:

1. a registered harness renderer (`register_renderer` in
   `web3guard/invariants/harness.py`), and
2. a real, locally-installable fuzzing toolchain the campaign can run
   sandboxed.

If either half is missing, the pipeline degrades to an honest skip with a
note — it never pretends to fuzz a language it cannot run. This file
records, per language, what exists, what was tried, and what would unblock
support.

## Supported today

### Solidity — SUPPORTED (Phase 2)
Renderer: Foundry project (`render_solidity_project`). Toolchain: `forge`
(preferred) with an Echidna fallback; honest skip when neither is
installed. This is the original Phase 2 path, unchanged by Phase 6.

### Vyper — SUPPORTED (Phase 6)
Renderer: `web3guard/invariants/vyper_harness.py` — emits the Vyper source
plus a `run_invariants.py` driver. Toolchain: **titanoboa** (the Vyper
interpreter / test framework), installed as a persistent venv at
`~/workspace/tools/vyper-invariants/venv` (imported as `boa`).
The driver compiles once, deploys fresh per run with a seeded RNG,
randomizes senders (`boa.env.prank`) and args per ABI type, absorbs
reverts (sequence continues, like Foundry/Medusa handler semantics), and
evaluates each invariant after every call. Verified end-to-end: a
deliberately-broken Vyper vault (withdraw forgets `total_assets`) yields
exactly one `HIGH` / `POTENTIAL` finding; the fixed vault is clean.

### Cairo (Starknet) — SUPPORTED (Phase 6)
Renderer: `web3guard/invariants/cairo_harness.py` — emits a full Scarb
project (`Scarb.toml` + pre-resolved `Scarb.lock` + `src/lib.cairo` +
`tests/invariants.cairo`). Toolchain: **Starknet Foundry (`snforge`)**
0.64.0 + `scarb` 2.20.1 + `universal-sierra-compiler`, installed to
persistent paths under `~/workspace/tools/` (never `~/.local`, which is
ephemeral). Each invariant becomes a `#[fuzzer]` test: snforge varies a
seed, an in-test LCG expands it into a randomized call sequence, and
calls go through the low-level `call_contract_syscall` so reverts are
absorbed instead of aborting the sequence. Verified end-to-end: a
deliberately-broken Cairo vault (withdraw forgets `total_assets`) is
caught with the fuzzer's counterexample; the fixed vault is clean.
Caveats: the Cairo assertion grammar is deliberately strict (getter
comparisons joined by `&&`/`||`); anything outside it is skipped
honestly, never treated as passing.

## Gaps (honest, no fake support)

### Move — GAP
Move has a real verification story (the Move Prover, an SMT-based
verifier), but it is not a *fuzzer*: it needs SMT solvers installed and
per-project prover configuration, and there is no lightweight
"randomized call sequence" runner comparable to Foundry/titanoboa/snforge
that we could drive uniformly. The Aptos/Sui CLIs are heavy installs and
their test runners are unit-test oriented, not invariant-fuzz oriented.
**What would unblock:** a maintained Move fuzzing harness with a stable
CLI (or first-class Prover integration with bundled solvers).

### Clarity (Stacks) — GAP
Modern Clarity testing lives in TypeScript: `clarinet` test projects need
Node ≥ 18, pnpm, `@stacks/clarinet-sdk`, and vitest *per scanned
project* — a heavy, network-dependent install with no standalone fuzz
engine. There is no local, zero-dependency Clarity fuzzer we could
bundle. **What would unblock:** a standalone Clarity interpreter with a
fuzzable API (or a clarinet offline bundle we can vendor).

### FunC / TON — GAP
FunC tooling is thin: the TON compiler toolchain has no maintained
invariant-fuzzing story, and test frameworks are ad-hoc TypeScript. Per
the phase scope, FunC was explicitly permitted to remain a gap.
**What would unblock:** a TON equivalent of titanoboa/snforge with
scriptable randomized execution.

### Rust (Anchor / Solana) — GAP
Rust *has* fuzzers (cargo-fuzz, honggfuzz), but wiring "LLM invariants
over an Anchor program" needs program-specific IDL handling, a Solana
test validator, and heavy toolchain installs per project — a large,
separate integration. Explicitly permitted to remain a gap for this
phase. **What would unblock:** a dedicated Anchor-invariant integration
(akin to Trident, the Solana fuzzing framework) with a stable CLI.

### TypeScript — GAP
TypeScript contracts here means off-chain/bot logic rather than
on-chain programs; "invariant fuzzing" of TS is property-based testing
(fast-check) over project-specific harnesses, not a uniform engine we
can drive from contract source alone. **What would unblock:** a
convention for TS contract harnesses we can target uniformly.

## Design rule (standing)

Renderer registration = language support; toolchain detection =
execution. A language with a renderer but no detectable toolchain, or a
toolchain with no renderer, degrades to a loud skip — never a silent
pass, never a fabricated finding.

# Design: External Reachability Pre-Filter (B1.2)

Date: 2026-09-16
Status: Approved

## Problem

Findings can be *present* without being *reachable*. The static
analyzer flags a code shape wherever it appears: the Solidity
reentrancy detector (`web3guard/discovery/static_analyzer.py:225`) flags
any function body with an external call before a state write, even if
that function is `internal`/`private` and nothing in the project ever
calls it. The AI chunk analysis can produce the same class of finding.

Runtime confirmation (impact marker + differential) already proves
reachability *for confirmed findings*, but only after an exploit is
generated and executed. Findings that are not externally reachable burn
AI/sandbox budget and inflate the report.

## Goal

Classify each finding as externally reachable, not reachable, or
unknown, and reject only the provable not-reachable cases before exploit
generation is attempted.

## Non-Goals

- Soundness. This is a conservative heuristic; it errs to `UNKNOWN`.
- Replacing runtime confirmation. Reachability is a pre-filter and
  annotation, never a confirmation signal.
- Authorization analysis. `onlyOwner`-gated paths are still reachable.
- Non-Solidity confirmation harnesses (separate work).

## Decisions

- **Role:** static pre-filter (option 1). Annotation plus definitive
  rejection; never a `CONFIRMED EXPLOIT` gate.
- **Scope:** Solidity-first with full visibility + inheritance + call
  resolution; a cheap visibility check for Vyper, Move, Cairo, Clarity;
  everything else `UNKNOWN`.
- **Behavior:** always annotate `metadata["reachability"]`; reject only
  definitive `not_reachable`; `unknown` and `reachable` are untouched.
- **Implementation:** custom lightweight parser by default, optionally
  corroborated by Slither when it is installed (hybrid).

## Architecture / Components

New package `web3guard/reachability/`:

### `types.py`

- `ReachabilityVerdict(StrEnum)`: `REACHABLE`, `NOT_REACHABLE`, `UNKNOWN`.
- `ReachabilityEvidence` (frozen dataclass): `verdict`, `backend`
  (`"solidity-parser" | "slither" | "visibility"`), `function`, `detail`,
  optional `entrypoint` and `path`, optional `gated`.

### `solidity_index.py`

- `FunctionInfo`: name, contract, file, visibility, `is_constructor`,
  `is_modifier`, `abstract`, `virtual`, `body`, `calls: set[str]`,
  `parents: list[str]`.
- `FunctionIndex.build(target_path)`: scans user `.sol` files once and
  indexes every function, its contract's parents, and callee names
  referenced in the body. Skips tests, mocks, and vendored libraries
  using the existing `_is_user_code` conventions.
- `FunctionIndex.find_enclosing(file, function, line)`: locates the
  function owning a finding, preferring an explicit function name and
  falling back to a line-to-function lookup (the logic currently in
  `scanner._function_name_at`).

### `solidity.py`

Pure verdict resolver over a `FunctionIndex` + target function. See
Verdict Rules.

### `slither_backend.py`

Optional corroboration. If `slither` imports and parses the target
within a bounded timeout, it is used to (a) rescue a custom
`NOT_REACHABLE` when Slither sees a caller/entrypoint, and (b)
corroborate a `NOT_REACHABLE`. Slither alone never produces
`NOT_REACHABLE`; any absence, error, or timeout is swallowed and the
custom verdict stands. Slither never runs on non-Solidity.

### `analyzer.py`

- `ReachabilityAnalyzer(target_path, *, use_slither=True)`: lazily
  builds and caches the `FunctionIndex`; routes by language; combines
  custom and Slither verdicts.
- `classify(finding) -> ReachabilityEvidence`: pure; does not mutate the
  finding. The scanner owns gating.

## Verdict Rules

Reachability means an external path exists, not that it is
permissionless. `onlyOwner`-gated functions are `REACHABLE` with
`gated: true`.

**Solidity entrypoints:** `public`/`external` functions, `constructor`,
`fallback`, `receive`; public library functions count as reachable.

Resolution for function `F`:

1. Not found in the index → `UNKNOWN`.
2. Modifier, or `virtual`/abstract/interface member → `UNKNOWN` (a
   derived contract could expose it).
3. Constructor or `public`/`external` → `REACHABLE`.
4. `internal`/`private` → search reverse call edges by name across all
   user files (this captures inheritance exposure):
   - Identifier `F.name` appears nowhere else in user code (excluding the
     declaration itself, comments, and string literals) →
     `NOT_REACHABLE` (dead code). **Case (a).**
   - BFS up the reverse-call closure; if any ancestor is an entrypoint →
     `REACHABLE`, recording `entrypoint` and `path`.
   - Callers exist but the closure never reaches an entrypoint, **and**
     `F` is non-virtual in a concrete, non-interface contract →
     `NOT_REACHABLE`. **Case (b).**
   - Otherwise `UNKNOWN`.
   - Name collisions and overrides err toward `REACHABLE` (conservative).

**Slither corroboration:**

| Custom | Slither | Result |
|--------|---------|--------|
| `NOT_REACHABLE` | sees a caller/entrypoint | `REACHABLE` (rescue) |
| `NOT_REACHABLE` | agrees | `NOT_REACHABLE`, backend `"slither"` |
| any | unavailable / error / timeout | custom verdict |
| any | `REACHABLE` | `REACHABLE` |

Slither alone never yields `NOT_REACHABLE`.

**Non-Solidity** (never rejects in this slice — only `REACHABLE` or
`UNKNOWN`):

- **Vyper:** `@external`/`@public` → `REACHABLE`; `@internal`/`@private`
  with a `self.name(` chain to a reachable function → `REACHABLE`; else
  `UNKNOWN`.
- **Move:** `entry`/`public entry`/`public fun` → `REACHABLE`; private
  `fun` → `UNKNOWN`.
- **Cairo:** `#[external]`/`#[abi]` → `REACHABLE`; else `UNKNOWN`.
- **Clarity:** `define-public` → `REACHABLE`; else `UNKNOWN`.
- Others → `UNKNOWN`.

Evidence is written to
`finding.metadata["reachability"] = {verdict, backend, function, detail,
entrypoint?, path?, gated?}`.

## Gating and Integration

- Config: `enable_reachability: true`, `reachability_use_slither: true`.
  Disabling restores current behavior.
- `scanner._scan_one` builds one `ReachabilityAnalyzer(target_path)` per
  target when enabled.
- **AI path:** `_analyze_chunk` gains a `reachability` parameter
  (default `None` = no-op). After the `Finding` and fingerprint are
  built and before `_generate_poc`, classify. On `NOT_REACHABLE` set
  `status = "REJECTED"` and
  `metadata["rejection_reason"] = "not externally reachable"`, skip the
  PoC, self-critique, and economics, and return the finding. This is
  where the cost saving occurs.
- **Discovery path:** in the `_scan_one` adapter loop, classify each
  discovery finding as it is appended; `NOT_REACHABLE` → `REJECTED` +
  reason. Discovery findings get no PoC regardless; the win is
  precision.
- `REACHABLE`/`UNKNOWN` are unchanged.
- Rejected findings remain in `tr.findings`, so `reports/builder.py` and
  `reports/digest.py` show them with status `REJECTED` and the reason —
  traceable, never silently dropped.

## Failure Handling

- Index build failure → analyzer returns `UNKNOWN` for every finding;
  the scan proceeds.
- Slither import/parse/timeout failure → custom verdict stands.
- The analyzer never raises into the scan loop; exceptions degrade to
  `UNKNOWN`.

## Testing

Unit:

- `FunctionIndex`: visibility, `is`-inheritance, `calls` edges,
  `find_enclosing` by name and by line hint.
- `solidity.py` verdict matrix:
  - `public` → `REACHABLE`.
  - `internal` called by a `public` → `REACHABLE` with `path` and
    `entrypoint`.
  - `internal` inherited from a base and called by a derived `public` →
    `REACHABLE` (inheritance resolution).
  - identifier referenced nowhere → `NOT_REACHABLE` (case a).
  - `internal` called only by an uncalled `internal` in a concrete
    contract → `NOT_REACHABLE` (case b).
  - `virtual`/abstract/interface → `UNKNOWN`.
  - not in index → `UNKNOWN`.
  - `onlyOwner` `public` → `REACHABLE` + `gated`.
- Slither backend: absent → custom stands (skip); a fake/mocked Slither
  exercises rescue and corroboration; one opt-in real-Slither test
  skipped when uninstalled.
- Scanner integration: reuse the fakes in
  `tests/test_exploit_confirmation.py`; assert a `NOT_REACHABLE` finding
  never invokes the sandbox and ends `REJECTED` with metadata, while a
  `REACHABLE` finding proceeds.
- Non-Solidity visibility: Move/Cairo/Clarity/Vyper yield
  `REACHABLE`/`UNKNOWN` only, never `NOT_REACHABLE`.

Fixtures:

- `test_contracts/vulnerable/UnreachableReentrancy.sol` — internal-only
  helper with no callers.
- `test_contracts/vulnerable/InheritedReentrancy.sol` — base `internal`
  helper plus derived `public` caller.

Verification:

- `python3 -m pytest -q` (no forge), `PATH="$HOME/.foundry/bin:$PATH"
  python3 -m pytest -q` (forge).
- Push and poll CI.

## Known Limitations

- The custom parser is regex/character-level and errs to `UNKNOWN`.
- Slither is opportunistic and never alone produces `NOT_REACHABLE`.
- Cross-target and dynamic dispatch can only inflate reachability (the
  safe direction).
- `unknown` findings are not suppressed, so some present-only false
  positives remain; this slice reduces, not eliminates, them.

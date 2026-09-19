# Design: Precision/Recall Calibration (B2.2)

Date: 2026-09-18
Status: Approved

## Problem

Every Bar-1 change (impact markers, differential confirmation, runtime
honesty, reachability pre-filter, fork parity) ships without evidence that
it improved precision or recall. The benchmark harness scores **only** the
offline static analyzer (`web3guard/bench/runner.py:30`); reachability,
runtime confirmation, and the AI path are unmeasured. The precision/recall
gate can therefore stay green while the pipeline that actually decides
`CONFIRMED EXPLOIT` regresses.

## Goal

Measure the real pipeline at three layers, using the real components at
each layer and no substitute for the component under test:

1. **L1 — Offline discovery + reachability (local, no AI, no toolchain).**
   Score real `StaticAnalyzerEngine` findings with and without the real
   `ReachabilityAnalyzer` pre-filter on a labeled corpus that contains a
   vulnerable-but-unreachable fixture. Prove the filter raises precision
   without lowering recall.
2. **L2 — Runtime confirmation (local, real Foundry).** Drive the real
   `Scanner` + real `FoundrySandbox` + real impact extraction + real
   differential over committed golden PoCs, and score whether the
   confirmation gate confirms true positives and rejects negatives.
3. **L3 — Online live model (CI-only, real provider).** Drive the real
   `Scanner` with a real AI provider over labeled vulnerable and clean
   targets, and score confirmed-finding precision/recall. If no provider
   key is configured, report `not-measured` with a reason and exit 0 —
   never a fake.

## Non-Goals

- Changing any detector, gate, or threshold. This slice only measures.
- A new corpus of external real-world exploits beyond SmartBugs (already
  vendored) and the in-repo fixtures.
- Cost/latency benchmarking of providers.
- Replacing the existing `bench` gate; L1 adds a stage alongside it.

## Decisions

- **Measurement is real.** L1 runs the real static analyzer and the real
  reachability analyzer. L2 runs real forge and the real differential.
  L3 runs a real provider. Only *inputs* are fixed: L2 feeds committed
  golden PoCs; L3 feeds real model output. The component under test is
  never replaced by a fake.
- **The AI client in L2 is a fixed input, not a mock.** L2 calibrates the
  confirmation gates; the PoC is an input fixture exactly like an
  expected-output file. L3 is where the model itself is measured.
- **Honest absence.** A missing toolchain or provider key yields an
  explicit `not-measured` record, never a skipped-without-trace or a
  synthetic score.
- **No regression to the existing gate.** The new reachability units live
  in a separate corpus so the static-only `--fail-below` gate and its
  committed baseline are untouched.
- **One report schema** for all layers so CI can diff and gate it.

## Architecture / Components

### `web3guard/bench/corpus.py`

Honor an optional `"root"` key in a manifest: a path relative to the
manifest's directory used as the corpus root. Absent → current behavior
(manifest's directory, or the repo root for the default manifest).

### `web3guard/bench/pipeline.py` (new)

- `make_reachability_analyzer(target_path, *, use_slither=False)` returns
  a callable `(root: Path) -> list[StaticIssue]` that:
  1. runs the real `StaticAnalyzerEngine().run(root)`;
  2. derives each issue's language from its file suffix (via the existing
     language detection used by the scanner);
  3. runs the real `ReachabilityAnalyzer(root)` on a finding-shaped view
     (`language`, `file`, `function`, `line_hint=line`, `category`);
  4. drops issues whose verdict is `NOT_REACHABLE`; keeps `REACHABLE` and
     `UNKNOWN`.
- Never raises: any per-issue failure keeps the issue (fail open), same
  policy as the scanner.

### `web3guard/bench/calibration.py` (new)

- `calibrate_l1(*, main_corpus, reachability_corpus, use_slither=False)`
  runs `run_benchmark` three ways (main corpus static; reachability
  corpus static; reachability corpus filtered) and returns a report with
  both `Score`s, the `precision_delta`, the `recall_delta`, and the list
  of rejected (file, category) pairs.
- `calibrate_l2(cases, *, workdir)` runs each case through the real
  `Scanner` with a golden-PoC client and returns a confusion matrix.
- `calibrate_l3(cases, *, workdir, env)` returns
  `{"status": "not-measured", "reason": ...}` unless live prerequisites
  hold, otherwise runs each case through the real provider scanner and
  returns a confusion matrix.
- `CalibrationReport` (dataclass) with `to_dict()` emitting schema
  `web3guard-calibration/1` and `measured`/`not-measured` per layer.

### `web3guard/bench/cases.py` (new)

Loaders for the L2 case manifest (`bench/calibration/cases.json`) and the
L3 manifest (`bench/calibration/live.json`), reusing `load_corpus`-style
JSON parsing. A case carries: `name`, `target` (fixture dir), `poc`
(golden PoC file, L2 only), `category`, `language`, `expect_confirmed`.

### `web3guard/cli.py`

New subcommand `calibrate`:
- `--layers l1,l2,l3` (default `l1`; a later layer implies its
  prerequisites are separately runnable).
- `--corpus`, `--reachability-corpus`, `--cases`, `--live-cases`.
- `--json PATH` writes the report.
- `--fail-on-regression` exits non-zero when L1's `precision_delta <= 0`
  or L1 recall drops; L2/L3 never gate on precision alone (they gate on
  the documented floors in the case manifests).

### Fixtures and manifests

- Reuse the existing reachability fixtures in `test_contracts/reachability/`:
  `UnreachableReentrancy.sol` (internal-only, no caller; label set empty)
  and `InheritedReentrancy.sol` (base helper reachable via a derived
  `public` function; `["reentrancy"]`). They are not moved, so the B1.2
  e2e test keeps referencing them. The static analyzer flags both; the
  reachability filter must reject the former and keep the latter.
- `bench/reachability/corpus.json` with `"root": "../.."` listing both
  units (plus one existing clean Solidity unit as a control).
- `bench/reachability/reports/baseline.json` committed from the real run.
- `bench/calibration/cases.json` + `bench/calibration/pocs/reentrancy.t.sol`
  (the existing real profitable PoC):
  - `reentrancy_positive` → target dir
    `bench/calibration/targets/reentrancy_vuln/` (a `ReentrancyVault.sol`
    copy of the vulnerable fixture) → `expect_confirmed: true`.
  - `reentrancy_fixed` → target dir
    `bench/calibration/targets/reentrancy_fixed/` (same contract/file name
    with the state update before the external call) → the same PoC must
    fail to pass the impact assertion → `expect_confirmed: false`.
  Each case `target` is a directory (the sandbox mirrors a tree), and the
  case's `poc` is a committed golden PoC file.
- `bench/calibration/live.json`: vulnerable + clean targets for L3.

## Data Flow

```
calibrate --layers l1
  → load_corpus(main) + load_corpus(reachability, root=../..)
  → StaticAnalyzerEngine (real)                      [static stage]
  → StaticAnalyzerEngine + ReachabilityAnalyzer      [filtered stage]
  → evaluate() both → CalibrationReport(l1)

calibrate --layers l2   (forge required)
  → cases.json + golden pocs
  → Scanner(enable_exploit, enable_differential, golden-poc client)  [real]
  → per-case CONFIRMED/not → confusion matrix

calibrate --layers l3   (provider required)
  → live.json
  → Scanner(real ai_providers)                                       [real]
  → per-case CONFIRMED/not → confusion matrix, or not-measured
```

## Metrics

- L1: finding-level precision and category-level recall (existing
  `Score`); report static vs filtered and the deltas.
- L2/L3: confusion matrix over cases — `tp` (vulnerable confirmed),
  `fp` (clean/patched confirmed), `fn` (vulnerable unconfirmed),
  `tn` (clean/patched unconfirmed); precision `tp/(tp+fp)`, recall
  `tp/(tp+fn)`.

## Failure Handling

- L1 pipeline fails per-issue open (keep the issue).
- L2 without forge → `not-measured` with reason `forge not installed`.
- L3 without `WEB3GUARD_LIVE_E2E=1` or without a provider key →
  `not-measured` with an explicit reason.
- A case whose sandbox errors counts as unconfirmed (negative), and the
  error is recorded on the case, never silently dropped.

## Testing

Real components, no fakes of the measured layer:

- `corpus.py` root key: a manifest with `"root": "../.."` resolves
  units; absent behaves as before.
- `pipeline.py`: on the reachability corpus, the real pipeline returns
  the inherited (reachable) issue and not the unreachable one; on a
  language with no backend, issues pass through (fail open).
- `calibration.py` L1: real run over the reachability corpus asserts
  `precision_delta > 0` and `recall_delta == 0`; the unreachable pair is
  in the rejected list.
- `calibration.py` L2: real forge run over the two cases asserts
  `tp == 1`, `tn == 1`, `fp == 0`, `fn == 0`; skipped where forge is
  absent.
- `calibration.py` L3: without env/keys asserts `status ==
  "not-measured"` and a non-empty reason (no network access).
- CLI: `python -m web3guard calibrate --layers l1 --json ...` exits 0,
  writes the schema, and `--fail-on-regression` works on a synthetic
  zero-delta input via the pure report function.
- Existing `tests/test_benchmark_gate.py` stays green (main corpus gate
  untouched).

Verification:

- `python3 -m pytest -q` (no forge).
- `PATH="$HOME/.foundry/bin:$PATH" python3 -m pytest -q` (forge).
- `ruff check` on changed files.
- Push and poll CI; add the L1 calibrate step to the `bench` job and the
  L2 calibrate test to the `toolchain-smoke` job, and call L3 from the
  existing `live-exploit-e2e` job.

## Known Limitations

- L1's recall is category-level and the reachability corpus is tiny, so
  the delta is directional evidence, not statistical confidence.
- L2's golden PoCs are curated; they cannot discover a confirmation
  regression on a code shape no case covers.
- L3 is nondeterministic and cost-bearing; it runs only in the opt-in
  live job and reports its provider/model in the report.

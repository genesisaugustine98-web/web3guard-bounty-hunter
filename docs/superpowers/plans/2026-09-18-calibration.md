# Precision/Recall Calibration (B2.2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure the real Web3Guard pipeline at three layers — offline discovery+reachability, runtime confirmation, and online live-model — with no fake of the component under test.

**Architecture:** A `web3guard calibrate` CLI runs layer functions. L1 uses the real `StaticAnalyzerEngine` and real `ReachabilityAnalyzer` over a new reachability corpus and reports the precision delta. L2 drives the real `Scanner` + real forge + real differential over committed golden PoCs. L3 drives the real `Scanner` with real providers over labeled targets, or reports `not-measured`.

**Tech Stack:** Python 3.11+, `pytest`, the `web3guard` CLI, Foundry (`forge`), real AI providers (L3 only).

**Spec:** `docs/superpowers/specs/2026-09-18-calibration-design.md`

## Global Constraints

- Python is `python3` (never `python`).
- Foundry-backed tests need `PATH="$HOME/.foundry/bin:$PATH"`.
- Repo root: `/tmp/opencode/web3guard-bounty-hunter`; always set the shell workdir there.
- TDD: failing test first, then implementation, then green.
- Do not add gratuitous inline comments; match the existing module-docstring style.
- Keep `ffi = false` and `fs_permissions = []` in generated Foundry configs (untouched here).
- Never print or commit secrets; never read provider keys' values into reports.
- Commit identity: `git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" commit -m "..."`.
- Push with `GIT_ASKPASS=/tmp/opencode/git-askpass.sh git -c credential.helper= push origin main`.
- **No fakes of the measured component.** L1 uses the real analyzer pkg; L2 uses real forge and real differential with a fixed golden PoC input; L3 uses a real provider. Missing prerequisites yield `not-measured`, never a synthetic score.
- The existing static-only `bench` gate and its committed baseline must stay green (do not add the unreachable fixture to `web3guard/bench/corpus.json`).

---

### Task 1: Corpus `root` key and the reachability pipeline analyzer

**Files:**
- Modify: `web3guard/bench/corpus.py:53-78,86-129`
- Create: `web3guard/bench/pipeline.py`
- Modify: `web3guard/bench/__init__.py`
- Test: `tests/test_calibration.py` (create)

**Interfaces:**
- Consumes: `web3guard.discovery.static_analyzer.StaticAnalyzerEngine`, `web3guard.reachability.ReachabilityAnalyzer`, `ReachabilityVerdict`.
- Produces:
  - `load_corpus`/`validate_corpus` honor an optional manifest `"root"` (relative to the manifest dir).
  - `make_reachability_analyzer(*, use_slither: bool = False) -> Callable[[Path], list[StaticIssue]]`.
  - `language_for(file: str) -> str`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_calibration.py`:

```python
"""Calibration harness tests: real analyzers, no fakes of the measured layer."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

REACHABILITY_CORPUS = PROJECT_ROOT / "bench" / "reachability" / "corpus.json"


def test_corpus_root_key_resolves_relative_to_manifest(tmp_path: Path) -> None:
    from web3guard.bench.corpus import load_corpus, validate_corpus

    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "Vault.sol").write_text("contract Vault {}", encoding="utf-8")
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    manifest = manifests / "corpus.json"
    manifest.write_text(json.dumps({
        "name": "root-key",
        "root": "../fixtures",
        "units": [{"path": "Vault.sol", "language": "solidity",
                   "vulnerabilities": []}],
    }), encoding="utf-8")

    corpus = load_corpus(manifest)
    assert corpus.root == fixtures.resolve()
    assert (corpus.root / corpus.units[0].path).is_file()
    assert validate_corpus(manifest) == []


def test_pipeline_rejects_unreachable_keeps_inherited() -> None:
    from web3guard.bench.pipeline import make_reachability_analyzer

    root = PROJECT_ROOT / "test_contracts" / "reachability"
    kept = make_reachability_analyzer()(root)
    names = {Path(issue.file).name for issue in kept}
    assert "InheritedReentrancy.sol" in names
    assert "UnreachableReentrancy.sol" not in names


def test_pipeline_fails_open_for_unknown_language(tmp_path: Path) -> None:
    from web3guard.bench.pipeline import make_reachability_analyzer

    (tmp_path / "Thing.clar").write_text(
        "(define-public (withdraw) (ok true))", encoding="utf-8")
    kept = make_reachability_analyzer()(tmp_path)
    assert isinstance(kept, list)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_calibration.py -q`
Expected: FAIL/ERROR — `web3guard.bench.pipeline` does not exist and `root` is ignored.

- [ ] **Step 3: Add `root` support to `corpus.py`**

In `load_corpus`, replace the root resolution:

```python
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    if data.get("root"):
        root = (manifest_path.parent / str(data["root"])).resolve()
    else:
        root = manifest_path.parent if manifest_path != DEFAULT_CORPUS else REPO_ROOT
```

In `validate_corpus`, replace the root resolution:

```python
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    if data.get("root"):
        root = (manifest_path.parent / str(data["root"])).resolve()
    else:
        root = REPO_ROOT if manifest_path == DEFAULT_CORPUS else manifest_path.parent
```

- [ ] **Step 4: Create `web3guard/bench/pipeline.py`**

```python
"""Real discovery + reachability pipeline analyzer.

Used by the calibration harness to measure the reachability pre-filter
against the plain static analyzer. Both engines are the real ones; nothing
is mocked. Issues whose verdict cannot be resolved are kept (fail open),
matching the scanner's policy.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

_EXT_LANGUAGE = {
    ".sol": "solidity",
    ".vy": "vyper",
    ".vyper": "vyper",
    ".move": "move",
    ".cairo": "cairo",
    ".clar": "clarity",
    ".fc": "func",
    ".rs": "rust-solana",
    ".ts": "ts-sdk",
    ".js": "ts-sdk",
}


def language_for(file: str) -> str:
    return _EXT_LANGUAGE.get(Path(file).suffix.lower(), "")


class _FindingView:
    __slots__ = ("language", "file", "function", "line_hint", "line", "category")

    def __init__(self, language: str, file: str, function: str,
                 line: int, category: str) -> None:
        self.language = language
        self.file = file
        self.function = function
        self.line_hint = str(line or "")
        self.line = line
        self.category = category


def make_reachability_analyzer(
    *, use_slither: bool = False
) -> Callable[[Path], list[Any]]:
    """Return a real analyzer ``(root) -> kept StaticIssue list``."""

    def _analyze(root: Path) -> list[Any]:
        from web3guard.discovery.static_analyzer import StaticAnalyzerEngine
        from web3guard.reachability import ReachabilityAnalyzer, ReachabilityVerdict

        issues: Sequence[Any] = list(StaticAnalyzerEngine().run(Path(root)))
        reachability = ReachabilityAnalyzer(Path(root), use_slither=use_slither)
        kept: list[Any] = []
        for issue in issues:
            view = _FindingView(
                language_for(str(getattr(issue, "file", ""))),
                str(getattr(issue, "file", "")),
                str(getattr(issue, "function", "")),
                int(getattr(issue, "line", 0) or 0),
                str(getattr(issue, "category", "")),
            )
            try:
                verdict = reachability.classify(view).verdict
            except Exception:  # noqa: BLE001
                verdict = ReachabilityVerdict.UNKNOWN
            if verdict != ReachabilityVerdict.NOT_REACHABLE:
                kept.append(issue)
        return kept

    return _analyze
```

- [ ] **Step 5: Export from `web3guard/bench/__init__.py`**

Add after the `runner` import:

```python
from web3guard.bench.pipeline import language_for, make_reachability_analyzer
```

Add to `__all__`:

```python
    "language_for",
    "make_reachability_analyzer",
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_calibration.py -q`
Expected: PASS (3 passed).

- [ ] **Step 7: Commit**

```bash
git add web3guard/bench/corpus.py web3guard/bench/pipeline.py web3guard/bench/__init__.py tests/test_calibration.py
git commit -m "feat(bench): real reachability pipeline analyzer and corpus root key"
```

---

### Task 2: L1 calibration module, reachability corpus, and `calibrate` CLI

**Files:**
- Create: `web3guard/bench/calibration.py`
- Create: `bench/reachability/corpus.json`
- Modify: `web3guard/bench/__init__.py`
- Modify: `web3guard/cli.py:132-160,181-186,240-337`
- Test: `tests/test_calibration.py` (append)

**Interfaces:**
- Consumes: `run_benchmark`, `make_reachability_analyzer`, `load_corpus`, `default_corpus`, `BenchmarkCorpus`.
- Produces:
  - `LayerResult`, `CalibrationReport` with `to_dict()` (schema `web3guard-calibration/1`).
  - `calibrate_l1(*, main_corpus, reachability_corpus, use_slither=False) -> LayerResult`.
  - `calibrate_l2(cases, *, cases_root, workdir) -> LayerResult`.
  - `calibrate_l3(cases, *, cases_root, workdir, env=None) -> LayerResult`.

- [ ] **Step 1: Create the reachability corpus manifest**

Create `bench/reachability/corpus.json`:

```json
{
  "name": "reachability",
  "description": "Reachability pre-filter calibration. UnreachableReentrancy.sol is flagged by the static analyzer but has no external path (label set empty, so a hit is a false positive). InheritedReentrancy.sol is a real reentrancy reachable through a derived public function. SafeVault.sol is a clean control.",
  "root": "../..",
  "units": [
    {"path": "test_contracts/reachability/UnreachableReentrancy.sol", "language": "solidity", "vulnerabilities": []},
    {"path": "test_contracts/reachability/InheritedReentrancy.sol", "language": "solidity", "vulnerabilities": ["reentrancy"]},
    {"path": "test_contracts/clean/SafeVault.sol", "language": "solidity", "vulnerabilities": []}
  ]
}
```

- [ ] **Step 2: Write the failing L1 test**

Append to `tests/test_calibration.py`:

```python
def test_calibrate_l1_rejects_unreachable_and_keeps_recall() -> None:
    from web3guard.bench import default_corpus, load_corpus
    from web3guard.bench.calibration import calibrate_l1

    main = default_corpus()
    reach = load_corpus(REACHABILITY_CORPUS)
    result = calibrate_l1(main_corpus=main, reachability_corpus=reach)

    assert result.status == "measured", result.reason
    assert result.data["precision_delta"] > 0
    assert result.data["recall_delta"] == 0
    assert result.data["filtered"]["precision"] == 1.0
    rejected = {item["file"] for item in result.data["rejected"]}
    assert any("UnreachableReentrancy" in f for f in rejected)
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_calibration.py::test_calibrate_l1_rejects_unreachable_and_keeps_recall -q`
Expected: FAIL/ERROR — `web3guard.bench.calibration` does not exist.

- [ ] **Step 4: Create `web3guard/bench/calibration.py`**

```python
"""Three-layer precision/recall calibration over real components.

L1 runs the real static analyzer with and without the real reachability
pre-filter. L2 drives the real scanner + Foundry + differential over
committed golden PoCs. L3 drives the real scanner with a real provider.
No layer substitutes a fake for the component it measures.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from web3guard.bench.corpus import BenchmarkCorpus
from web3guard.bench.metrics import BenchmarkReport
from web3guard.bench.pipeline import make_reachability_analyzer
from web3guard.bench.runner import run_benchmark

_PROVIDER_KEY_ENVS = (
    "NIM_API_KEY",
    "OPENROUTER_API_KEY",
    "GROQ_API_KEY",
    "DEEPSEEK_API_KEY",
    "OPENAI_API_KEY",
)


@dataclass
class LayerResult:
    status: str = "measured"
    reason: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"status": self.status}
        if self.reason:
            out["reason"] = self.reason
        out.update(self.data)
        return out


@dataclass
class CalibrationReport:
    layers: dict[str, LayerResult]
    schema: str = "web3guard-calibration/1"

    def to_dict(self) -> dict[str, Any]:
        return {"schema": self.schema,
                **{name: layer.to_dict() for name, layer in self.layers.items()}}


def _score(report: BenchmarkReport) -> dict[str, Any]:
    o = report.overall
    return {
        "precision": round(o.precision, 4),
        "recall": round(o.recall, 4),
        "f1": round(o.f1, 4),
        "tp": o.tp,
        "fp": o.fp,
        "fn": o.fn,
        "findings": report.findings,
        "clean_hits": len(report.clean_hits),
    }


def calibrate_l1(
    *,
    main_corpus: BenchmarkCorpus,
    reachability_corpus: BenchmarkCorpus,
    use_slither: bool = False,
) -> LayerResult:
    main_static = run_benchmark(main_corpus)
    static = run_benchmark(reachability_corpus)
    filtered = run_benchmark(
        reachability_corpus,
        analyzer=make_reachability_analyzer(use_slither=use_slither),
    )
    static_fps = {(f.file, f.category) for f in static.false_positives}
    filtered_fps = {(f.file, f.category) for f in filtered.false_positives}
    rejected = sorted(static_fps - filtered_fps)
    return LayerResult(data={
        "main_static": _score(main_static),
        "static": _score(static),
        "filtered": _score(filtered),
        "precision_delta": round(
            filtered.overall.precision - static.overall.precision, 4),
        "recall_delta": round(
            filtered.overall.recall - static.overall.recall, 4),
        "rejected": [{"file": file, "category": cat} for file, cat in rejected],
    })
```

- [ ] **Step 5: Run the L1 test to verify it passes**

Run: `python3 -m pytest tests/test_calibration.py -q`
Expected: PASS.

- [ ] **Step 6: Add the `calibrate` subcommand to `cli.py`**

After the `bench` parser block (line ~155), add:

```python
    # ---- calibrate ------------------------------------------------------
    cal = sub.add_parser(
        "calibrate",
        help="Measure pipeline precision/recall across calibration layers",
    )
    cal.add_argument("--layers", default="l1",
                     help="Comma-separated layers to run (l1,l2,l3)")
    cal.add_argument("--corpus", type=Path, default=None,
                     help="Main corpus manifest (default: built-in)")
    cal.add_argument("--reachability-corpus", type=Path,
                     default=Path("bench/reachability/corpus.json"),
                     help="Reachability calibration corpus manifest")
    cal.add_argument("--cases", type=Path,
                     default=Path("bench/calibration/cases.json"),
                     help="L2 golden-case manifest")
    cal.add_argument("--live-cases", type=Path,
                     default=Path("bench/calibration/live.json"),
                     help="L3 live-case manifest")
    cal.add_argument("--json", type=Path, default=None, dest="json_out",
                     help="Write the calibration report here")
    cal.add_argument("--fail-on-regression", action="store_true",
                     help="Exit non-zero when L1 precision does not improve")
```

In `main`, after the `bench` dispatch (line ~182), add:

```python
    if args.command == "calibrate":
        return _cmd_calibrate(args)
```

After `_cmd_bench` (line ~337), add:

```python
def _cmd_calibrate(args: argparse.Namespace) -> int:
    from web3guard.bench import default_corpus, load_corpus
    from web3guard.bench.calibration import CalibrationReport

    layers = {x.strip().lower() for x in args.layers.split(",") if x.strip()}
    results: dict[str, object] = {}

    if "l1" in layers:
        from web3guard.bench.calibration import calibrate_l1

        main = load_corpus(args.corpus) if args.corpus else default_corpus()
        reach = load_corpus(args.reachability_corpus)
        results["l1"] = calibrate_l1(
            main_corpus=main, reachability_corpus=reach)

    if "l2" in layers:
        from web3guard.bench.calibration import calibrate_l2
        from web3guard.bench.cases import load_cases

        cases = load_cases(args.cases)
        results["l2"] = calibrate_l2(
            cases, cases_root=args.cases.parent,
            workdir=Path("bench/calibration/run"))

    if "l3" in layers:
        from web3guard.bench.calibration import calibrate_l3
        from web3guard.bench.cases import load_live_cases

        cases = load_live_cases(args.live_cases)
        results["l3"] = calibrate_l3(
            cases, cases_root=args.live_cases.parent,
            workdir=Path("bench/calibration/run"))

    report = CalibrationReport(layers=results)  # type: ignore[arg-type]
    print(json.dumps(report.to_dict(), indent=2))
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"\nCalibration report written to {args.json_out}")

    if args.fail_on_regression and "l1" in results:
        delta = results["l1"].data.get("precision_delta", 0.0)  # type: ignore[union-attr]
        recall_delta = results["l1"].data.get("recall_delta", 0.0)  # type: ignore[union-attr]
        if delta <= 0 or recall_delta < 0:
            print(f"\nL1 regression: precision_delta={delta} "
                  f"recall_delta={recall_delta}")
            return 1
    return 0
```

---

### Task 3: L2 runtime confirmation calibration

**Files:**
- Create: `web3guard/bench/cases.py`
- Create: `bench/calibration/cases.json`
- Create: `bench/calibration/pocs/reentrancy.t.sol`
- Create: `bench/calibration/targets/reentrancy_vuln/ReentrancyVault.sol`
- Create: `bench/calibration/targets/reentrancy_fixed/ReentrancyVault.sol`
- Create: `bench/calibration/targets/clean_vault/SafeVault.sol`
- Modify: `web3guard/bench/calibration.py`
- Modify: `web3guard/bench/__init__.py`
- Test: `tests/test_calibration.py` (append)

**Interfaces:**
- Consumes: `web3guard.scanner.Scanner`, `DEFAULT_CONFIG`; golden PoC input.
- Produces:
  - `CalibrationCase(name, target, category, language, expect_confirmed, poc="")`.
  - `load_cases(manifest) -> list[CalibrationCase]`, `load_live_cases(manifest) -> list[CalibrationCase]`.
  - `calibrate_l2(cases, *, cases_root, workdir) -> LayerResult` with a confusion matrix.

- [ ] **Step 1: Create the fixtures and golden PoC**

Create `bench/calibration/targets/reentrancy_vuln/ReentrancyVault.sol` as an exact copy of `test_contracts/vulnerable/ReentrancyVault.sol`.

Create `bench/calibration/targets/reentrancy_fixed/ReentrancyVault.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send fail");
    }

    function balanceOf(address u) external view returns (uint256) {
        return balances[u];
    }
}
```

Create `bench/calibration/targets/clean_vault/SafeVault.sol` as a copy of `test_contracts/clean/SafeVault.sol` (verify with `cat test_contracts/clean/SafeVault.sol` before copying).

Create `bench/calibration/pocs/reentrancy.t.sol` as an exact copy of the `_GOOD_POC` constant from `tests/test_exploit_e2e_foundry.py` (lines 30-85), without the Python string escaping.

Create `bench/calibration/cases.json`:

```json
{
  "name": "confirmation",
  "description": "L2 runtime confirmation calibration. A golden PoC that drains the vulnerable fixture must confirm (positive); the same PoC must fail against the fixed fixture (negative). No AI: the PoC is a fixed input, and the real scanner, sandbox, impact extractor, and differential are exercised.",
  "cases": [
    {"name": "reentrancy_positive", "target": "targets/reentrancy_vuln",
     "poc": "pocs/reentrancy.t.sol", "category": "reentrancy",
     "language": "solidity", "expect_confirmed": true},
    {"name": "reentrancy_fixed", "target": "targets/reentrancy_fixed",
     "poc": "pocs/reentrancy.t.sol", "category": "reentrancy",
     "language": "solidity", "expect_confirmed": false}
  ]
}
```

- [ ] **Step 2: Write the failing L2 test**

Append to `tests/test_calibration.py`:

```python
import shutil

import pytest

CASES = PROJECT_ROOT / "bench" / "calibration" / "cases.json"


@pytest.mark.skipif(shutil.which("forge") is None, reason="forge not installed")
def test_calibrate_l2_golden_cases(tmp_path: Path) -> None:
    from web3guard.bench.calibration import calibrate_l2
    from web3guard.bench.cases import load_cases

    cases = load_cases(CASES)
    result = calibrate_l2(cases, cases_root=CASES.parent, workdir=tmp_path)

    assert result.status == "measured", result.reason
    assert result.data["tp"] == 1
    assert result.data["tn"] == 1
    assert result.data["fp"] == 0
    assert result.data["fn"] == 0
    assert result.data["precision"] == 1.0
    assert result.data["recall"] == 1.0
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `PATH="$HOME/.foundry/bin:$PATH" python3 -m pytest tests/test_calibration.py::test_calibrate_l2_golden_cases -q`
Expected: FAIL/ERROR — `web3guard.bench.cases` does not exist.

- [ ] **Step 4: Create `web3guard/bench/cases.py`**

```python
"""Labeled calibration cases for the confirmation and live layers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CalibrationCase:
    name: str
    target: str
    category: str
    language: str
    expect_confirmed: bool
    poc: str = ""


def _load(manifest: Path | str) -> list[CalibrationCase]:
    path = Path(manifest)
    data = json.loads(path.read_text(encoding="utf-8"))
    cases: list[CalibrationCase] = []
    for raw in data.get("cases", []):
        cases.append(CalibrationCase(
            name=str(raw["name"]),
            target=str(raw["target"]),
            category=str(raw.get("category", "")),
            language=str(raw.get("language", "")),
            expect_confirmed=bool(raw.get("expect_confirmed", False)),
            poc=str(raw.get("poc", "")),
        ))
    return cases


def load_cases(manifest: Path | str) -> list[CalibrationCase]:
    return _load(manifest)


def load_live_cases(manifest: Path | str) -> list[CalibrationCase]:
    return _load(manifest)
```

- [ ] **Step 5: Add `calibrate_l2` to `calibration.py`**

Append:

```python
class _GoldenPocAI:
    """Fixed-input client: vulnerable verdict, then a committed golden PoC."""

    def __init__(self, poc: str, category: str) -> None:
        self._poc = poc
        self._category = category

    def _response(self, content: str) -> Any:
        return type("Resp", (), {"content": content})()

    def chat(self, system: str, user: str, **kwargs: Any) -> Any:
        import json

        if kwargs.get("role", "analysis") == "exploit":
            return self._response(f"```solidity\n{self._poc}\n```")
        return self._response(json.dumps({
            "status": "vulnerable",
            "category": self._category,
            "severity": "HIGH",
            "confidence": 0.9,
            "function": "withdraw",
            "description": "golden calibration case",
            "reasoning": "fixed input",
            "line_hint": "1-50",
        }))

    def cost_tracker(self) -> Any:
        return type("Tracker", (), {"summary": lambda self: {"total_cost_usd": 0.0}})()


def _confusion(cases: Sequence[Any], outcomes: Sequence[bool]) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    recorded = []
    for case, confirmed in zip(cases, outcomes):
        if case.expect_confirmed and confirmed:
            tp += 1
        elif case.expect_confirmed and not confirmed:
            fn += 1
        elif not case.expect_confirmed and confirmed:
            fp += 1
        else:
            tn += 1
        recorded.append({"name": case.name, "confirmed": confirmed,
                         "expected": case.expect_confirmed})
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4), "recall": round(recall, 4),
            "cases": recorded}


def _confirm_with_scanner(target: Path, poc: str, category: str,
                          workdir: Path) -> bool:
    from web3guard.scanner import DEFAULT_CONFIG, Scanner

    cfg = dict(DEFAULT_CONFIG)
    cfg.update({
        "enable_ai_analysis": True,
        "enable_discovery": False,
        "enable_exploit": True,
        "max_exploit_attempts": 1,
        "enable_self_critique": False,
        "enable_attack_sequence_brainstorm": False,
        "enable_role_map": False,
        "enable_secret_scan": False,
        "enable_economic_analyzer": False,
        "enable_reachability": False,
        "enable_differential": True,
    })
    case_work = workdir / target.name
    case_work.mkdir(parents=True, exist_ok=True)
    scanner = Scanner(config=cfg, workdir=case_work,
                      ai_client=_GoldenPocAI(poc, category))
    result = scanner.scan([str(target) + "|max"])
    if not result.targets:
        return False
    return any(f.status == "CONFIRMED EXPLOIT"
               for f in result.targets[0].findings)


def calibrate_l2(
    cases: Sequence[Any], *, cases_root: Path, workdir: Path
) -> LayerResult:
    if shutil.which("forge") is None:
        return LayerResult(status="not-measured", reason="forge not installed")
    outcomes: list[bool] = []
    for case in cases:
        target = (Path(cases_root) / case.target).resolve()
        poc = (Path(cases_root) / case.poc).read_text(encoding="utf-8")
        try:
            outcomes.append(_confirm_with_scanner(
                target, poc, case.category, Path(workdir)))
        except Exception:  # noqa: BLE001
            outcomes.append(False)
    return LayerResult(data=_confusion(cases, outcomes))
```

- [ ] **Step 6: Add `calibrate_l3` to `calibration.py`**

Append:

```python
def _live_skip_reason(env: dict[str, str]) -> str:
    if env.get("WEB3GUARD_LIVE_E2E") != "1":
        return "set WEB3GUARD_LIVE_E2E=1 to run the live layer"
    if not any(env.get(k) for k in _PROVIDER_KEY_ENVS):
        return "no provider API key set (one of: " + ", ".join(_PROVIDER_KEY_ENVS) + ")"
    return ""


def calibrate_l3(
    cases: Sequence[Any], *, cases_root: Path, workdir: Path,
    env: dict[str, str] | None = None,
) -> LayerResult:
    environment = dict(os.environ) if env is None else env
    reason = _live_skip_reason(environment)
    if reason:
        return LayerResult(status="not-measured", reason=reason)

    from web3guard.scanner import DEFAULT_CONFIG, Scanner

    cfg = dict(DEFAULT_CONFIG)
    cfg.update({
        "enable_ai_analysis": True,
        "enable_discovery": False,
        "enable_exploit": True,
        "max_exploit_attempts": 3,
        "max_cost_usd": 5.0,
        "enable_self_critique": False,
        "enable_attack_sequence_brainstorm": False,
        "enable_role_map": False,
        "enable_secret_scan": False,
        "enable_economic_analyzer": False,
    })
    outcomes: list[bool] = []
    for case in cases:
        target = (Path(cases_root) / case.target).resolve()
        case_work = Path(workdir) / case.name
        case_work.mkdir(parents=True, exist_ok=True)
        scanner = Scanner(config=cfg, workdir=case_work)
        try:
            result = scanner.scan([str(target) + "|max"])
            confirmed = bool(result.targets) and any(
                f.status == "CONFIRMED EXPLOIT"
                for f in result.targets[0].findings)
        except Exception:  # noqa: BLE001
            confirmed = False
        outcomes.append(confirmed)
    data = _confusion(cases, outcomes)
    data["provider_keys_present"] = sorted(
        k for k in _PROVIDER_KEY_ENVS if environment.get(k))
    return LayerResult(data=data)
```

- [ ] **Step 7: Export the new names from `web3guard/bench/__init__.py`**

Add:

```python
from web3guard.bench.calibration import (
    CalibrationReport,
    LayerResult,
    calibrate_l1,
    calibrate_l2,
    calibrate_l3,
)
from web3guard.bench.cases import CalibrationCase, load_cases, load_live_cases
```

Add to `__all__`:

```python
    "CalibrationReport",
    "LayerResult",
    "calibrate_l1",
    "calibrate_l2",
    "calibrate_l3",
    "CalibrationCase",
    "load_cases",
    "load_live_cases",
```

- [ ] **Step 8: Run the L2 test to verify it passes**

Run: `PATH="$HOME/.foundry/bin:$PATH" python3 -m pytest tests/test_calibration.py::test_calibrate_l2_golden_cases -v`
Expected: PASS (`tp=1 tn=1 fp=0 fn=0`). If the negative case confirms, verify the fixed fixture's state update precedes the external call.

- [ ] **Step 9: Commit**

```bash
git add web3guard/bench/cases.py web3guard/bench/calibration.py \
  web3guard/bench/__init__.py bench/calibration/cases.json \
  bench/calibration/pocs bench/calibration/targets tests/test_calibration.py
git commit -m "feat(calibrate): L2 runtime confirmation over golden PoCs"
```

---

### Task 4: L3 live-model calibration and CI wiring

**Files:**
- Create: `bench/calibration/live.json`
- Create: `bench/calibration/targets/reentrancy_live/ReentrancyVault.sol`
- Modify: `tests/test_calibration.py` (append)
- Modify: `.github/workflows/bounty-hunter.yml`

**Interfaces:**
- Consumes: `calibrate_l3` from Task 3.
- Produces: a real l3 run in the opt-in live CI job, and an offline `not-measured` test.

- [ ] **Step 1: Create the live manifest and target**

Create `bench/calibration/live.json`:

```json
{
  "name": "live",
  "description": "L3 online calibration with a real provider. The vulnerable target should yield CONFIRMED EXPLOIT; the clean target should not. Runs only in the opt-in live CI job.",
  "cases": [
    {"name": "live_reentrancy", "target": "targets/reentrancy_live",
     "category": "reentrancy", "language": "solidity", "expect_confirmed": true},
    {"name": "live_clean", "target": "targets/clean_vault",
     "category": "", "language": "solidity", "expect_confirmed": false}
  ]
}
```

Create `bench/calibration/targets/reentrancy_live/ReentrancyVault.sol` as an exact copy of `test_contracts/vulnerable/ReentrancyVault.sol`.

- [ ] **Step 2: Write the failing L3 test**

Append to `tests/test_calibration.py`:

```python
LIVE_CASES = PROJECT_ROOT / "bench" / "calibration" / "live.json"


def test_calibrate_l3_reports_not_measured_without_prereqs(tmp_path: Path) -> None:
    from web3guard.bench.calibration import calibrate_l3
    from web3guard.bench.cases import load_live_cases

    cases = load_live_cases(LIVE_CASES)
    result = calibrate_l3(cases, cases_root=LIVE_CASES.parent,
                          workdir=tmp_path, env={})
    assert result.status == "not-measured"
    assert result.reason
    assert result.data == {}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_calibration.py::test_calibrate_l3_reports_not_measured_without_prereqs -q`
Expected: FAIL — manifest missing or `calibrate_l3` absent (Task 3 adds it; here the manifest is what this task adds).

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_calibration.py -q`
Expected: PASS (L2 is skipped without forge on the bare PATH; L1/L3 pass).

- [ ] **Step 5: Wire L1 and L2 into CI**

In `.github/workflows/bounty-hunter.yml`:

In the `bench` job, after the "Diff in-repo benchmark vs committed baseline" step, add:

```yaml
      - name: Calibrate offline reachability (L1)
        run: |
          python -m web3guard.cli calibrate --layers l1 \
            --json bench/reachability/reports/current.json \
            --fail-on-regression
```

In `toolchain-smoke`'s run line, append `tests/test_calibration.py::test_calibrate_l2_golden_cases` to the pytest invocation.

In the `live-exploit-e2e` job, after the live pytest step, add:

```yaml
      - name: Calibrate live model (L3)
        env:
          WEB3GUARD_LIVE_E2E: "1"
          NIM_API_KEY: ${{ secrets.NIM_API_KEY }}
          OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
          GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
          DEEPSEEK_API_KEY: ${{ secrets.DEEPSEEK_API_KEY }}
        run: |
          python -m web3guard.cli calibrate --layers l3 \
            --json bench/calibration/reports/live.json
```

- [ ] **Step 6: Commit**

```bash
git add bench/calibration/live.json bench/calibration/targets/reentrancy_live \
  tests/test_calibration.py .github/workflows/bounty-hunter.yml
git commit -m "feat(calibrate): L3 live-model layer and CI wiring"
```

---

### Task 5: Full verification, push, and CI

**Files:**
- Verify only (no source changes expected).

**Interfaces:**
- Consumes: Tasks 1-4.
- Produces: green local suites, a pushed `main`, and a successful CI run.

- [ ] **Step 1: Run the full suite without forge**

Run: `python3 -m pytest -q`
Expected: all pass except forge-gated skips.

- [ ] **Step 2: Run the full suite with forge**

Run: `PATH="$HOME/.foundry/bin:$PATH" python3 -m pytest -q`
Expected: all pass, including the L2 golden-case test.

- [ ] **Step 3: Run the existing bench gate (must stay green)**

Run: `python3 -m web3guard bench --fail-below 0.99,0.95`
Expected: PASS.

- [ ] **Step 4: Run L1 calibration end to end**

Run: `python3 -m web3guard calibrate --layers l1 --fail-on-regression`
Expected: exit 0, `precision_delta` > 0.

- [ ] **Step 5: Lint the changed files**

Run: `ruff check web3guard/bench web3guard/cli.py tests/test_calibration.py`
Expected: `All checks passed!` (fix and commit if not).

- [ ] **Step 6: Push**

Run: `GIT_ASKPASS=/tmp/opencode/git-askpass.sh git -c credential.helper= push origin main`
Expected: `main -> main`.

- [ ] **Step 7: Poll CI**

Run:
```bash
GH_TOKEN="$(cat /tmp/opencode/gh_pat)" gh run list \
  --repo genesisaugustine98-web/web3guard-bounty-hunter --limit 1
```
Then: `python3 /tmp/opencode/poll_run.py <run_id> 1200`
Expected: `run completed success` for Test (3.11/3.12), Toolchain sandbox smoke, Benchmark, Devcontainer smoke.

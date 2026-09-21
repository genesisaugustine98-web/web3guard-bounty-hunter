"""Three-layer precision/recall calibration over real components.

L1 runs the real static analyzer with and without the real reachability
pre-filter. L2 drives the real scanner + Foundry + differential over
committed golden PoCs. L3 drives the real scanner with a real provider.
No layer substitutes a fake for the component it measures.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
    for case, confirmed in zip(cases, outcomes, strict=False):
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

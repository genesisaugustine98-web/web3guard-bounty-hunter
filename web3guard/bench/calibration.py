"""Three-layer precision/recall calibration over real components.

L1 runs the real static analyzer with and without the real reachability
pre-filter. L2 drives the real scanner + Foundry + differential over
committed golden PoCs. L3 drives the real scanner with a real provider.
No layer substitutes a fake for the component it measures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
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

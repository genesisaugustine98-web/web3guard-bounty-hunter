"""Benchmark harness — precision/recall/F1 over labeled corpora.

Phase-0 measurement layer: run the offline static analyzer over
ground-truth labeled fixtures and get per-language and per-category
precision/recall/F1 numbers, plus a machine-readable report. A CI gate
fails the build when numbers drop below a floor.

Usage from the CLI: ``web3guard bench`` (see ``cli.py``).
"""

from __future__ import annotations

from web3guard.bench.corpus import (
    DEFAULT_CORPUS,
    BenchmarkCorpus,
    CorpusUnit,
    default_corpus,
    load_corpus,
    validate_corpus,
)
from web3guard.bench.metrics import (
    BenchFinding,
    BenchmarkReport,
    Score,
    diff_reports,
    evaluate,
)
from web3guard.bench.runner import run_benchmark

__all__ = [
    "DEFAULT_CORPUS",
    "BenchmarkCorpus",
    "CorpusUnit",
    "BenchFinding",
    "BenchmarkReport",
    "Score",
    "default_corpus",
    "load_corpus",
    "validate_corpus",
    "evaluate",
    "diff_reports",
    "run_benchmark",
]

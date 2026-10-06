"""Runner that executes an analysis engine over a corpus.

The default engine is the built-in :class:`StaticAnalyzerEngine` (the
deterministic, offline, multi-language heuristic layer), so the benchmark
runs with zero API keys and zero installed toolchains. The same harness
is used to benchmark external corpora (e.g. ARC) once they are labeled.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

from web3guard.bench.corpus import BenchmarkCorpus
from web3guard.bench.metrics import BenchFinding, BenchmarkReport, evaluate


def run_benchmark(
    corpus: BenchmarkCorpus,
    *,
    analyzer: Callable[[Path], Sequence[object]] | None = None,
    min_severity: str = "LOW",
    exclude_categories: Sequence[str] | None = None,
) -> BenchmarkReport:
    """Run the static analyzer over every unit in ``corpus`` and score it.

    ``analyzer`` is callable taking the repo root and returning an
    iterable of discovery results (objects with ``.file``, ``.category``,
    ``.line``, ``.severity``). Defaults to the built-in static engine.

    ``exclude_categories`` drops findings in the named categories *before*
    scoring. Use it when a corpus's ground-truth taxonomy does not cover
    a detector family at all (e.g. code-hygiene SWC classes on a
    vulnerability-only corpus): such findings can never be true positives
    there, so counting them as false positives measures taxonomy mismatch,
    not detector quality. Excluded findings are still emitted by real
    scans — this only scopes the benchmark.
    """
    if analyzer is None:
        from web3guard.discovery.static_analyzer import StaticAnalyzerEngine
        analyzer = StaticAnalyzerEngine().run

    severity_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    min_rank = severity_order.get(min_severity.upper(), 0)
    excluded = {c.strip().lower() for c in (exclude_categories or ()) if c.strip()}

    results = analyzer(corpus.root)
    findings: list[BenchFinding] = []
    for r in results:
        sev = str(getattr(r, "severity", "MEDIUM")).upper()
        if severity_order.get(sev, 0) < min_rank:
            continue
        category = getattr(r, "category", "") or getattr(r, "title", "")
        if category.lower() in excluded:
            continue
        findings.append(BenchFinding(
            file=str(Path(getattr(r, "file", ""))).replace("\\", "/"),
            category=category,
            line=int(getattr(r, "line", 0) or 0),
            severity=sev,
            confidence=float(getattr(r, "confidence", 0.5) or 0.5),
        ))
    return evaluate(corpus, findings)

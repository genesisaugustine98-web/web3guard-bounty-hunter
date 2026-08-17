"""Precision / recall / F1 evaluation for a benchmark corpus.

Two different counting levels are reported:

- **Finding-level precision**: of every finding the analyzer emitted,
  what fraction is labeled as a genuine vulnerability class for that
  file. Every finding is scored (a finding whose category is not in the
  unit's label set counts as a false positive).
- **Category-level recall**: for each label in the ground truth, did the
  analyzer emit at least one finding of that category for the file?
  A missing category counts as a false negative.

Aggregates are computed overall, per language, and per category so a
regression in one language (e.g. the Move detector) is visible without
drowning in the Solidity numbers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from web3guard.bench.corpus import BenchmarkCorpus, CorpusUnit


@dataclass(frozen=True)
class BenchFinding:
    """A single finding produced against one corpus unit."""
    file: str
    category: str
    line: int = 0
    severity: str = "MEDIUM"
    confidence: float = 0.5


@dataclass
class Score:
    """Aggregate precision/recall/F1 over a set of findings.

    ``tp``/``fp``/``fn`` are plain counts. The ``weighted_*`` variants
    scale each finding's contribution by its confidence, so a flood of
    low-confidence noise moves the weighted score less than a handful of
    high-confidence hits. Recall is still category-level: each ground
    truth label contributes its *detection strength* (the highest
    confidence among matching findings, capped at 1.0) instead of 1.0.
    """
    tp: int = 0          # finding-level true positives
    fp: int = 0          # finding-level false positives
    fn: int = 0          # category-level false negatives
    positives: int = 0   # number of ground-truth labels considered
    weighted_tp: float = 0.0      # confidence-sum of true positives
    weighted_fp: float = 0.0      # confidence-sum of false positives
    weighted_fn: float = 0.0      # 1 - detection-strength, per missed label
    weighted_tp_categories: float = 0.0  # detection-strength sum over labels

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp_categories + self.fn
        return self.tp_categories / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def tp_categories(self) -> int:
        """Number of ground-truth labels with >=1 matching finding."""
        return self.positives - self.fn

    @property
    def weighted_precision(self) -> float:
        denom = self.weighted_tp + self.weighted_fp
        return self.weighted_tp / denom if denom else 0.0

    @property
    def weighted_recall(self) -> float:
        denom = self.weighted_tp_categories + self.weighted_fn
        return self.weighted_tp_categories / denom if denom else 0.0

    @property
    def weighted_f1(self) -> float:
        p, r = self.weighted_precision, self.weighted_recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass
class BenchmarkReport:
    """Full evaluation of an analyzer run against a corpus."""
    corpus_name: str
    total_units: int
    clean_units: int
    findings: int
    overall: Score = field(default_factory=Score)
    per_language: dict[str, Score] = field(default_factory=dict)
    per_category: dict[str, Score] = field(default_factory=dict)
    missed: list[tuple[str, str]] = field(default_factory=list)          # (file, category)
    false_positives: list[BenchFinding] = field(default_factory=list)    # wrong-category findings
    clean_hits: list[BenchFinding] = field(default_factory=list)         # findings on clean fixtures

    def to_dict(self) -> dict:
        return {
            "corpus": self.corpus_name,
            "units": self.total_units,
            "clean_units": self.clean_units,
            "findings": self.findings,
            "overall": {
                "precision": round(self.overall.precision, 4),
                "recall": round(self.overall.recall, 4),
                "f1": round(self.overall.f1, 4),
                "weighted_precision": round(self.overall.weighted_precision, 4),
                "weighted_recall": round(self.overall.weighted_recall, 4),
                "weighted_f1": round(self.overall.weighted_f1, 4),
                "tp": self.overall.tp,
                "fp": self.overall.fp,
                "fn": self.overall.fn,
                "tp_categories": self.overall.tp_categories,
            },
            "per_language": {
                k: {
                    "precision": round(v.precision, 4),
                    "recall": round(v.recall, 4),
                    "f1": round(v.f1, 4),
                    "weighted_precision": round(v.weighted_precision, 4),
                    "weighted_recall": round(v.weighted_recall, 4),
                    "weighted_f1": round(v.weighted_f1, 4),
                    "tp": v.tp,
                    "fp": v.fp,
                    "fn": v.fn,
                }
                for k, v in sorted(self.per_language.items())
            },
            "per_category": {
                k: {
                    "precision": round(v.precision, 4),
                    "recall": round(v.recall, 4),
                    "f1": round(v.f1, 4),
                    "weighted_precision": round(v.weighted_precision, 4),
                    "weighted_recall": round(v.weighted_recall, 4),
                    "weighted_f1": round(v.weighted_f1, 4),
                    "tp": v.tp,
                    "fp": v.fp,
                    "fn": v.fn,
                }
                for k, v in sorted(self.per_category.items())
            },
            "missed_categories": [{"file": f, "category": c} for f, c in sorted(self.missed)],
            "false_positives": [
                {"file": f.file, "category": f.category, "line": f.line}
                for f in sorted(self.false_positives, key=lambda x: (x.file, x.line))
            ],
            "clean_hits": [
                {"file": f.file, "category": f.category, "line": f.line}
                for f in sorted(self.clean_hits, key=lambda x: (x.file, x.line))
            ],
        }


def evaluate(corpus: BenchmarkCorpus, findings: list[BenchFinding]) -> BenchmarkReport:
    """Score ``findings`` (one per analyzer hit) against the corpus labels."""
    by_unit: dict[str, list[BenchFinding]] = {}
    for f in findings:
        by_unit.setdefault(f.file, []).append(f)

    overall = Score()
    per_language: dict[str, Score] = {}
    per_category: dict[str, Score] = {}
    missed: list[tuple[str, str]] = []
    false_positives: list[BenchFinding] = []
    clean_hits: list[BenchFinding] = []

    for unit in corpus.units:
        rel = Path(unit.path).as_posix()
        unit_findings = by_unit.get(rel, [])
        labels = set(unit.vulnerabilities)
        unit_score = Score()

        if unit.is_clean:
            if unit_findings:
                clean_hits.extend(unit_findings)

        # Finding-level true/false positives, plus confidence weighting.
        detected_categories: set[str] = set()
        strength: dict[str, float] = {}  # max finding confidence per category
        for finding in unit_findings:
            if finding.category in labels:
                overall.tp += 1
                unit_score.tp += 1
                overall.weighted_tp += finding.confidence
                unit_score.weighted_tp += finding.confidence
                detected_categories.add(finding.category)
                strength[finding.category] = max(
                    strength.get(finding.category, 0.0), finding.confidence)
            else:
                overall.fp += 1
                unit_score.fp += 1
                overall.weighted_fp += finding.confidence
                unit_score.weighted_fp += finding.confidence
                false_positives.append(finding)

        # Category-level false negatives (count + detection strength).
        overall.positives += len(labels)
        unit_score.positives += len(labels)
        for label in sorted(labels):
            if label not in detected_categories:
                overall.fn += 1
                unit_score.fn += 1
                missed.append((rel, label))
            s = strength.get(label, 0.0)
            overall.weighted_tp_categories += s
            unit_score.weighted_tp_categories += s
            overall.weighted_fn += 1.0 - s
            unit_score.weighted_fn += 1.0 - s

        if unit_findings or labels:
            score = per_language.setdefault(unit.language or "unknown", Score())
            for attr in ("tp", "fp", "fn", "positives", "weighted_tp",
                         "weighted_fp", "weighted_fn", "weighted_tp_categories"):
                setattr(score, attr, getattr(score, attr) + getattr(unit_score, attr))

        for label in labels:
            cat_score = per_category.setdefault(label, Score())
            cat_score.positives += 1
            s = strength.get(label, 0.0)
            cat_score.weighted_tp_categories += s
            cat_score.weighted_fn += 1.0 - s
            if label in detected_categories:
                cat_score.tp += 1
            else:
                cat_score.fn += 1
        for finding in unit_findings:
            cat_score = per_category.setdefault(finding.category, Score())
            if finding.category in labels:
                cat_score.tp += 1
                cat_score.weighted_tp += finding.confidence
            else:
                cat_score.fp += 1
                cat_score.weighted_fp += finding.confidence

    return BenchmarkReport(
        corpus_name=corpus.name,
        total_units=len(corpus.units),
        clean_units=sum(1 for u in corpus.units if u.is_clean),
        findings=len(findings),
        overall=overall,
        per_language=per_language,
        per_category=per_category,
        missed=missed,
        false_positives=false_positives,
        clean_hits=clean_hits,
    )


def diff_reports(baseline: dict, current: dict, *,
                 epsilon: float = 1e-6) -> dict:
    """Compare two ``to_dict()`` reports and flag regressions.

    ``baseline`` is the previously-shipped report, ``current`` the one
    just produced. A regression is a drop in any headline metric
    (precision, recall, F1, weighted F1) below ``epsilon``, or a finding
    whose category is new on the current run. Returns a machine-readable
    diff suitable for CI display and gating.
    """
    b, c = baseline.get("overall", {}), current.get("overall", {})
    metrics = ("precision", "recall", "f1",
               "weighted_precision", "weighted_recall", "weighted_f1")
    deltas = {
        f"{m}_delta": round(c.get(m, 0.0) - b.get(m, 0.0), 4)
        for m in metrics
    }

    b_fp = set(map(_fp_key, baseline.get("false_positives", [])))
    c_fp = set(map(_fp_key, current.get("false_positives", [])))

    def _fp_list(items: set[str]) -> list[dict]:
        out: list[dict] = []
        for key in sorted(items):
            file, cat, line = key.split("\x00")
            out.append({"file": file, "category": cat, "line": int(line)})
        return out

    regressed = any(d < -epsilon for d in deltas.values()) or \
        bool(c_fp - b_fp)
    return {
        "corpus": current.get("corpus", baseline.get("corpus", "")),
        "regressed": regressed,
        **deltas,
        "new_false_positives": _fp_list(c_fp - b_fp),
        "resolved_false_positives": _fp_list(b_fp - c_fp),
        "new_missed_categories": sorted(
            set(map(tuple, current.get("missed_categories", []))) -
            set(map(tuple, baseline.get("missed_categories", [])))
        ),
    }


def _fp_key(fp: dict) -> str:
    return f"{fp.get('file', '')}\x00{fp.get('category', '')}\x00" \
           f"{fp.get('line', 0)}"

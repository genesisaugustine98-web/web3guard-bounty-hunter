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


@dataclass
class Score:
    """Aggregate precision/recall/F1 over a set of findings."""
    tp: int = 0          # finding-level true positives
    fp: int = 0          # finding-level false positives
    fn: int = 0          # category-level false negatives
    positives: int = 0   # number of ground-truth labels considered

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

        # Finding-level true/false positives.
        detected_categories: set[str] = set()
        for finding in unit_findings:
            if finding.category in labels:
                overall.tp += 1
                unit_score.tp += 1
                detected_categories.add(finding.category)
            else:
                overall.fp += 1
                unit_score.fp += 1
                false_positives.append(finding)

        # Category-level false negatives.
        overall.positives += len(labels)
        unit_score.positives += len(labels)
        for label in sorted(labels):
            if label not in detected_categories:
                overall.fn += 1
                unit_score.fn += 1
                missed.append((rel, label))

        if unit_findings or labels:
            score = per_language.setdefault(unit.language or "unknown", Score())
            for attr in ("tp", "fp", "fn", "positives"):
                setattr(score, attr, getattr(score, attr) + getattr(unit_score, attr))

        for label in labels:
            cat_score = per_category.setdefault(label, Score())
            cat_score.positives += 1
            if label in detected_categories:
                cat_score.tp += 1
            else:
                cat_score.fn += 1
        for finding in unit_findings:
            cat_score = per_category.setdefault(finding.category, Score())
            if finding.category in labels:
                cat_score.tp += 1
            else:
                cat_score.fp += 1

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

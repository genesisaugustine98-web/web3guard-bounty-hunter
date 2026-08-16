"""Benchmark corpus loading.

A corpus is a JSON manifest describing ground-truth labeled fixtures.
Each unit has a path (relative to the corpus root), a language, and the
set of vulnerability classes it is *designed* to contain. Clean fixtures
have an empty label set.

The in-repo corpus is ``web3guard/bench/corpus.json`` (the
``test_contracts/`` fixtures). External corpora (e.g. the Trail of Bits
ARC dataset) can be loaded with the same schema so precision/recall can
be measured on independent, published data rather than only on our own
fixtures.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS = Path(__file__).with_name("corpus.json")


@dataclass(frozen=True)
class CorpusUnit:
    """One labeled fixture in a benchmark corpus."""
    path: str
    language: str
    vulnerabilities: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_clean(self) -> bool:
        return not self.vulnerabilities


@dataclass(frozen=True)
class BenchmarkCorpus:
    """A set of ground-truth units plus the filesystem root they live in."""
    name: str
    description: str
    root: Path
    units: tuple[CorpusUnit, ...]

    def unit_for(self, rel_path: str) -> CorpusUnit | None:
        norm = Path(rel_path).as_posix()
        for unit in self.units:
            if Path(unit.path).as_posix() == norm:
                return unit
        return None


def load_corpus(manifest: Path | str | None = None) -> BenchmarkCorpus:
    """Load a corpus from a JSON manifest file.

    ``manifest`` defaults to the in-repo ``corpus.json``. Paths inside
    the manifest are resolved relative to the repository root (or, for
    external corpora, relative to the manifest's own directory).
    """
    manifest_path = Path(manifest or DEFAULT_CORPUS)
    if not manifest_path.is_absolute():
        manifest_path = REPO_ROOT / manifest_path
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    root = manifest_path.parent if manifest_path != DEFAULT_CORPUS else REPO_ROOT
    units = tuple(
        CorpusUnit(
            path=str(u["path"]),
            language=str(u.get("language", "")),
            vulnerabilities=tuple(u.get("vulnerabilities", [])),
        )
        for u in data.get("units", [])
    )
    return BenchmarkCorpus(
        name=data.get("name", manifest_path.stem),
        description=data.get("description", ""),
        root=root,
        units=units,
    )


def default_corpus() -> BenchmarkCorpus:
    """Load the in-repo test-contracts corpus."""
    return load_corpus(DEFAULT_CORPUS)

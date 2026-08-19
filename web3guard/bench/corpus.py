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


def validate_corpus(manifest: Path | str) -> list[str]:
    """Validate a corpus manifest and return a list of human-readable errors.

    Checks that keep ground truth honest and the benchmark measurable:

    - every ``units[].path`` resolves to a real file under the corpus root,
    - every ``units[].language`` is non-empty,
    - every vulnerability label is in :data:`VALID_CATEGORIES`,
    - no path is listed twice.

    An empty list means the manifest is well-formed. This is the gate an
    externally-vendored corpus (e.g. the Trail of Bits ARC dataset) must
    pass before it is benchmarked.
    """
    errors: list[str] = []
    manifest_path = Path(manifest)
    if not manifest_path.is_absolute():
        manifest_path = REPO_ROOT / manifest_path
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    root = REPO_ROOT if manifest_path == DEFAULT_CORPUS else manifest_path.parent

    from web3guard.bench.metrics import VALID_CATEGORIES

    seen: set[str] = set()
    for i, unit in enumerate(data.get("units", [])):
        path = str(unit.get("path", ""))
        if not path:
            errors.append(f"unit[{i}]: missing 'path'")
            continue
        if path in seen:
            errors.append(f"unit[{i}]: duplicate path {path!r}")
        seen.add(path)
        if not (root / path).is_file():
            errors.append(f"unit[{i}]: file not found: {path!r}")
        lang = str(unit.get("language", ""))
        if not lang:
            errors.append(f"unit[{i}]: missing 'language' for {path!r}")
        for label in unit.get("vulnerabilities", []):
            if label not in VALID_CATEGORIES:
                errors.append(
                    f"unit[{i}]: unknown vulnerability label {label!r} "
                    f"in {path!r} (valid: "
                    f"{', '.join(sorted(VALID_CATEGORIES))})")
    return errors

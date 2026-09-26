"""Dependency-graph incremental analysis.

A scan's unit of change is the file; the unit of cost is the LLM chunk.
The analyzer bridges them:

1. Walk the target's source files, hash contents (SHA-256).
2. Parse import/include edges with per-language regexes (cheap, no
   compiler required; unresolved imports are deliberately dropped —
   forcing global invalidation on every unresolved path would erase
   the savings).
3. Diff against the previous run's graph (persisted in state_kv via the
   durable store), mark changed files dirty.
4. Propagate dirtiness transitively over *reverse* import edges: a
   changed interface can change every caller. This is the correctness
   half of incremental scanning.
5. Emit the set of files needing re-analysis; the scanner skips chunks
   from clean files entirely.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger("web3guard.graph")

# Extensions that carry source for the supported language families.
_SOURCE_EXTS = {
    ".sol", ".vy", ".move", ".cairo", ".clar", ".fc", ".rs", ".ts", ".js",
    ".huff", ".yul", ".scilla", ".tz", ".go",
}

# --- import edge patterns per family ---------------------------------------

_IMPORT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("solidity", re.compile(
        r"^\s*import\s+(?:\{[^}]*\}\s*from\s+)?[\"']([^\"']+)[\"']", re.M)),
    ("move", re.compile(r"^\s*use\s+([\w:]+)", re.M)),
    ("cairo", re.compile(r"^\s*use\s+([\w:]+)", re.M)),
    ("clarity", re.compile(r"\((?:impl-trait|use-trait)\s+([\w.\-!]+)")),
    ("func", re.compile(r"#include\s+\"([^\"]+)\"")),
    ("rust", re.compile(r"^\s*use\s+([\w:]+)", re.M)),
    ("ts-sdk", re.compile(
        r"^\s*import\s+(?:[\w*{}\s,]+\s*from\s+)?[\"']([^\"']+)[\"']", re.M)),
    ("go", re.compile(r"^\s*import\s+(?:\w+\s+)?\"([^\"]+)\"", re.M)),
)


def hash_content(content: str) -> str:
    """SHA-256 of file content (first 24 hex chars)."""
    return hashlib.sha256(
        content.encode("utf-8", errors="ignore")).hexdigest()[:24]


class DependencyGraph:
    """Content-addressed file graph with reverse import edges."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}   # rel_path -> {hash, size, mtime}
        self.edges: dict[str, set[str]] = {}         # rel_path -> imported rel_paths
        self.reverse: dict[str, set[str]] = {}       # rel_path -> importers

    def add_node(self, rel_path: str, content_hash: str, size: int = 0,
                 mtime: float = 0.0) -> None:
        self.nodes[rel_path] = {
            "hash": content_hash, "size": size, "mtime": mtime}

    def add_edge(self, src: str, dst: str) -> None:
        if src == dst:
            return
        self.edges.setdefault(src, set()).add(dst)
        self.reverse.setdefault(dst, set()).add(src)

    def importers_of(self, rel_path: str) -> set[str]:
        return set(self.reverse.get(rel_path, set()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "nodes": self.nodes,
            "edges": {k: sorted(v) for k, v in self.edges.items()},
            "built_ts": time.time(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DependencyGraph:
        g = cls()
        g.nodes = {k: dict(v) for k, v in (data.get("nodes") or {}).items()}
        g.edges = {k: set(v) for k, v in (data.get("edges") or {}).items()}
        g.reverse = {}
        for src, dsts in g.edges.items():
            for dst in dsts:
                g.reverse.setdefault(dst, set()).add(src)
        return g

    def stats(self) -> dict[str, int]:
        return {
            "files": len(self.nodes),
            "edges": sum(len(v) for v in self.edges.values()),
        }


class IncrementalAnalyzer:
    """Compute the minimal re-analysis set across runs."""

    _PROPAGATE_STEP_LIMIT = 100_000  # cycle guard

    def __init__(self, *, store: Any = None) -> None:  # DurableStore
        self._store = store
        self._graph: DependencyGraph | None = None

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def build_graph(self, target_path: Path,
                    files: list[Path]) -> DependencyGraph:
        """Build the content graph for ``files`` under ``target_path``."""
        g = DependencyGraph()
        rel_by_stem: dict[str, str] = {}
        contents: dict[str, str] = {}
        for fp in files:
            try:
                rel = str(fp.relative_to(target_path)).replace("\\", "/")
                content = fp.read_text(errors="ignore")
            except (ValueError, OSError):
                continue
            h = hash_content(content)
            try:
                mtime = fp.stat().st_mtime
            except OSError:
                mtime = 0.0
            g.add_node(rel, h, size=len(content), mtime=mtime)
            rel_by_stem.setdefault(Path(rel).stem, rel)
            contents[rel] = content
        for rel, content in contents.items():
            for _lang, pat in _IMPORT_PATTERNS:
                for m in pat.finditer(content):
                    raw = (m.group(1) or "").strip()
                    if not raw:
                        continue
                    resolved = self._resolve_import(raw, rel, rel_by_stem)
                    if resolved:
                        g.add_edge(src=rel, dst=resolved)
        self._graph = g
        return g

    def _resolve_import(self, raw: str, src_rel: str,
                        rel_by_stem: dict[str, str]) -> str | None:
        """Best-effort import resolution to a known file."""
        raw = raw.strip().strip("'\"")
        if not raw:
            return None
        if raw.startswith("."):
            base = Path(src_rel).parent
            candidate = Path(str(base / raw)).as_posix()
            while candidate.startswith("../"):
                candidate = candidate[3:]
            candidate = candidate.lstrip("/")
            if candidate in rel_by_stem.values():
                return candidate
            if Path(candidate).stem in rel_by_stem:
                return rel_by_stem[Path(candidate).stem]
            return None
        stem = Path(raw.replace(":", "/")).stem
        return rel_by_stem.get(stem)

    # ------------------------------------------------------------------
    # Dirty computation + persistence
    # ------------------------------------------------------------------

    def compute_dirty(self, target_path: Path, files: list[Path],
                      *, target: str) -> dict[str, Any]:
        """Diff the fresh graph against the previous run's and propagate.

        Returns ``{"files": [...], "clean": n, "dirty": n,
        "changed": [...], "first_scan": bool}`` where ``files`` lists
        relative paths that need re-analysis.
        """
        g = self.build_graph(target_path, files)
        prev = self._load_graph(target)
        dirty: set[str] = set()
        changed: list[str] = []
        first_scan = prev is None or not prev.nodes
        if first_scan:
            dirty = set(g.nodes)
        else:
            assert prev is not None  # narrows Optional for type checkers
            for rel, node in g.nodes.items():
                prev_hash = (prev.nodes.get(rel) or {}).get("hash")
                if prev_hash is None or prev_hash != node["hash"]:
                    dirty.add(rel)
                    changed.append(rel)
            dirty = self._propagate(g, dirty)
        self._save_graph(target, g)
        return {
            "files": sorted(dirty),
            "clean": max(0, len(g.nodes) - len(dirty)),
            "dirty": len(dirty),
            "changed": changed,
            "first_scan": first_scan,
        }

    def _propagate(self, g: DependencyGraph, dirty: set[str]) -> set[str]:
        """Mark importers of dirty files dirty, transitively."""
        seen = set(dirty)
        queue = list(dirty)
        steps = 0
        while queue and steps < self._PROPAGATE_STEP_LIMIT:
            steps += 1
            cur = queue.pop()
            for imp in g.importers_of(cur):
                if imp not in seen:
                    seen.add(imp)
                    queue.append(imp)
        if steps >= self._PROPAGATE_STEP_LIMIT:  # pragma: no cover
            LOGGER.warning("dirty propagation hit the step limit")
        return seen

    def _load_graph(self, target: str) -> DependencyGraph | None:
        if self._store is None:
            return None
        try:
            rows = self._store.local.query_all(
                "SELECT v FROM state_kv WHERE k = ?", (self._key(target),))
            if not rows:
                return None
            data = json.loads(rows[0]["v"])
            return DependencyGraph.from_dict(data)
        except (ValueError, TypeError, KeyError):
            return None

    def _save_graph(self, target: str, g: DependencyGraph) -> None:
        if self._store is None:
            return
        try:
            self._store.write("state_kv", "k", {
                "k": self._key(target),
                "v": json.dumps(g.to_dict(), default=str),
                "updated_ts": time.time(),
            })
        except Exception:  # noqa: BLE001
            LOGGER.debug("graph save failed", exc_info=True)

    def _key(self, target: str) -> str:
        return f"graph:{hashlib.sha256(target.encode()).hexdigest()[:24]}"

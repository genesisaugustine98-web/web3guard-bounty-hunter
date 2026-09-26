"""Adaptive scan planning.

v3.5: the static research plan (``_plan_target``) scores files once by
structure and never learns. This planner sits on top of it and adapts
with signals the old planner ignored:

1. **Budget** — the :class:`~web3guard.ai.budget.BudgetController`'s
   current state (ok / warning / exhausted) reshapes the plan: under
   pressure the plan keeps only the high-risk head of the queue.
2. **Memory** — the :class:`~web3guard.memory.SecurityMemory` target
   profile biases chunk priority toward the categories this target's
   program historically ships (e.g. a DEX that produced two oracle
   findings gets oracle chunks promoted).
3. **Incremental** — the dependency graph's dirty set restricts the
   plan to files that actually changed plus their importers.

Output is a plain dict (``plan.to_dict()``) so it serializes into
``TargetResult.research_plan`` and reports without new plumbing.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger("web3guard.planning")

# How much of the ordered queue to keep at each budget state.
_KEEP_FRACS = {"ok": 1.0, "warning": 0.6, "exhausted": 0.25}

# Confidence bump for chunks in categories this target historically
# produced verified findings in.
_MEMORY_BOOST = 2.5


@dataclass
class AdaptivePlan:
    """The per-target analysis plan."""
    files: list[dict[str, Any]] = field(default_factory=list)   # ordered queue
    chunk_budget: int = 0
    skipped_chunks: int = 0
    degraded: bool = False
    memory_boosted: int = 0
    incremental: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "files": self.files,
            "chunk_budget": self.chunk_budget,
            "skipped_chunks": self.skipped_chunks,
            "degraded": self.degraded,
            "memory_boosted": self.memory_boosted,
            "incremental": self.incremental,
            "notes": self.notes,
        }


class AdaptivePlanner:
    """Compose static risk, memory priors, incremental state, budget."""

    def __init__(
        self,
        *,
        budget: Any = None,        # BudgetController
        memory: Any = None,        # SecurityMemory
    ) -> None:
        self._budget = budget
        self._memory = memory

    def plan(
        self,
        *,
        target: str,
        static_plan: dict[str, Any],
        chunks: list[Any],
        dirty_files: set[str] | None = None,
        first_scan: bool = True,
    ) -> AdaptivePlan:
        """Build the analysis queue from the static plan + live signals.

        ``chunks`` are the adapter's chunk objects (need ``.file``);
        ``dirty_files`` is the incremental analyzer's re-analysis set
        (relative paths, or ``None`` to disable incremental filtering).
        """
        plan = AdaptivePlan()
        risk_map: dict[str, float] = {}
        for entries in (static_plan.get("files") or {}).values():
            for entry in entries:
                risk_map[entry.get("file", "")] = float(entry.get("risk", 0.0))

        # Memory priors: categories this target historically shipped
        # (any remembered verdict means the category is real for it).
        prior_categories: set[str] = set()
        if self._memory is not None and target:
            try:
                profile = self._memory.target_profile(target)
                categories = profile.get("categories") or {}
                # A remembered category only counts when it produced a
                # confirmed verdict at least once.
                confirmed_cats = {
                    row.get("category", "").lower()
                    for row in self._memory.confirmed_categories(target)
                }
                prior_categories = {
                    str(cat).lower() for cat in categories
                    if str(cat).lower() in confirmed_cats
                }
            except Exception:  # noqa: BLE001
                LOGGER.debug("memory profile unavailable", exc_info=True)

        # Chunk-level scoring: static file risk + memory prior boost.
        scored: list[tuple[float, Any]] = []
        for ch in chunks:
            rel = _chunk_rel(ch)
            risk = risk_map.get(rel, 0.0)
            if dirty_files is not None and rel not in dirty_files:
                plan.skipped_chunks += 1
                continue
            boost = _MEMORY_BOOST if _chunk_category(ch) in prior_categories else 0.0
            if boost:
                plan.memory_boosted += 1
            scored.append((risk + boost, ch))
        # Deterministic order: score desc, then file, then chunk index.
        scored.sort(key=lambda t: (-t[0], _chunk_rel(t[1]),
                                   int(getattr(t[1], "index", 0) or 0)))

        # Budget shaping: keep the high-risk head of the queue.
        state = "ok"
        if self._budget is not None:
            try:
                state = self._budget.check().state
            except Exception:  # noqa: BLE001
                state = "ok"
        keep = _KEEP_FRACS.get(state, 1.0)
        if keep < 1.0 and scored:
            plan.degraded = True
            plan.notes.append(
                f"budget {state}: keeping top {keep:.0%} of the analysis queue")
        cut = int(len(scored) * (1.0 - keep))
        plan.skipped_chunks += cut
        kept = scored[: len(scored) - cut] if cut else scored
        plan.files = [
            {"file": _chunk_rel(ch), "risk": round(risk, 2)}
            for risk, ch in kept
        ]
        plan.chunk_budget = len(kept)
        plan.incremental = dirty_files is not None
        if plan.incremental:
            plan.notes.append(
                f"incremental: {plan.skipped_chunks} chunk(s) skipped "
                "(unchanged files outside the dirty set)")
        if plan.memory_boosted:
            plan.notes.append(
                f"memory: {plan.memory_boosted} chunk(s) boosted — categories "
                "this target previously shipped")
        return plan


def _chunk_rel(chunk: Any) -> str:
    """Relative file id of a chunk (best-effort)."""
    fp = getattr(chunk, "file", "")
    try:
        return Path(str(fp)).as_posix()
    except (TypeError, ValueError):
        return str(fp or "")


def _chunk_category(chunk: Any) -> str:
    """A chunk's hinted category, if the adapter provides one."""
    return str(getattr(chunk, "category", "") or "").lower()

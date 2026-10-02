"""Audit history + version comparison.

Phase 4 of the "hunt bigger fish" build: this is the "hunt OLD projects
too" requirement. It answers one question per historical audit finding:

    *Was this actually fixed, was it band-aided, is it still open, or did
    it come back?*

Modules:

- :mod:`web3guard.history.diff` — structured diffs between git refs.
- :mod:`web3guard.history.normalize` — rename-resistant canonicalization
  so renames, reformatting, and moved blocks don't fool comparisons
  (statement order is preserved: it can be security-relevant).
- :mod:`web3guard.history.xref` — cross-file reference map (imports,
  inheritance, calls) so a finding's code is located wherever it
  actually lives in each version.
- :mod:`web3guard.history.verdicts` — per-version FIXED/BAND-AID/
  STILL OPEN/REGRESSED verdicts (heuristic, confidence-tagged,
  property-driven).
- :mod:`web3guard.history.redive` — persistent re-dive queue with
  explicit resolved states.
- :mod:`web3guard.history.report` — per-version summaries (JSON + plain
  English).

All verdicts in this package are **heuristic** — they carry a confidence
level and the evidence used. Nothing here claims certainty it doesn't
have.
"""

from __future__ import annotations

from web3guard.history.diff import VersionDiff, diff_refs
from web3guard.history.ingest import AuditFinding, AuditReport, parse_report
from web3guard.history.normalize import canonicalize_function, is_rename
from web3guard.history.redive import (
    RESOLVED_ACCEPTED_RISK,
    RESOLVED_FIXED,
    RESOLVED_STILL_OPEN,
    RediveItem,
    RediveQueue,
    suggest_adjacent,
)
from web3guard.history.report import render_text, summarize_verdicts
from web3guard.history.verdicts import VersionVerdict, walk_versions
from web3guard.history.xref import XRefMap, build_xref

__all__ = [
    "AuditFinding",
    "AuditReport",
    "RESOLVED_ACCEPTED_RISK",
    "RESOLVED_FIXED",
    "RESOLVED_STILL_OPEN",
    "RediveItem",
    "RediveQueue",
    "VersionDiff",
    "VersionVerdict",
    "XRefMap",
    "build_xref",
    "canonicalize_function",
    "diff_refs",
    "is_rename",
    "parse_report",
    "render_text",
    "suggest_adjacent",
    "summarize_verdicts",
    "walk_versions",
]

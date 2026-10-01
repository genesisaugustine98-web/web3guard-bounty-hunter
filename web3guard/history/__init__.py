"""Audit history + version comparison.

Phase 4 of the "hunt bigger fish" build: this is the "hunt OLD projects
too" requirement. It answers one question per historical audit finding:

    *Was this actually fixed, was it band-aided, is it still open, or did
    it come back?*

Modules:

- :mod:`web3guard.history.ingest` — parse audit reports (md/txt/pdf).
- :mod:`web3guard.history.diff` — structured diffs between git refs.
- :mod:`web3guard.history.verdicts` — per-version FIXED/BAND-AID/
  STILL OPEN/REGRESSED verdicts (heuristic, confidence-tagged).
- :mod:`web3guard.history.redive` — persistent re-dive queue.
- :mod:`web3guard.history.report` — per-version summaries (JSON + plain
  English).

All verdicts in this package are **heuristic** — they carry a confidence
level and the evidence used. Nothing here claims certainty it doesn't
have.
"""

from __future__ import annotations

from web3guard.history.diff import VersionDiff, diff_refs
from web3guard.history.ingest import AuditFinding, AuditReport, parse_report
from web3guard.history.redive import RediveItem, RediveQueue
from web3guard.history.report import render_text, summarize_verdicts
from web3guard.history.verdicts import VersionVerdict, walk_versions

__all__ = [
    "AuditFinding",
    "AuditReport",
    "RediveItem",
    "RediveQueue",
    "VersionDiff",
    "VersionVerdict",
    "diff_refs",
    "parse_report",
    "render_text",
    "summarize_verdicts",
    "walk_versions",
]

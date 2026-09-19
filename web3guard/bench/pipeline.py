"""Real discovery + reachability pipeline analyzer.

Used by the calibration harness to measure the reachability pre-filter
against the plain static analyzer. Both engines are the real ones; nothing
is mocked. Issues whose verdict cannot be resolved are kept (fail open),
matching the scanner's policy.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

_EXT_LANGUAGE = {
    ".sol": "solidity",
    ".vy": "vyper",
    ".vyper": "vyper",
    ".move": "move",
    ".cairo": "cairo",
    ".clar": "clarity",
    ".fc": "func",
    ".rs": "rust-solana",
    ".ts": "ts-sdk",
    ".js": "ts-sdk",
}


def language_for(file: str) -> str:
    return _EXT_LANGUAGE.get(Path(file).suffix.lower(), "")


class _FindingView:
    __slots__ = ("language", "file", "function", "line_hint", "line", "category")

    def __init__(self, language: str, file: str, function: str,
                 line: int, category: str) -> None:
        self.language = language
        self.file = file
        self.function = function
        self.line_hint = str(line or "")
        self.line = line
        self.category = category


def make_reachability_analyzer(
    *, use_slither: bool = False
) -> Callable[[Path], list[Any]]:
    """Return a real analyzer ``(root) -> kept StaticIssue list``."""

    def _analyze(root: Path) -> list[Any]:
        from web3guard.discovery.static_analyzer import StaticAnalyzerEngine
        from web3guard.reachability import ReachabilityAnalyzer, ReachabilityVerdict

        issues: Sequence[Any] = list(StaticAnalyzerEngine().run(Path(root)))
        reachability = ReachabilityAnalyzer(Path(root), use_slither=use_slither)
        kept: list[Any] = []
        for issue in issues:
            view = _FindingView(
                language_for(str(getattr(issue, "file", ""))),
                str(getattr(issue, "file", "")),
                str(getattr(issue, "function", "")),
                int(getattr(issue, "line", 0) or 0),
                str(getattr(issue, "category", "")),
            )
            try:
                verdict = reachability.classify(view).verdict
            except Exception:  # noqa: BLE001
                verdict = ReachabilityVerdict.UNKNOWN
            if verdict != ReachabilityVerdict.NOT_REACHABLE:
                kept.append(issue)
        return kept

    return _analyze

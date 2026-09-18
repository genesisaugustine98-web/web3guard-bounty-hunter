"""Route findings to the right reachability backend."""

from __future__ import annotations

import re
from pathlib import Path

from web3guard.reachability.solidity import resolve_solidity
from web3guard.reachability.types import ReachabilityEvidence, ReachabilityVerdict
from web3guard.reachability.visibility import resolve_visibility

_VISIBILITY_LANGS = {"vyper", "move", "cairo", "clarity"}


def _first_line(hint: str) -> int:
    m = re.search(r"\d+", hint or "")
    return int(m.group()) if m else 0


class ReachabilityAnalyzer:
    def __init__(
        self,
        target_path: Path,
        *,
        use_slither: bool = False,
        slither_backend: object | None = None,
    ) -> None:
        self._target = Path(target_path)
        self._use_slither = use_slither
        self._slither = slither_backend
        self._index = None
        self._index_failed = False

    def classify(self, finding: object) -> ReachabilityEvidence:
        language = str(getattr(finding, "language", "") or "").lower()
        try:
            if language == "solidity":
                return self._classify_solidity(finding)
            if language in _VISIBILITY_LANGS:
                return self._classify_visibility(language, finding)
        except Exception:  # noqa: BLE001
            pass
        return ReachabilityEvidence(
            ReachabilityVerdict.UNKNOWN, "analyzer",
            detail=f"no reachability backend for {language or 'unknown'}",
        )

    def _get_index(self):  # noqa: ANN202
        if self._index is None and not self._index_failed:
            try:
                from web3guard.reachability.solidity_index import FunctionIndex

                self._index = FunctionIndex.build(self._target)
            except Exception:  # noqa: BLE001
                self._index_failed = True
        return self._index

    def _get_slither(self):  # noqa: ANN202
        if self._slither is not None:
            return self._slither
        if not self._use_slither:
            return None
        from web3guard.reachability.slither_backend import SlitherBackend

        self._slither = SlitherBackend(self._target)
        return self._slither

    def _classify_solidity(self, finding: object) -> ReachabilityEvidence:
        index = self._get_index()
        if index is None:
            return ReachabilityEvidence(
                ReachabilityVerdict.UNKNOWN, "solidity-parser",
                detail="function index build failed",
            )
        fn = index.enclosing(
            str(getattr(finding, "file", "") or ""),
            str(getattr(finding, "function", "") or ""),
            _first_line(str(getattr(finding, "line_hint", "") or "")),
        )
        evidence = resolve_solidity(index, fn)
        if fn is None:
            return evidence
        slither = self._get_slither()
        if slither is None:
            return evidence
        return _corroborate(evidence, slither, fn)

    def _classify_visibility(
        self, language: str, finding: object
    ) -> ReachabilityEvidence:
        source = self._read_source(str(getattr(finding, "file", "") or ""))
        if source is None:
            return ReachabilityEvidence(
                ReachabilityVerdict.UNKNOWN, "visibility",
                detail="source file not found",
            )
        return resolve_visibility(
            language, source, str(getattr(finding, "function", "") or "")
        )

    def _read_source(self, rel: str) -> str | None:
        if not rel:
            return None
        candidate = self._target / rel
        if candidate.is_file():
            try:
                return candidate.read_text(errors="ignore")
            except OSError:
                return None
        base = Path(rel).name
        for path in self._target.rglob(base):
            if path.is_file():
                try:
                    return path.read_text(errors="ignore")
                except OSError:
                    return None
        return None


def _corroborate(evidence: ReachabilityEvidence, slither: object, fn: object) -> ReachabilityEvidence:
    try:
        verdict = slither.verdict(fn)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return evidence
    if verdict is None:
        return evidence
    if verdict == ReachabilityVerdict.REACHABLE:
        return ReachabilityEvidence(
            ReachabilityVerdict.REACHABLE, "slither",
            function=evidence.function, entrypoint=evidence.entrypoint or evidence.function,
            gated=evidence.gated, detail="Slither sees an external caller",
        )
    if verdict == ReachabilityVerdict.NOT_REACHABLE \
            and evidence.verdict == ReachabilityVerdict.NOT_REACHABLE:
        return ReachabilityEvidence(
            ReachabilityVerdict.NOT_REACHABLE, "slither",
            function=evidence.function, detail="custom parser and Slither agree",
        )
    return evidence

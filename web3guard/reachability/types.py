"""Verdict and evidence types for external reachability analysis."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ReachabilityVerdict(StrEnum):
    REACHABLE = "reachable"
    NOT_REACHABLE = "not_reachable"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ReachabilityEvidence:
    verdict: ReachabilityVerdict
    backend: str
    function: str = ""
    detail: str = ""
    entrypoint: str = ""
    path: tuple[str, ...] = ()
    gated: bool = False

    def to_metadata(self) -> dict[str, object]:
        out: dict[str, object] = {
            "verdict": self.verdict.value,
            "backend": self.backend,
            "function": self.function,
            "detail": self.detail,
        }
        if self.entrypoint:
            out["entrypoint"] = self.entrypoint
        if self.path:
            out["path"] = list(self.path)
        if self.gated:
            out["gated"] = True
        return out

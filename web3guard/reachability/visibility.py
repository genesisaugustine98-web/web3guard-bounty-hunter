"""Cheap visibility-based reachability for non-Solidity languages."""

from __future__ import annotations

import re

from web3guard.reachability.types import ReachabilityEvidence, ReachabilityVerdict


def resolve_visibility(
    language: str, source: str, function: str
) -> ReachabilityEvidence:
    lang = language.lower()
    if lang == "vyper":
        return _resolve_vyper(source, function)
    if lang == "move":
        return _resolve_move(source, function)
    if lang == "cairo":
        return _resolve_cairo(source, function)
    if lang == "clarity":
        return _resolve_clarity(source, function)
    return _unknown(f"no visibility check for {language}")


def _reachable(detail: str) -> ReachabilityEvidence:
    return ReachabilityEvidence(
        ReachabilityVerdict.REACHABLE, "visibility", detail=detail
    )


def _unknown(detail: str) -> ReachabilityEvidence:
    return ReachabilityEvidence(
        ReachabilityVerdict.UNKNOWN, "visibility", detail=detail
    )


def _preceding_decorators(lines: list[str], idx: int) -> list[str]:
    out: list[str] = []
    j = idx - 1
    while j >= 0:
        stripped = lines[j].strip()
        if stripped.startswith("@"):
            out.append(stripped[1:].split("(")[0].strip())
            j -= 1
        elif stripped == "":
            j -= 1
        else:
            break
    return out


def _resolve_vyper(source: str, function: str) -> ReachabilityEvidence:
    if not function:
        return _unknown("no function name")
    lines = source.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^\s*def\s+([a-z_][a-z0-9_]*)\s*\(", line)
        if not m or m.group(1) != function:
            continue
        decorators = _preceding_decorators(lines, i)
        if any(d in ("external", "public") for d in decorators):
            return _reachable(f"@{decorators[0]} {function}")
        if any(d in ("internal", "private") for d in decorators):
            if re.search(rf"self\.{re.escape(function)}\s*\(", source):
                return _reachable(f"internal {function} reached via self-call")
            return _unknown(f"internal {function} with no visible caller")
        return _unknown("no visibility decorator")
    return _unknown("function not found")


def _resolve_move(source: str, function: str) -> ReachabilityEvidence:
    if not function:
        return _unknown("no function name")
    if re.search(rf"\b(?:public\s+)?entry\s+fun\s+{re.escape(function)}\b", source):
        return _reachable(f"entry fun {function}")
    if re.search(rf"\bpublic\s+fun\s+{re.escape(function)}\b", source):
        return _reachable(f"public fun {function}")
    return _unknown(f"non-public fun {function}")


def _resolve_cairo(source: str, function: str) -> ReachabilityEvidence:
    if not function:
        return _unknown("no function name")
    for m in re.finditer(rf"\bfn\s+{re.escape(function)}\b", source):
        window = source[max(0, m.start() - 200):m.start()]
        if "#[external]" in window or "#[abi" in window:
            return _reachable(f"external fn {function}")
    return _unknown(f"non-external fn {function}")


def _resolve_clarity(source: str, function: str) -> ReachabilityEvidence:
    if not function:
        return _unknown("no function name")
    if re.search(rf"\(define-public\s*\(\s*{re.escape(function)}\b", source):
        return _reachable(f"define-public {function}")
    return _unknown(f"non-public define {function}")

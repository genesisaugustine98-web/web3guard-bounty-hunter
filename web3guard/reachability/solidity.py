"""Custom Solidity reachability verdicts."""

from __future__ import annotations

from web3guard.reachability.solidity_index import FunctionIndex, FunctionInfo
from web3guard.reachability.types import ReachabilityEvidence, ReachabilityVerdict

_ENTRY_VISIBILITIES = {"public", "external"}
_SPECIAL_ENTRY_NAMES = {"fallback", "receive"}
_MAX_HOPS = 64


def resolve_solidity(
    index: FunctionIndex, fn: FunctionInfo | None
) -> ReachabilityEvidence:
    if fn is None:
        return ReachabilityEvidence(
            ReachabilityVerdict.UNKNOWN, "solidity-parser",
            detail="function not found in index",
        )
    if fn.is_constructor or fn.name in _SPECIAL_ENTRY_NAMES \
            or fn.visibility in _ENTRY_VISIBILITIES:
        label = fn.visibility or ("constructor" if fn.is_constructor else fn.name)
        return ReachabilityEvidence(
            ReachabilityVerdict.REACHABLE, "solidity-parser",
            function=fn.name, entrypoint=fn.name, gated=fn.gated,
            detail=f"external entrypoint ({label})",
        )
    if fn.visibility not in ("internal", "private"):
        return ReachabilityEvidence(
            ReachabilityVerdict.UNKNOWN, "solidity-parser",
            function=fn.name, detail="unknown visibility",
        )
    found = _bfs(index, fn)
    if found is not None:
        entry, path = found
        return ReachabilityEvidence(
            ReachabilityVerdict.REACHABLE, "solidity-parser",
            function=fn.name, entrypoint=entry, path=path, gated=fn.gated,
            detail="reverse call path reaches an external entrypoint",
        )
    if fn.virtual or fn.abstract:
        return ReachabilityEvidence(
            ReachabilityVerdict.UNKNOWN, "solidity-parser",
            function=fn.name,
            detail="virtual or abstract member; a derived contract may expose it",
        )
    if not index.references(fn.name):
        return ReachabilityEvidence(
            ReachabilityVerdict.NOT_REACHABLE, "solidity-parser",
            function=fn.name,
            detail="identifier referenced nowhere in user code",
        )
    return ReachabilityEvidence(
        ReachabilityVerdict.NOT_REACHABLE, "solidity-parser",
        function=fn.name,
        detail="no reverse call path reaches an external entrypoint",
    )


def _bfs(index: FunctionIndex, fn: FunctionInfo) -> tuple[str, tuple[str, ...]] | None:
    frontier: list[tuple[FunctionInfo, tuple[str, ...]]] = [
        (start, (start.name,)) for start in index.by_name(fn.name)
    ]
    visited: set[tuple[str, str, str]] = set()
    for _ in range(_MAX_HOPS):
        if not frontier:
            return None
        nxt: list[tuple[FunctionInfo, tuple[str, ...]]] = []
        for current, path in frontier:
            key = (current.file, current.contract, current.name)
            if key in visited:
                continue
            visited.add(key)
            if current.is_constructor \
                    or current.name in _SPECIAL_ENTRY_NAMES \
                    or current.visibility in _ENTRY_VISIBILITIES:
                return current.name, path
            for caller in index.references(current.name):
                nxt.append((caller, path + (caller.name,)))
        frontier = nxt
    return None

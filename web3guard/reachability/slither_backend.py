"""Optional Slither corroboration for Solidity reachability."""

from __future__ import annotations

from pathlib import Path

from web3guard.reachability.solidity_index import FunctionInfo
from web3guard.reachability.types import ReachabilityVerdict


def _full_name(function: object) -> str:
    return getattr(function, "full_name", None) or getattr(function, "name", "")


class SlitherBackend:
    def __init__(self, target_path: Path) -> None:
        self._target = Path(target_path)
        self._result = None
        self._loaded = False

    def _load(self):  # noqa: ANN202
        if self._loaded:
            return self._result
        self._loaded = True
        try:
            from slither import Slither

            self._result = Slither(str(self._target))
        except Exception:  # noqa: BLE001
            self._result = None
        return self._result

    def verdict(self, fn: FunctionInfo) -> ReachabilityVerdict | None:
        instance = self._load()
        if instance is None:
            return None
        try:
            reachable = self._reachable(instance)
            matches = [
                f for c in instance.contracts for f in c.functions if f.name == fn.name
            ]
            if not matches:
                return None
            if any(_full_name(f) in reachable for f in matches):
                return ReachabilityVerdict.REACHABLE
            if all(not c.is_abstract for c in instance.contracts):
                return ReachabilityVerdict.NOT_REACHABLE
            return None
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _reachable(instance: object) -> set[str]:
        stack = [
            f for c in instance.contracts for f in c.functions_entry_points  # type: ignore[attr-defined]
        ]
        seen: set[str] = set()
        while stack:
            function = stack.pop()
            name = _full_name(function)
            if name in seen:
                continue
            seen.add(name)
            try:
                stack.extend(function.all_internal_calls())
            except Exception:  # noqa: BLE001
                continue
        return seen

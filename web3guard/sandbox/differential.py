"""Best-effort source mutators that patch one vulnerability category.

Used for differential confirmation: a real exploit must pass against the
vulnerable contract and FAIL against the patched copy. A mutator returns
``None`` when it cannot confidently patch the source, and the caller then
treats the finding as undifferentiated instead of confirmed.
"""
from __future__ import annotations

import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from web3guard.sandbox import create_sandbox

_REENTRANCY_CALL = re.compile(
    r'\(bool\s+ok,\)\s*=\s*msg\.sender\.call\{value:\s*_amount\}\(""\);\s*'
    r'require\(ok,\s*"send fail"\);\s*'
    r'balances\[msg\.sender\]\s*-=\s*_amount;',
    re.DOTALL,
)


def _mutate_reentrancy(source: str) -> str | None:
    def _fix(m: re.Match[str]) -> str:
        return (
            "balances[msg.sender] -= _amount;\n        "
            '(bool ok,) = msg.sender.call{value: _amount}("");\n        '
            'require(ok, "send fail");'
        )

    new, count = _REENTRANCY_CALL.subn(_fix, source)
    return new if count else None


def _mutate_access_control(source: str) -> str | None:
    pattern = re.compile(
        r"(\bfunction\s+\w+\s*\([^)]*\)\s*(?:external|public)[^{;]*)\{([^{}]*)\}",
        re.DOTALL,
    )

    def _fix(m: re.Match[str]) -> str:
        body = m.group(2)
        if "require(msg.sender" in body:
            return m.group(0)
        return (
            m.group(1) + "{\n        "
            'require(msg.sender == owner, "unauthorized");\n'
            + body + "\n    }"
        )

    new, count = pattern.subn(_fix, source)
    return new if count else None


MUTATORS: dict[str, Callable[[str], str | None]] = {
    "reentrancy": _mutate_reentrancy,
    "access-control": _mutate_access_control,
}


def mutate_source(category: str, source: str) -> str | None:
    mutator = MUTATORS.get(category)
    if mutator is None:
        return None
    return mutator(source)


@dataclass
class DifferentialOutcome:
    status: str
    vulnerable_output: str = ""
    patched_output: str = ""


_SKIP_DIRS = {
    "lib", "libs", "node_modules", "test", "tests", "script", "scripts",
    "out", "cache", "broadcast", ".git", ".github", ".vscode",
}

_SKIP_SUFFIXES = ("test.sol", "mock.sol", "stub.sol", "fake.sol", "script.sol")


def _apply_mutation(category: str, root: Path) -> bool:
    changed = False
    for sol in root.rglob("*.sol"):
        if any(part.lower() in _SKIP_DIRS for part in sol.relative_to(root).parts[:-1]):
            continue
        if sol.name.lower().endswith(_SKIP_SUFFIXES):
            continue
        text = sol.read_text(errors="ignore")
        new = mutate_source(category, text)
        if new is not None and new != text:
            sol.write_text(new)
            changed = True
    return changed


def run_differential(
    adapter: Any,
    target_path: Path,
    workdir: Path,
    poc_code: str,
    fingerprint: str,
    category: str,
) -> DifferentialOutcome:
    if category not in MUTATORS:
        return DifferentialOutcome("no-mutator")
    vuln = create_sandbox(adapter, target_path, workdir)
    if vuln is None:
        return DifferentialOutcome("vulnerable-failed", "sandbox init failed", "")
    ok_v, out_v = vuln.write_and_run(poc_code, f"{fingerprint}-vuln")
    if not ok_v:
        return DifferentialOutcome("vulnerable-failed", out_v, "")
    patched_dir = workdir / f"patched-{fingerprint[:12] or 'fp'}"
    shutil.copytree(target_path, patched_dir, dirs_exist_ok=True)
    if not _apply_mutation(category, patched_dir):
        return DifferentialOutcome("no-mutator", out_v, "")
    patched = create_sandbox(adapter, patched_dir, workdir)
    if patched is None:
        return DifferentialOutcome("no-mutator", out_v, "")
    ok_p, out_p = patched.write_and_run(poc_code, f"{fingerprint}-patched")
    if ok_p:
        return DifferentialOutcome("patched-still-passes", out_v, out_p)
    return DifferentialOutcome("confirmed", out_v, out_p)

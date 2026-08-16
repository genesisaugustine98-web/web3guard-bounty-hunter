"""Echidna discovery engine — property-based fuzzing (assertion mode)."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from web3guard.discovery.base import (
    DiscoveryEngineBase,
    DiscoveryResult,
    safe_run_subprocess,
    temp_report_path,
)
from web3guard.languages.base import TargetLanguage

LOGGER = logging.getLogger("web3guard.discovery.echidna")


class EchidnaEngine(DiscoveryEngineBase):
    """Echidna property-based fuzzer in assertion mode."""

    name = "echidna"
    binary = "echidna"
    supported_languages = (TargetLanguage.SOLIDITY, TargetLanguage.VYPER)
    default_timeout = 300

    def run(self, target_path: Path, *, timeout: int = 0,
            extra_args: list[str] | None = None) -> list[DiscoveryResult]:
        if not self.is_installed():
            LOGGER.info("echidna not installed; skipping")
            return []
        # Echidna needs a compiled contract to fuzz. We need Foundry
        # or Hardhat. If neither is set up, bail.
        if not ((target_path / "foundry.toml").exists()
                or (target_path / "hardhat.config.js").exists()
                or (target_path / "hardhat.config.ts").exists()):
            LOGGER.info("echidna: no foundry/hardhat project; skipping")
            return []
        timeout = timeout or self.default_timeout
        out_file = temp_report_path(target_path, "echidna")
        # Pick a single top-level contract to fuzz
        contracts = self._pick_contracts(target_path)
        if not contracts:
            return []
        results: list[DiscoveryResult] = []
        for contract in contracts[:2]:
            cmd = [
                "echidna", str(contract),
                "--contract", contract.stem,
                "--format", "json",
                "--output", str(out_file),
                "--test-limit", "10000",
                "--seq-len", "50",
            ]
            if extra_args:
                cmd.extend(extra_args)
            rc, stdout, stderr = safe_run_subprocess(
                cmd, cwd=target_path, timeout=min(timeout, 180),
            )
            if out_file.exists():
                try:
                    data = json.loads(out_file.read_text())
                except json.JSONDecodeError:
                    continue
                for issue in data.get("issues", []) or []:
                    results.append(self._translate(issue, target_path, str(contract)))
        return results

    @staticmethod
    def _pick_contracts(target_path: Path) -> list[Path]:
        """Pick the contracts most worth fuzzing.

        Heuristic: prefer contracts with `function` declarations and
        skip libraries / interfaces / mocks.
        """
        candidates: list[Path] = []
        for sol in target_path.rglob("*.sol"):
            s = str(sol).lower()
            if any(p in s for p in ("/test/", "/lib/", "/mock", "/node_modules/", "/script/")):
                continue
            try:
                content = sol.read_text(errors="ignore")[:4000]
            except Exception:  # noqa: BLE001
                continue
            if re.search(r"\bcontract\s+\w+", content):
                candidates.append(sol)
        return candidates

    @staticmethod
    def _translate(issue: dict[str, Any], target_path: Path, contract: str) -> DiscoveryResult:
        # Echidna issue format: {"contract": ..., "function": ..., "tx_seq": [...], "bug": "..."}
        return DiscoveryResult(
            engine="echidna",
            target=str(target_path),
            file=contract,
            function=issue.get("function", "") or "",
            category="assertion-failure",
            severity="HIGH",
            title=f"Echidna: assertion failure in {issue.get('function', '?')}",
            description=str(issue.get("bug", ""))[:2000],
            confidence=0.95,  # dynamic, so high
            raw=issue,
        )

"""Mythril discovery engine — symbolic execution."""

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
)
from web3guard.languages.base import TargetLanguage

LOGGER = logging.getLogger("web3guard.discovery.mythril")


class MythrilEngine(DiscoveryEngineBase):
    """Mythril symbolic execution."""

    name = "mythril"
    binary = "myth"
    supported_languages = (TargetLanguage.SOLIDITY, TargetLanguage.VYPER)
    default_timeout = 300

    def run(self, target_path: Path, *, timeout: int = 0,
            extra_args: list[str] | None = None) -> list[DiscoveryResult]:
        if not self.is_installed():
            LOGGER.info("mythril not installed; skipping")
            return []
        timeout = timeout or self.default_timeout
        out_file = target_path / "mythril_report.json"
        # Mythril analyzes one .sol file at a time, but you can pass
        # a directory if solc-select is configured. We run per top-level
        # .sol file to keep the timeout bounded.
        results: list[DiscoveryResult] = []
        sol_files = list(target_path.rglob("*.sol"))[:5]  # cap for time
        for sol in sol_files:
            if any(p in str(sol).lower() for p in ("/test/", "/lib/", "/node_modules/")):
                continue
            cmd = [
                "myth", "analyze", str(sol),
                "-o", "json",
                "--execution-timeout", str(max(30, timeout // max(1, len(sol_files)))),
            ]
            if extra_args:
                cmd.extend(extra_args)
            rc, stdout, stderr = safe_run_subprocess(cmd, cwd=target_path, timeout=timeout // max(1, len(sol_files)) + 30)
            if not stdout:
                continue
            try:
                data = json.loads(stdout)
            except json.JSONDecodeError:
                continue
            for issue in data.get("issues", []) or []:
                results.append(self._translate(issue, target_path, str(sol)))
        return results

    @staticmethod
    def _translate(issue: dict[str, Any], target_path: Path, sol_file: str) -> DiscoveryResult:
        swc = issue.get("swc-id", "") or issue.get("swc_id", "")
        if isinstance(swc, str) and not swc.startswith("SWC-"):
            swc = f"SWC-{swc}" if swc else ""
        return DiscoveryResult(
            engine="mythril",
            target=str(target_path),
            file=sol_file,
            line=issue.get("lineno", 0) or 0,
            function=issue.get("function", "") or "",
            category=(issue.get("title", "") or "").lower().replace(" ", "-"),
            severity=str(issue.get("severity", "Medium")).upper(),
            title=issue.get("title", ""),
            description=issue.get("description", ""),
            swc_id=swc,
            confidence=0.7,
            raw=issue,
        )

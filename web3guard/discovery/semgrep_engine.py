"""Semgrep discovery engine — security-audit ruleset for TS/JS SDKs."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from web3guard.discovery.base import (
    DiscoveryEngineBase,
    DiscoveryResult,
    safe_run_subprocess,
    temp_report_path,
)
from web3guard.languages.base import TargetLanguage

LOGGER = logging.getLogger("web3guard.discovery.semgrep")


class SemgrepEngine(DiscoveryEngineBase):
    """Semgrep with the security-audit ruleset."""

    name = "semgrep"
    binary = "semgrep"
    supported_languages = (TargetLanguage.TS_SDK,)
    default_timeout = 240

    def run(self, target_path: Path, *, timeout: int = 0,
            extra_args: list[str] | None = None) -> list[DiscoveryResult]:
        if not self.is_installed():
            LOGGER.info("semgrep not installed; skipping")
            return []
        timeout = timeout or self.default_timeout
        out_file = temp_report_path(target_path, "semgrep")
        cmd = [
            "semgrep", "scan",
            "--config", "p/security-audit",
            "--config", "p/javascript",
            "--config", "p/typescript",
            "--config", "p/owasp-top-ten",
            "--json", "--output", str(out_file),
            "--quiet", "--error", "--no-git-ignore",
            str(target_path),
        ]
        if extra_args:
            cmd.extend(extra_args)
        rc, stdout, stderr = safe_run_subprocess(cmd, cwd=target_path, timeout=timeout)
        if not out_file.exists():
            return []
        try:
            data = json.loads(out_file.read_text())
        except json.JSONDecodeError:
            return []
        results: list[DiscoveryResult] = []
        for r in data.get("results", []) or []:
            results.append(self._translate(r, target_path))
        return results

    @staticmethod
    def _translate(r: dict[str, Any], target_path: Path) -> DiscoveryResult:
        sev = (r.get("extra", {}).get("severity") or "WARNING").upper()
        return DiscoveryResult(
            engine="semgrep",
            target=str(target_path),
            file=r.get("path", ""),
            line=r.get("start", {}).get("line", 0) or 0,
            end_line=r.get("end", {}).get("line", 0) or 0,
            category=(r.get("check_id", "") or "").split(".")[-1],
            severity="HIGH" if sev == "ERROR" else "MEDIUM" if sev == "WARNING" else "LOW",
            title=r.get("check_id", ""),
            description=(r.get("extra", {}).get("message", "") or "")[:2000],
            confidence=0.6,
            raw=r,
        )

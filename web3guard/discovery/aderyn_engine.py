"""Aderyn discovery engine — Cyfrin's Rust-based static analyzer."""

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

LOGGER = logging.getLogger("web3guard.discovery.aderyn")


_ADERYN_IMPACT_TO_SEVERITY = {
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "Informational": "INFO",
}


class AderynEngine(DiscoveryEngineBase):
    """Aderyn (Cyfrin)."""

    name = "aderyn"
    binary = "aderyn"
    supported_languages = (TargetLanguage.SOLIDITY,)
    default_timeout = 300

    def run(self, target_path: Path, *, timeout: int = 0,
            extra_args: list[str] | None = None) -> list[DiscoveryResult]:
        if not self.is_installed():
            LOGGER.info("aderyn not installed; skipping")
            return []
        timeout = timeout or self.default_timeout
        # Aderyn writes its report to a file; use --output.
        out_file = temp_report_path(target_path, "aderyn")
        cmd = ["aderyn", str(target_path), "--output", str(out_file), "--no-fail"]
        if extra_args:
            cmd.extend(extra_args)
        rc, stdout, stderr = safe_run_subprocess(cmd, cwd=target_path, timeout=timeout)
        if not out_file.exists():
            return []
        try:
            data = json.loads(out_file.read_text())
        except json.JSONDecodeError as e:
            LOGGER.warning("aderyn JSON decode failed: %s", e)
            return []
        results: list[DiscoveryResult] = []
        # Aderyn's report format: {"high_count": ..., "lower_count": ...,
        # "issues": [...]}. Each issue has a "title" and "details".
        for issue in data.get("issues", []) or []:
            results.append(self._translate(issue, target_path))
        return results

    @staticmethod
    def _translate(issue: dict[str, Any], target_path: Path) -> DiscoveryResult:
        severity = _ADERYN_IMPACT_TO_SEVERITY.get(issue.get("impact", "Medium"), "MEDIUM")
        instances = issue.get("instances", []) or []
        results: list[DiscoveryResult] = []
        for inst in instances:
            path_str = inst.get("path", "")
            line_no = inst.get("line", 0) or 0
            return DiscoveryResult(
                engine="aderyn",
                target=str(target_path),
                file=path_str,
                line=int(line_no) if str(line_no).isdigit() else 0,
                function=inst.get("function", "") or "",
                category=(issue.get("title", "") or "").lower().replace(" ", "-"),
                severity=severity,
                title=issue.get("title", ""),
                description=issue.get("details", ""),
                confidence=0.5,
                raw=issue,
            )
        # No instances — emit one synthetic finding per detector
        if not results:
            return DiscoveryResult(
                engine="aderyn",
                target=str(target_path),
                file="",
                category=(issue.get("title", "") or "").lower().replace(" ", "-"),
                severity=severity,
                title=issue.get("title", ""),
                description=issue.get("details", ""),
                confidence=0.5,
                raw=issue,
            )
        return results[0]

"""npm audit discovery engine — dependency vulnerabilities for TS/JS SDKs."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from web3guard.discovery.base import (
    DiscoveryEngineBase,
    DiscoveryResult,
    safe_run_subprocess,
)
from web3guard.languages.base import TargetLanguage

LOGGER = logging.getLogger("web3guard.discovery.npm_audit")


class NpmAuditEngine(DiscoveryEngineBase):
    """`npm audit --json` — pulls in advisory DB results."""

    name = "npm-audit"
    binary = "npm"
    supported_languages = (TargetLanguage.TS_SDK,)
    default_timeout = 120

    def run(self, target_path: Path, *, timeout: int = 0,
            extra_args: list[str] | None = None) -> list[DiscoveryResult]:
        if not (target_path / "package.json").exists():
            return []
        if not self.is_installed():
            LOGGER.info("npm not installed; skipping")
            return []
        timeout = timeout or self.default_timeout
        cmd = ["npm", "audit", "--json"]
        if extra_args:
            cmd.extend(extra_args)
        rc, stdout, stderr = safe_run_subprocess(cmd, cwd=target_path, timeout=timeout)
        if not stdout:
            return []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return []
        results: list[DiscoveryResult] = []
        for advisory_id, advisory in (data.get("vulnerabilities") or {}).items():
            results.append(DiscoveryResult(
                engine="npm-audit",
                target=str(target_path),
                file="package.json",
                line=0,
                category="dependency-vuln",
                severity=str(advisory.get("severity", "medium")).upper(),
                title=advisory.get("title", advisory_id),
                description=advisory.get("url", ""),
                confidence=0.8,
                raw=advisory,
            ))
        return results

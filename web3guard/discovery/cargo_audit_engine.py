"""Cargo audit discovery engine — dependency vulnerabilities for Rust crates."""

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

LOGGER = logging.getLogger("web3guard.discovery.cargo_audit")


class CargoAuditEngine(DiscoveryEngineBase):
    """`cargo audit` — RustSec advisory database."""

    name = "cargo-audit"
    binary = "cargo"
    supported_languages = (TargetLanguage.RUST_SOLANA,)
    default_timeout = 180

    def run(self, target_path: Path, *, timeout: int = 0,
            extra_args: list[str] | None = None) -> list[DiscoveryResult]:
        if not (target_path / "Cargo.toml").exists():
            return []
        if not self.is_installed():
            LOGGER.info("cargo not installed; skipping")
            return []
        timeout = timeout or self.default_timeout
        cmd = ["cargo", "audit", "--json"]
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
        for finding in (data.get("vulnerabilities") or {}).get("list", []) or []:
            advisory = finding.get("advisory", {})
            results.append(DiscoveryResult(
                engine="cargo-audit",
                target=str(target_path),
                file="Cargo.toml",
                line=0,
                category="dependency-vuln",
                severity="HIGH" if advisory.get("severity", "") == "high" else "MEDIUM",
                title=advisory.get("title", ""),
                description=advisory.get("description", "")[:2000],
                confidence=0.85,
                raw=finding,
            ))
        return results

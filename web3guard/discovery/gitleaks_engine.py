"""Gitleaks discovery engine — secret scanning.

Falls back to a built-in regex-only secret scan if Gitleaks isn't
installed, so the scanner always produces some signal here.
"""

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

LOGGER = logging.getLogger("web3guard.discovery.gitleaks")


_BUILTIN_PATTERNS: dict[str, re.Pattern[str]] = {
    "private_key":       re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    "aws_access_key":    re.compile(r"AKIA[0-9A-Z]{16}"),
    "alchemy_rpc":       re.compile(r"https://[a-zA-Z0-9._-]*alchemy[a-zA-Z0-9._-]*/v2/[A-Za-z0-9_-]{20,}"),
    "infura_rpc":        re.compile(r"https://[a-zA-Z0-9._-]*infura[a-zA-Z0-9._-]*/v3/[A-Za-z0-9_-]{20,}"),
    "mnemonic":          re.compile(r"\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b"),
    "github_token":      re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
    "openai_key":        re.compile(r"sk-[A-Za-z0-9]{20,}"),
    "google_api_key":    re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "private_key_hex":   re.compile(r"\b[0-9a-fA-F]{64}\b"),
}


class GitleaksEngine(DiscoveryEngineBase):
    """Gitleaks — secret scanner with a built-in regex fallback."""

    name = "gitleaks"
    binary = "gitleaks"
    supported_languages = (
        TargetLanguage.SOLIDITY, TargetLanguage.VYPER, TargetLanguage.MOVE,
        TargetLanguage.CAIRO, TargetLanguage.CLARITY, TargetLanguage.FUNC,
        TargetLanguage.RUST_SOLANA, TargetLanguage.TS_SDK,
    )
    default_timeout = 180
    enabled_by_default = True

    def run(self, target_path: Path, *, timeout: int = 0,
            extra_args: list[str] | None = None) -> list[DiscoveryResult]:
        if not self.is_installed():
            LOGGER.info("gitleaks not installed; running built-in regex scan")
            return self._builtin_scan(target_path)
        timeout = timeout or self.default_timeout
        out_file = target_path / "gitleaks_report.json"
        cmd = [
            "gitleaks", "detect",
            "--source", str(target_path),
            "--report-format", "json",
            "--report-path", str(out_file),
            "--no-banner",
            "--exit-code", "0",  # never fail the run
        ]
        if extra_args:
            cmd.extend(extra_args)
        rc, stdout, stderr = safe_run_subprocess(cmd, cwd=target_path, timeout=timeout)
        if not out_file.exists():
            return self._builtin_scan(target_path)
        try:
            data = json.loads(out_file.read_text())
        except json.JSONDecodeError:
            return self._builtin_scan(target_path)
        results: list[DiscoveryResult] = []
        for finding in data or []:
            results.append(DiscoveryResult(
                engine="gitleaks",
                target=str(target_path),
                file=finding.get("File", ""),
                line=int(finding.get("StartLine", 0) or 0),
                category="secret-leak",
                severity="CRITICAL",
                title=f"Secret: {finding.get('RuleID', '?')}",
                description=finding.get("Match", "")[:200],
                confidence=0.95,
                raw=finding,
            ))
        return results

    def _builtin_scan(self, target_path: Path) -> list[DiscoveryResult]:
        """Regex-only fallback so we always have secret-scan signal."""
        results: list[DiscoveryResult] = []
        for fp in target_path.rglob("*"):
            if not fp.is_file():
                continue
            s = str(fp).lower()
            if any(p in s for p in ("/.git/", "/node_modules/", "/target/", "/build/", "/out/")):
                continue
            try:
                content = fp.read_text(errors="ignore")
            except Exception:  # noqa: BLE001
                continue
            for kind, pattern in _BUILTIN_PATTERNS.items():
                for m in pattern.finditer(content):
                    line = content[: m.start()].count("\n") + 1
                    results.append(DiscoveryResult(
                        engine="gitleaks",
                        target=str(target_path),
                        file=str(fp.relative_to(target_path)),
                        line=line,
                        category="secret-leak",
                        severity="CRITICAL",
                        title=f"Secret: {kind}",
                        description=m.group(0)[:120],
                        confidence=0.85,
                        raw={"kind": kind, "file": str(fp.relative_to(target_path))},
                    ))
        return results

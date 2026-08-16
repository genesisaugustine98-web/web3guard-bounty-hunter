"""Gitleaks discovery engine — secret scanning.

Falls back to a built-in regex-only secret scan if Gitleaks isn't
installed, so the scanner always produces some signal here.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from web3guard.discovery.base import (
    DiscoveryEngineBase,
    DiscoveryResult,
    safe_run_subprocess,
    temp_report_path,
)
from web3guard.languages.base import TargetLanguage
from web3guard.utils.secrets import iter_secret_matches

LOGGER = logging.getLogger("web3guard.discovery.gitleaks")


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
        out_file = temp_report_path(target_path, "gitleaks")
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
            s = "/" + fp.relative_to(target_path).as_posix().lower().strip("/") + "/"
            if any(p in s for p in ("/.git/", "/node_modules/", "/target/", "/build/", "/out/")):
                continue
            try:
                content = fp.read_text(errors="ignore")
            except Exception:  # noqa: BLE001
                continue
            for match in iter_secret_matches(content):
                results.append(DiscoveryResult(
                    engine="gitleaks",
                    target=str(target_path),
                    file=str(fp.relative_to(target_path)),
                    line=match.line,
                    category="secret-leak",
                    severity="CRITICAL",
                    title=f"Secret: {match.kind}",
                    description=match.value[:120],
                    confidence=0.85,
                    raw={"kind": match.kind, "file": str(fp.relative_to(target_path))},
                ))
        return results

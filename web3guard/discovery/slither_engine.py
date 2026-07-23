"""Slither discovery engine — Trail of Bits' static analyzer."""

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

LOGGER = logging.getLogger("web3guard.discovery.slither")


# Slither's detector categories mapped to a small set of severity
# buckets. This is a coarse mapping; we trust the LLM pass to refine.
_SLITHER_IMPACT_TO_SEVERITY = {
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "Informational": "INFO",
    "Optimization": "INFO",
}


class SlitherEngine(DiscoveryEngineBase):
    """Slither (Trail of Bits)."""

    name = "slither"
    binary = "slither"
    supported_languages = (TargetLanguage.SOLIDITY, TargetLanguage.VYPER)
    default_timeout = 300

    def run(self, target_path: Path, *, timeout: int = 0,
            extra_args: list[str] | None = None) -> list[DiscoveryResult]:
        if not self.is_installed():
            LOGGER.info("slither not installed; skipping")
            return []
        timeout = timeout or self.default_timeout
        out_format = "json"
        # Slither expects a target. We pass the project root and let it
        # autodetect the framework. We use --no-fail to keep going on
        # compilation errors (so we still get hints from files that
        # compile).
        cmd = [
            "slither", str(target_path),
            "--json", "-",
            "--no-fail",
            "--filter", "low",  # include Low+ detectors
        ]
        if extra_args:
            cmd.extend(extra_args)
        rc, stdout, stderr = safe_run_subprocess(cmd, cwd=target_path, timeout=timeout)
        if not stdout:
            LOGGER.warning("slither returned no output (rc=%d, stderr=%s)", rc, stderr[:300])
            return []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            LOGGER.warning("slither JSON decode failed: %s; first 200 bytes: %s",
                           e, stdout[:200])
            return []
        results: list[DiscoveryResult] = []
        for detector in (data.get("results") or {}).get("detectors", []):
            results.append(self._translate(detector, target_path))
        return results

    @staticmethod
    def _translate(det: dict[str, Any], target_path: Path) -> DiscoveryResult:
        elements = det.get("elements") or []
        first_file = ""
        first_line = 0
        first_end_line = 0
        first_function = ""
        for el in elements:
            if el.get("type") in ("function", "node"):
                sm = el.get("source_mapping") or {}
                fname = sm.get("filename_relative") or sm.get("filename_short") or ""
                if fname and not first_file:
                    first_file = fname
                    first_line = sm.get("lines", [0])[0] if sm.get("lines") else 0
                    first_end_line = sm.get("lines", [0, 0])[-1] if sm.get("lines") else 0
                if el.get("type") == "function" and not first_function:
                    first_function = el.get("name", "")
        impact = det.get("impact", "Medium")
        confidence = det.get("confidence", "Medium")
        severity = _SLITHER_IMPACT_TO_SEVERITY.get(impact, "MEDIUM")
        return DiscoveryResult(
            engine="slither",
            target=str(target_path),
            file=first_file,
            line=first_line,
            end_line=first_end_line,
            function=first_function,
            category=(det.get("check", "") or "").lower(),
            severity=severity,
            title=det.get("check", ""),
            description=det.get("description", ""),
            swc_id=_extract_swc(det),
            confidence=0.5 + (0.3 if confidence == "High" else 0.1 if confidence == "Medium" else 0.0),
            raw=det,
        )


def _extract_swc(det: dict[str, Any]) -> str:
    """Pull the SWC ID out of a Slither detector's markdown string."""
    m = re.search(r"SWC-(\d+)", det.get("markdown", "") or "")
    return f"SWC-{m.group(1)}" if m else ""

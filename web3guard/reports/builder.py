"""Render scan results as text, JSON, SARIF 2.1.0, and Markdown."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Iterable
from enum import Enum, StrEnum
from pathlib import Path
from typing import Any


class ReportFormat(StrEnum):
    TXT = "txt"
    JSON = "json"
    SARIF = "sarif"
    MARKDOWN = "md"


_FILENAMES = {
    "txt": "WEB3GUARD_EXPLOIT_REPORT.txt",
    "json": "WEB3GUARD_FINDINGS.json",
    "sarif": "web3guard.sarif",
    "md": "WEB3GUARD_EXPLOIT_REPORT.md",
}


class ReportBuilder:
    def __init__(self, result: Any, findings_db: Any | None = None) -> None:
        self.result = result
        self.findings_db = findings_db

    def write(self, out_dir: Path, *, formats: Iterable[str] = ("txt", "json", "sarif", "md")) -> dict[str, Path]:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        written: dict[str, Path] = {}
        for requested in formats:
            fmt = requested.value if isinstance(requested, ReportFormat) else str(requested).lower()
            if fmt == "markdown":
                fmt = "md"
            if fmt not in _FILENAMES:
                raise ValueError(f"unsupported report format: {requested!r}")
            path = out_dir / _FILENAMES[fmt]
            path.write_text(self._render(fmt), encoding="utf-8")
            written[fmt] = path
        return written

    def _render(self, fmt: str) -> str:
        if fmt == "json":
            return json.dumps(dataclasses.asdict(self.result), indent=2, default=_json_default) + "\n"
        if fmt == "sarif":
            return json.dumps(self._sarif(), indent=2) + "\n"
        if fmt == "md":
            return self._markdown()
        return self._text()

    def _text(self) -> str:
        findings = list(self.result.all_findings)
        lines = ["Web3Guard Exploit Report", "=" * 24, f"Findings: {len(findings)}", ""]
        for finding in findings:
            lines.extend([
                f"[{finding.severity}] {finding.category or 'uncategorized'}",
                f"Target: {finding.target}",
                f"Location: {finding.file}{':' + finding.line_hint if finding.line_hint else ''}",
                f"Status: {finding.status}",
                finding.description,
                "",
            ])
        return "\n".join(lines).rstrip() + "\n"

    def _markdown(self) -> str:
        findings = list(self.result.all_findings)
        lines = ["# Web3Guard Exploit Report", "", f"**Findings:** {len(findings)}", ""]
        for finding in findings:
            lines.extend([
                f"## {finding.severity}: {finding.category or 'Uncategorized'}",
                "",
                f"- Target: `{finding.target}`",
                f"- Location: `{finding.file}{':' + finding.line_hint if finding.line_hint else ''}`",
                f"- Status: `{finding.status}`",
                f"- Confidence: `{finding.confidence:.2f}`",
                "",
                finding.description,
                "",
            ])
        return "\n".join(lines).rstrip() + "\n"

    def _sarif(self) -> dict[str, Any]:
        results = []
        rules: dict[str, dict[str, Any]] = {}
        levels = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
        for finding in self.result.all_findings:
            rule_id = finding.fingerprint or finding.category or "web3guard-finding"
            rules.setdefault(rule_id, {
                "id": rule_id,
                "name": finding.category or "Web3GuardFinding",
                "shortDescription": {"text": finding.description or finding.category or "Web3Guard finding"},
            })
            location: dict[str, Any] = {"artifactLocation": {"uri": finding.file}}
            start_line = _start_line(finding.line_hint)
            if start_line is not None:
                location["region"] = {"startLine": start_line}
            results.append({
                "ruleId": rule_id,
                "level": levels.get(str(finding.severity).upper(), "warning"),
                "message": {"text": finding.description or finding.reasoning or finding.category},
                "locations": [{"physicalLocation": location}],
            })
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Web3Guard", "informationUri": "https://github.com/genesisaugustine98-web/web3guard-bounty-hunter", "rules": list(rules.values())}},
                "results": results,
            }],
        }


def _json_default(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    return str(value)


def _start_line(line_hint: str) -> int | None:
    if not line_hint:
        return None
    first = line_hint.split("-", 1)[0].strip().lstrip("L")
    return int(first) if first.isdigit() and int(first) > 0 else None

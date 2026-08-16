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
    HTML = "html"


_FILENAMES = {
    "txt": "WEB3GUARD_EXPLOIT_REPORT.txt",
    "json": "WEB3GUARD_FINDINGS.json",
    "sarif": "web3guard.sarif",
    "md": "WEB3GUARD_EXPLOIT_REPORT.md",
    "html": "WEB3GUARD_EXPLOIT_REPORT.html",
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
        if fmt == "html":
            return self._html()
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

    def _html(self) -> str:
        """Self-contained HTML report (inline CSS, no external assets)."""
        findings = list(self.result.all_findings)
        severity_color = {
            "CRITICAL": "#c62828", "HIGH": "#e65100", "MEDIUM": "#f9a825",
            "LOW": "#2e7d32", "INFO": "#37474f",
        }
        rows: list[str] = []
        for f in findings:
            sev = str(f.severity).upper()
            color = severity_color.get(sev, "#37474f")
            rows.append(
                "<tr>"
                f"<td><span class=\"sev\" style=\"background:{color}\">{sev}</span></td>"
                f"<td>{_html_escape(f.category or 'uncategorized')}</td>"
                f"<td><code>{_html_escape(f.file)}</code>"
                + (f":<code>{_html_escape(f.line_hint)}</code>" if f.line_hint else "")
                + "</td>"
                f"<td>{_html_escape(f.function or '')}</td>"
                f"<td>{_html_escape(f.description or '')}</td>"
                f"<td>{_html_escape(f.status)}</td>"
                f"<td>{f.confidence:.2f}</td>"
                "</tr>"
            )
        return (
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
            "<meta charset=\"utf-8\">\n"
            "<title>Web3Guard Exploit Report</title>\n"
            "<style>\n"
            "body{font-family:-apple-system,'Segoe UI',Roboto,sans-serif;"
            "margin:2rem auto;max-width:1100px;padding:0 1rem;color:#222}\n"
            "h1{border-bottom:2px solid #1a237e;padding-bottom:.5rem}\n"
            "table{border-collapse:collapse;width:100%;margin-top:1rem}\n"
            "th,td{border:1px solid #ddd;padding:.5rem .75rem;text-align:left;"
            "font-size:.9rem;vertical-align:top}\n"
            "th{background:#f5f5f5}\n"
            "code{background:#f5f5f5;padding:.1rem .35rem;border-radius:3px;"
            "font-size:.85rem}\n"
            ".sev{color:#fff;padding:.15rem .5rem;border-radius:3px;"
            "font-size:.8rem;font-weight:600;white-space:nowrap}\n"
            "</style>\n</head>\n<body>\n"
            f"<h1>Web3Guard Exploit Report</h1>\n"
            f"<p><strong>Findings:</strong> {len(findings)} "
            f"&nbsp;|&nbsp; <strong>Confirmed:</strong> {len(self.result.confirmed_findings)} "
            f"&nbsp;|&nbsp; <strong>Targets:</strong> {len(self.result.targets)}</p>\n"
            "<table>\n<thead><tr>"
            "<th>Severity</th><th>Category</th><th>Location</th><th>Function</th>"
            "<th>Description</th><th>Status</th><th>Confidence</th>"
            "</tr></thead>\n<tbody>\n"
            + "\n".join(rows)
            + "\n</tbody>\n</table>\n</body>\n</html>\n"
        )

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


def _html_escape(value: Any) -> str:
    return (str(value)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))


def _start_line(line_hint: str) -> int | None:
    if not line_hint:
        return None
    first = line_hint.split("-", 1)[0].strip().lstrip("L")
    return int(first) if first.isdigit() and int(first) > 0 else None

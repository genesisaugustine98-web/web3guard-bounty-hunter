"""Render a saved scan report as human-readable finding text.

The Telegram bot posts scan outcomes back to the requesting chat. Instead
of the shared-database ``dashboard`` summary (short fingerprint rows that
carry no finding text), this renders the actual findings persisted to disk
by a scan — full severity, location, status, description and evidence —
so the chat message contains the findings themselves without the user
having to open GitHub artifacts.
"""

from __future__ import annotations

import json
from pathlib import Path

FINDINGS_FILENAME = "WEB3GUARD_FINDINGS.json"
TXT_FILENAME = "WEB3GUARD_EXPLOIT_REPORT.txt"

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def load_scan_report(report_dir: str | Path) -> dict | None:
    """Load ``WEB3GUARD_FINDINGS.json`` from a scan output directory."""
    path = Path(report_dir) / FINDINGS_FILENAME
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def iter_findings(data: dict):
    """Yield normalized finding dicts from a ``ScanResult``-asdict report.

    Tolerates both the nested ``targets[].findings`` layout the scanner
    writes and a flat ``findings`` list for hand-built inputs.
    """
    if not isinstance(data, dict):
        return
    targets = data.get("targets")
    if isinstance(targets, list):
        for target in targets:
            if not isinstance(target, dict):
                continue
            target_name = target.get("target", "")
            for finding in target.get("findings") or []:
                if isinstance(finding, dict):
                    finding = dict(finding)
                    finding.setdefault("target", target_name)
                    yield finding
        return
    findings = data.get("findings")
    if isinstance(findings, list):
        for finding in findings:
            if isinstance(finding, dict):
                yield finding


def _severity_key(finding: dict) -> int:
    try:
        return _SEVERITY_ORDER.index(str(finding.get("severity", "LOW")).upper())
    except ValueError:
        return len(_SEVERITY_ORDER)


def _location(finding: dict) -> str:
    loc = str(finding.get("file") or "unknown")
    line_hint = str(finding.get("line_hint") or "").strip()
    if line_hint:
        loc += ":" + line_hint
    function = str(finding.get("function") or "").strip()
    if function:
        loc += f" ({function})"
    return loc


def _severity_counts(findings: list[dict]) -> str:
    counts: list[str] = []
    for sev in _SEVERITY_ORDER:
        n = sum(1 for f in findings if str(f.get("severity", "")).upper() == sev)
        if n:
            counts.append(f"{sev}={n}")
    return " ".join(counts) if counts else "none"


def render_digest(data: dict, *, include_poc: bool = True, max_findings: int = 0) -> str:
    """Render a scan report dict as plain-text findings for a chat message."""
    all_findings = sorted(iter_findings(data), key=_severity_key)
    truncated = bool(max_findings and max_findings > 0 and len(all_findings) > max_findings)
    findings = all_findings[:max_findings] if truncated else all_findings

    confirmed = sum(
        1 for f in all_findings if str(f.get("status", "")).upper() == "CONFIRMED EXPLOIT"
    )
    header = (
        f"Web3Guard findings ({_severity_counts(all_findings)})",
        f"Findings: {len(all_findings)}  Confirmed exploits: {confirmed}",
    )
    if truncated:
        header += (f"(showing first {len(findings)}; see the Actions report artifact for all)",)
    lines: list[str] = list(header)

    for finding in findings:
        severity = str(finding.get("severity") or "LOW").upper()
        category = str(finding.get("category") or "uncategorized")
        confidence = finding.get("confidence")
        confidence_txt = f"  confidence {float(confidence):.2f}" if isinstance(confidence, (int, float)) else ""
        lines.append("")
        lines.append(f"[{severity}] {category}{confidence_txt}")
        lines.append(f"  Location: {_location(finding)}")
        meta = []
        language = str(finding.get("language") or "").strip()
        if language:
            meta.append(language)
        status = str(finding.get("status") or "POTENTIAL")
        meta.append(f"status {status}")
        swc = str(finding.get("swc_id") or "").strip()
        if swc:
            meta.append(swc)
        lines.append("  " + " | ".join(meta))
        target = str(finding.get("target") or "").strip()
        if target:
            lines.append(f"  Target: {target}")

        description = str(finding.get("description") or "").strip()
        if description:
            lines.append("")
            lines.append(description)

        reasoning = str(finding.get("reasoning") or "").strip()
        if reasoning and reasoning != description:
            lines.append("")
            lines.append(f"Evidence: {reasoning}")

        poc = str(finding.get("poc_code") or "").strip()
        if include_poc and poc and status.upper() == "CONFIRMED EXPLOIT":
            lines.append("")
            lines.append("PoC:")
            lines.append(poc)

        exploit_log = str(finding.get("exploit_log") or "").strip()
        if include_poc and exploit_log and status.upper() == "CONFIRMED EXPLOIT":
            lines.append("")
            lines.append("Exploit output (tail):")
            lines.append(exploit_log[-2000:])

    return "\n".join(lines).rstrip() + "\n"

"""
Dual-channel finding feed.

Every completed scan writes two extra artifacts next to the regular
report formats:

- ``raw_findings.json`` — the machine-readable feed: every finding with
  its severity, confidence, PoC code, exploit log tail, reproduction
  data (differential status, reachability, consensus, economic
  estimate) and the suggested bounty-program route. This is the file
  the GitHub Actions board consumes (upload it as a workflow artifact).

- ``ai_drafted_feed.md`` — the human-readable feed: per-finding
  submission drafts drafted from the scan evidence (title, severity,
  description, impact, proof-of-concept, remediation). This is the
  file the Telegram console delivers to the operator chat.

The raw feed is written first and the drafted feed is derived from it,
so a draft can never contain a claim the raw evidence does not back.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger("web3guard.reports.dual_feed")

RAW_FILENAME = "raw_findings.json"
DRAFT_FILENAME = "ai_drafted_feed.md"

# Deterministic severity order for feed rendering.
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _finding_route(f: Any) -> str:
    """Suggested submission route for one finding.

    Confirmed exploits route to the platform-agnostic 'submit after
    manual verification' lane; everything else routes to internal
    review so look-alike findings never reach a program queue.
    """
    if str(getattr(f, "status", "")) == "CONFIRMED EXPLOIT":
        return "submit-after-manual-verification"
    return "internal-review"


def _raw_record(f: Any, target: str) -> dict[str, Any]:
    """One machine-readable record per finding."""
    metadata = dict(getattr(f, "metadata", {}) or {})
    differential = metadata.pop("differential", None)
    reachability = metadata.pop("reachability", None)
    consensus = metadata.pop("consensus", None)
    economic = metadata.pop("economic", None)
    record = {
        "schema": "web3guard.raw_finding/1",
        "fingerprint": getattr(f, "fingerprint", ""),
        "target": target or getattr(f, "target", ""),
        "language": getattr(f, "language", ""),
        "file": getattr(f, "file", ""),
        "function": getattr(f, "function", ""),
        "line_hint": getattr(f, "line_hint", ""),
        "category": getattr(f, "category", ""),
        "severity": str(getattr(f, "severity", "LOW")).upper(),
        "confidence": round(float(getattr(f, "confidence", 0.0) or 0.0), 4),
        "swc_id": getattr(f, "swc_id", ""),
        "status": getattr(f, "status", ""),
        "description": getattr(f, "description", ""),
        "reasoning": getattr(f, "reasoning", ""),
        "poc_code": getattr(f, "poc_code", ""),
        "exploit_log_tail": str(getattr(f, "exploit_log", "") or "")[-2000:],
        "gas_used": getattr(f, "gas_used", None),
        "reproduction": {
            "differential": differential,
            "reachability": reachability,
            "consensus": consensus,
            "economic": economic,
            "extra_metadata": metadata,
        },
        "suggested_route": _finding_route(f),
    }
    return record


def build_raw_feed(result: Any) -> dict[str, Any]:
    """Assemble the raw feed document for a :class:`ScanResult`."""
    records: list[dict[str, Any]] = []
    for t in getattr(result, "targets", []):
        for f in getattr(t, "findings", []):
            records.append(_raw_record(f, getattr(t, "target", "")))
    records.sort(key=lambda r: (_SEV_ORDER.get(r["severity"], 9), -r["confidence"]))
    cost = getattr(result, "cost_summary", {}) or {}
    return {
        "schema": "web3guard.raw_feed/1",
        "started_at": getattr(result, "started_at", ""),
        "finished_at": getattr(result, "finished_at", ""),
        "cost_summary": {
            "total_cost_usd": cost.get("total_cost_usd", 0.0),
            "calls": cost.get("calls", 0),
        },
        "counts": {
            "targets": len(getattr(result, "targets", []) or []),
            "findings": len(records),
            "confirmed": sum(1 for r in records if r["status"] == "CONFIRMED EXPLOIT"),
        },
        "metadata": dict(getattr(result, "metadata", {}) or {}),
        "findings": records,
    }


def _draft_one(rec: dict[str, Any]) -> str:
    """Render one AI-drafted submission section from a raw record."""
    repro = rec.get("reproduction") or {}
    lines: list[str] = []
    title = (
        f"{rec['severity']}: {rec['category'] or 'unknown category'} in "
        f"{Path(rec['file']).name}"
    )
    if rec.get("function"):
        title += f"::{rec['function']}"
    lines.append(f"## {title}")
    lines.append("")
    lines.append(f"- **Fingerprint:** `{rec['fingerprint'][:16]}`")
    lines.append(f"- **File:** `{rec['file']}`"
                 + (f" (lines {rec['line_hint']})" if rec.get("line_hint") else ""))
    lines.append(f"- **Language:** {rec['language']}")
    lines.append(f"- **Severity / confidence:** {rec['severity']} / "
                 f"{rec['confidence']:.2f}")
    lines.append(f"- **Verification status:** {rec['status']}")
    if rec.get("swc_id"):
        lines.append(f"- **SWC:** {rec['swc_id']}")
    diff = repro.get("differential")
    if diff:
        lines.append(f"- **Differential confirmation:** {diff}")
    reach = repro.get("reachability")
    if isinstance(reach, dict) and reach.get("verdict"):
        lines.append(f"- **Reachability:** {reach.get('verdict')}")
    cons = repro.get("consensus")
    if isinstance(cons, dict) and cons.get("sources"):
        lines.append(f"- **Corroborated by:** {', '.join(cons['sources'])}")
    lines.append(f"- **Suggested route:** {rec['suggested_route']}")
    lines.append("")
    lines.append("### Description")
    lines.append(rec.get("description") or "(no description produced)")
    lines.append("")
    reasoning = rec.get("reasoning")
    if reasoning and reasoning != rec.get("description"):
        lines.append("### Technical reasoning")
        lines.append(reasoning)
        lines.append("")
    if rec.get("poc_code"):
        lang_tag = rec.get("language") or "solidity"
        lines.append("### Proof of concept")
        lines.append(f"```{lang_tag}")
        lines.append(rec["poc_code"].rstrip())
        lines.append("```")
        lines.append("")
    if rec.get("exploit_log_tail"):
        lines.append("### Exploit output (tail)")
        lines.append("```text")
        lines.append(rec["exploit_log_tail"].rstrip())
        lines.append("```")
        lines.append("")
    return "\n".join(lines)


def build_ai_drafted_feed(raw: dict[str, Any]) -> str:
    """Render the human-readable markdown feed from the raw feed doc."""
    counts = raw.get("counts") or {}
    lines: list[str] = []
    lines.append("# Web3Guard — AI-drafted findings feed")
    lines.append("")
    lines.append(
        f"Scan window: `{raw.get('started_at', '?')} → {raw.get('finished_at', '?')}` · "
        f"findings: **{counts.get('findings', 0)}** · "
        f"confirmed exploits: **{counts.get('confirmed', 0)}** · "
        f"scan cost: ${float((raw.get('cost_summary') or {}).get('total_cost_usd', 0)):.4f}"
    )
    lines.append("")
    lines.append("> Drafted from `raw_findings.json`. Every claim below is "
                 "backed by the raw evidence in that file. Verify manually "
                 "before submitting to any program.")
    lines.append("")
    records = raw.get("findings") or []
    if not records:
        lines.append("_No findings in this scan._")
    for rec in records:
        lines.append(_draft_one(rec))
    return "\n".join(lines) + "\n"


def write_dual_feed(
    result: Any,
    out_dir: Path | str,
    *,
    formats: Sequence[str] = ("json", "md"),
) -> dict[str, Path]:
    """Write ``raw_findings.json`` and ``ai_drafted_feed.md`` under ``out_dir``.

    Returns ``{"raw": path, "draft": path}`` for the requested formats.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    raw = build_raw_feed(result)
    if "json" in formats:
        raw_path = out / RAW_FILENAME
        raw_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
        written["raw"] = raw_path
    if "md" in formats:
        draft_path = out / DRAFT_FILENAME
        draft_path.write_text(build_ai_drafted_feed(raw), encoding="utf-8")
        written["draft"] = draft_path
    LOGGER.info("dual feed written to %s (%d findings)", out, len(raw.get("findings", [])))
    return written

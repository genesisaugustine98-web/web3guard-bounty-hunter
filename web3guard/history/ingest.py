"""Audit report ingestion — markdown, plain text, and PDF (best effort).

Parses audit reports into structured :class:`AuditFinding` records:
title, severity, description, affected files/functions, auditor name, and
report date.

This is **heuristic extraction** — audit reports have no standard
format. Every finding carries a ``confidence`` score (0.0-1.0) and the
``raw_excerpt`` it was pulled from so a human (or a later phase) can
double-check the parse.

Format support:

- ``.md`` / ``.markdown`` — section-based parsing, fully supported.
- ``.txt`` — header-line based parsing, fully supported.
- ``.pdf`` — supported only when the ``pypdf`` package is installed. It
  is **not** a hard dependency: if it is missing, a clear
  :class:`PdfSupportError` is raised instead of a confusing traceback.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_SEVERITIES = ("critical", "high", "medium", "low", "informational", "info")

_SEVERITY_RE = re.compile(
    r"\b(critical|high|medium|low|informational|info)\b", re.IGNORECASE
)
_FINDING_ID_RE = re.compile(
    r"\[?\b([HMCLI])\s*[-–.]?\s*0*(\d{1,3})\b\]?", re.IGNORECASE
)
# Headings that look like findings: "## [H-01] Reentrancy in withdraw",
# "### H-1: Missing access control (High)", "#### M02 Title".
_MD_HEADING_RE = re.compile(r"^(#{1,4})\s+(.+?)\s*$")
# Plain-text finding headers: "H-01: Title", "HIGH - Title", "Finding 3 (Medium)".
_TXT_HEADER_RE = re.compile(
    r"^(?:\[?\s*(?:[HMCLI]\s*[-–.]?\s*\d{1,3}|critical|high|medium|low|informational)"
    r"\s*\]?[\s:.\-–—]+.+|finding\s+\d+[\s:.\-–—]+.+)$",
    re.IGNORECASE,
)
_FILE_RE = re.compile(
    r"(?:^|[\s\"'`(\[])"
    r"((?:contracts?|src|lib|test|tests|contracts-legacy)/[A-Za-z0-9_./-]*"
    r"\.(?:sol|vy|cairo|move|clar|func|rs|ts))"
    r"(?=[\s\"'`)\].,:;]|$)"
)
_ANY_FILE_RE = re.compile(
    r"`([A-Za-z0-9_./-]+\.(?:sol|vy|cairo|move|clar|func|rs|ts))`"
)
_FUNC_DEF_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_FUNC_CALL_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_DOTTED_FUNC_RE = re.compile(r"\b([A-Z][A-Za-z0-9_]*)\.([a-z_][A-Za-z0-9_]*)\s*\(")
# Hedged audit language: "may be at risk", "could be vulnerable", ... Auditors
# hedge real caveats; dropping them means a real warning never enters the
# pipeline. These become low-severity, low-confidence findings rather than
# being silently skipped — but only when the section also names code
# (a function or file), so generic "no potential issues" summaries don't
# turn into findings.
_HEDGED_RE = re.compile(
    r"\b(may be at risk|may be vulnerable|could be vulnerable|"
    r"could be at risk|might be vulnerable|might be exploitable|"
    r"potential vulnerability|potentially vulnerable|at risk of)\b",
    re.IGNORECASE,
)
_AUDITOR_RES = (
    re.compile(r"(?im)^(?:auditor|audit\s+firm|audited\s+by|prepared\s+by)\s*[:\-–—]\s*(.+)$"),
    re.compile(r"(?im)\baudit(?:ed)?\s+by\s+([A-Z][A-Za-z0-9 .&'-]{2,60})"),
)
_DATE_RE = re.compile(
    r"(?im)^(?:date|report\s+date|published)\s*[:\-–—]\s*(.+)$"
)
_ISO_DATE_RE = re.compile(r"\b(20\d{2}[-/.]\d{1,2}[-/.]\d{1,2})\b")

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
    "info": 0,
}


class PdfSupportError(ValueError):
    """Raised when a PDF report is requested but ``pypdf`` is not installed."""


@dataclass
class AuditFinding:
    """One heuristically extracted finding from an audit report."""

    id: str
    title: str
    severity: str  # critical|high|medium|low|informational|unknown
    description: str
    files: list[str] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    auditor: str = ""
    report_date: str = ""
    confidence: float = 0.5
    raw_excerpt: str = ""
    source_path: str = ""


@dataclass
class AuditReport:
    """A parsed audit report."""

    path: str
    title: str
    auditor: str
    report_date: str
    findings: list[AuditFinding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def parse_report(path: str | Path) -> AuditReport:
    """Parse an audit report file into structured findings.

    Raises:
        PdfSupportError: for ``.pdf`` input when ``pypdf`` is unavailable.
        ValueError: for unsupported extensions or unreadable files.
    """
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        text = _read_pdf(path)
        sections = _split_txt(text)
    elif suffix in (".md", ".markdown"):
        text = path.read_text(encoding="utf-8", errors="replace")
        sections = _split_markdown(text)
    elif suffix == ".txt":
        text = path.read_text(encoding="utf-8", errors="replace")
        sections = _split_txt(text)
    else:
        raise ValueError(
            f"Unsupported report format {suffix!r}; expected .md, .txt or .pdf"
        )

    auditor = _extract_auditor(text)
    report_date = _extract_date(text)
    findings: list[AuditFinding] = []
    notes: list[str] = []
    auto = 0
    for heading, body in sections:
        finding = _parse_section(heading, body, auditor, report_date, str(path))
        if finding is None:
            continue
        if finding.id.startswith("AUTO-"):
            auto += 1
            finding.id = f"FINDING-{auto:02d}"
        findings.append(finding)
    if not findings:
        notes.append(
            "No findings could be extracted — the report may use an "
            "unrecognised layout. Raw text was not discarded; check the "
            "source file directly."
        )
    title = _extract_title(text, path)
    return AuditReport(
        path=str(path),
        title=title,
        auditor=auditor,
        report_date=report_date,
        findings=findings,
        notes=notes,
    )


def _read_pdf(path: Path) -> str:
    """Extract text from a PDF, or raise a clear error if pypdf is missing."""
    try:
        import pypdf
    except ImportError as exc:
        raise PdfSupportError(
            "PDF audit reports need the optional 'pypdf' package, which is "
            "not installed in this environment. Either install pypdf "
            "(`pip install pypdf`) or convert the report to Markdown/text. "
            ".md and .txt reports are fully supported without it."
        ) from exc
    reader = pypdf.PdfReader(str(path))
    pages = []
    for page in reader.pages:
        try:
            pages.append(page.extract_text() or "")
        except Exception:  # noqa: BLE001 - one bad page must not kill the parse
            pages.append("")
    return "\n".join(pages)


def _split_markdown(text: str) -> list[tuple[str, str]]:
    """Split markdown into (heading, body) sections at ## / ### headings."""
    sections: list[tuple[str, str]] = []
    cur_heading = ""
    cur_body: list[str] = []
    seen_first = False
    for line in text.splitlines():
        m = _MD_HEADING_RE.match(line)
        if m and len(m.group(1)) >= 2:
            if seen_first:
                sections.append((cur_heading, "\n".join(cur_body).strip()))
            cur_heading = m.group(2).strip()
            cur_body = []
            seen_first = True
        elif seen_first:
            cur_body.append(line)
    if seen_first:
        sections.append((cur_heading, "\n".join(cur_body).strip()))
    return sections


def _split_txt(text: str) -> list[tuple[str, str]]:
    """Split plain text at finding-header lines."""
    sections: list[tuple[str, str]] = []
    cur_heading = ""
    cur_body: list[str] = []
    seen_first = False
    for line in text.splitlines():
        if _TXT_HEADER_RE.match(line.strip()):
            if seen_first:
                sections.append((cur_heading, "\n".join(cur_body).strip()))
            cur_heading = line.strip()
            cur_body = []
            seen_first = True
        elif seen_first:
            cur_body.append(line)
    if seen_first:
        sections.append((cur_heading, "\n".join(cur_body).strip()))
    if not seen_first:
        # No recognisable headers: treat the whole document as one section
        # and let _parse_section decide if it holds a finding.
        return [("", text.strip())]
    return sections


def _parse_section(
    heading: str,
    body: str,
    auditor: str,
    report_date: str,
    source_path: str,
) -> AuditFinding | None:
    """Turn one (heading, body) section into a finding, or None."""
    probe = f"{heading}\n{body[:800]}"
    sev_match = _SEVERITY_RE.search(probe)
    id_match = _FINDING_ID_RE.search(heading) or _FINDING_ID_RE.search(body[:200])
    hedged = False
    if not sev_match and not id_match:
        # Hedged audit language ("may be at risk") with no severity or ID:
        # keep it as a low-confidence finding rather than silently dropping
        # a real caveat — but only when the section names actual code, so
        # generic "no potential issues" summaries don't become findings.
        text = f"{heading}\n{body}"
        if _HEDGED_RE.search(probe) and (
            _extract_functions(text) or _extract_files(text)
        ):
            hedged = True
        else:
            return None

    severity = (
        "low"
        if hedged
        else (_normalise_severity(sev_match.group(1)) if sev_match else "unknown")
    )
    fid = _normalise_id(id_match) if id_match else "AUTO"
    title = _clean_title(heading, fid, severity)
    description = _first_paragraphs(body)
    files = _extract_files(f"{heading}\n{body}")
    functions = _extract_functions(f"{heading}\n{body}")
    excerpt = (f"{heading}\n{body[:1200]}").strip()

    confidence = 0.5
    if id_match:
        confidence += 0.2
    if sev_match:
        confidence += 0.15
    if files or functions:
        confidence += 0.1
    if hedged:
        # Hedged language is weak evidence by definition: cap it below
        # every confidently-parsed finding.
        confidence = min(confidence, 0.3)
    confidence = min(confidence, 0.95)

    return AuditFinding(
        id=fid,
        title=title,
        severity=severity,
        description=description,
        files=files,
        functions=functions,
        auditor=auditor,
        report_date=report_date,
        confidence=round(confidence, 2),
        raw_excerpt=excerpt,
        source_path=source_path,
    )


def _normalise_severity(raw: str) -> str:
    raw = raw.lower()
    return "informational" if raw == "info" else raw


def _normalise_id(match: re.Match[str]) -> str:
    letter = match.group(1).upper()
    num = int(match.group(2))
    return f"{letter}-{num:02d}"


def _clean_title(heading: str, fid: str, severity: str) -> str:
    title = heading.strip()
    title = re.sub(r"^\[?[HMCLI]\s*[-–.]?\s*\d{1,3}\]?\s*[:\-–—]?\s*", "", title, flags=re.IGNORECASE)
    title = re.sub(
        rf"\(\s*{re.escape(severity)}\s*\)\s*$", "", title, flags=re.IGNORECASE
    ).strip()
    title = re.sub(r"^\*\*|\*\*$", "", title).strip()
    return title or f"Finding {fid}"


def _first_paragraphs(body: str, limit: int = 3) -> str:
    paras = [p.strip() for p in re.split(r"\n\s*\n", body) if p.strip()]
    paras = [p for p in paras if not p.startswith(("#", "|", "-", "* ", "1. "))]
    return "\n\n".join(paras[:limit])


def _extract_files(text: str) -> list[str]:
    found: list[str] = []
    for pattern in (_FILE_RE, _ANY_FILE_RE):
        for m in pattern.finditer(text):
            name = m.group(1).strip().rstrip(".,;:")
            if name not in found:
                found.append(name)
    return found


def _extract_functions(text: str) -> list[str]:
    found: list[str] = []
    for m in _FUNC_DEF_RE.finditer(text):
        if m.group(1) not in found:
            found.append(m.group(1))
    for m in _FUNC_CALL_RE.finditer(text):
        if m.group(1) not in found and len(m.group(1)) > 2:
            found.append(m.group(1))
    for m in _DOTTED_FUNC_RE.finditer(text):
        if m.group(2) not in found:
            found.append(m.group(2))
    # Common Solidity keywords are not functions.
    noise = {"if", "for", "while", "require", "revert", "return", "emit"}
    return [f for f in found if f not in noise]


def _extract_auditor(text: str) -> str:
    for rx in _AUDITOR_RES:
        m = rx.search(text[:4000])
        if m:
            return m.group(1).strip().rstrip(".")
    return ""


def _extract_date(text: str) -> str:
    m = _DATE_RE.search(text[:4000])
    if m:
        return m.group(1).strip()
    m = _ISO_DATE_RE.search(text[:4000])
    return m.group(1) if m else ""


def _extract_title(text: str, path: Path) -> str:
    for line in text.splitlines()[:10]:
        m = re.match(r"^#\s+(.+?)\s*$", line.strip())
        if m:
            return m.group(1).strip()
    return path.stem.replace("_", " ").replace("-", " ").strip().title()

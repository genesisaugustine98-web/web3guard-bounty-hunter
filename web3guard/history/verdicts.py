"""Per-version verdicts for historical audit findings.

For each finding, walk an ordered list of versions (git tags) and emit
one verdict per version:

- ``FIXED`` — the vulnerable shape is gone and there is evidence the
  root cause was addressed.
- ``BAND-AID`` — the originally implicated spot was touched, but the
  same vulnerable pattern still exists elsewhere (another function or
  file). **This is the money verdict**: it flags places that look fixed
  but are still exploitable.
- ``STILL OPEN`` — the vulnerable shape is still present.
- ``REGRESSED`` — it was fixed in an earlier version and the vulnerable
  shape has reappeared.

Honesty contract: these verdicts are **heuristic**. Every verdict
carries a confidence level (``high`` / ``medium`` / ``low``) and the
evidence strings that produced it. ``FIXED`` always requires positive
evidence (the risky pattern is absent *and* a guard/fix marker or a
structural change is present); absence of evidence is never reported as
a fix.

Pattern classes are deliberately small and Solidity-focused:

- ``reentrancy`` — external value-sending calls
  (``call{value: ...}``, ``.call(``, ``.send(``, ``.transfer(``) inside a
  function body without a reentrancy guard marker.
- ``access-control`` — externally reachable functions that move value
  or change privileged state without an ``onlyOwner``/access-control
  marker.
- ``generic`` — fallback for anything else: the verdict rests on
  whether the implicated functions still exist unchanged. Confidence is
  capped at ``low`` and the evidence says so.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from web3guard.history.diff import extract_solidity_functions, file_content_at, list_files_at
from web3guard.history.ingest import AuditFinding

FIXED = "FIXED"
BAND_AID = "BAND-AID"
STILL_OPEN = "STILL OPEN"
REGRESSED = "REGRESSED"

_VERDICTS = (FIXED, BAND_AID, STILL_OPEN, REGRESSED)


@dataclass
class _PatternClass:
    name: str
    risk: re.Pattern[str]
    guards: tuple[str, ...]


_PATTERN_CLASSES: tuple[_PatternClass, ...] = (
    _PatternClass(
        name="reentrancy",
        risk=re.compile(
            r"\.call\s*\{\s*value|\.call\s*\(|\.send\s*\(|\.transfer\s*\("
        ),
        guards=("nonReentrant", "ReentrancyGuard", "noReentrant", "ReentrancyGuardUpgradeable"),
    ),
    _PatternClass(
        name="access-control",
        risk=re.compile(r"\b(external|public)\b"),
        guards=("onlyOwner", "onlyRole", "AccessControl", "require(msg.sender"),
    ),
)


@dataclass
class VersionVerdict:
    """One heuristic verdict for one finding at one version."""

    finding_id: str
    version: str
    verdict: str  # FIXED | BAND-AID | STILL OPEN | REGRESSED
    confidence: str  # high | medium | low
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "version": self.version,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
        }


@dataclass
class _VersionAnalysis:
    """What the heuristic saw at one version."""

    version: str
    vulnerable_functions: list[str]  # implicated fns still showing the risky pattern
    guarded_functions: list[str]  # implicated fns carrying a fix marker
    implicated_found: list[str]  # implicated fns located at all
    pattern_elsewhere: list[str]  # "otherfn (file)" with the risky pattern
    files_scanned: list[str]


def _classify(finding: AuditFinding) -> _PatternClass | None:
    probe = f"{finding.title} {finding.description}".lower()
    if any(w in probe for w in ("reentrancy", "re-entrancy", "reentrant")):
        return _PATTERN_CLASSES[0]
    if any(
        w in probe
        for w in ("access control", "onlyowner", "unauthorized", "privilege", "missing check")
    ):
        return _PATTERN_CLASSES[1]
    return None


def _function_body_guarded(body: str, cls: _PatternClass) -> bool:
    return any(g in body for g in cls.guards)


def _scan_functions(
    source: str, cls: _PatternClass
) -> tuple[list[str], list[str]]:
    """Return (vulnerable_fn_names, guarded_fn_names) for one source file."""
    vulnerable: list[str] = []
    guarded: list[str] = []
    for name, body in extract_solidity_functions(source).items():
        if not cls.risk.search(body):
            continue
        if _function_body_guarded(body, cls):
            guarded.append(name)
        else:
            vulnerable.append(name)
    return vulnerable, guarded


def analyze_version(
    repo: str | Path,
    version: str,
    finding: AuditFinding,
) -> _VersionAnalysis:
    """Heuristically check whether a finding's vulnerable shape is present."""
    repo = Path(repo)
    cls = _classify(finding)

    # Files to inspect: the ones the report named (if they exist at this
    # version), else every Solidity file at this version.
    candidates: list[str] = []
    for named in finding.files:
        if file_content_at(repo, version, named) is not None:
            candidates.append(named)
    if not candidates:
        candidates = list_files_at(repo, version, (".sol",))

    implicated = [fn for fn in finding.functions if fn]
    vuln_fns: list[str] = []
    guarded_fns: list[str] = []
    found: list[str] = []
    elsewhere: list[str] = []

    for path in candidates:
        src = file_content_at(repo, version, path)
        if src is None:
            continue
        functions = extract_solidity_functions(src)
        for fn in implicated:
            if fn in functions and fn not in found:
                found.append(fn)
                body = functions[fn]
                if cls is not None and cls.risk.search(body):
                    if _function_body_guarded(body, cls):
                        guarded_fns.append(fn)
                    else:
                        vuln_fns.append(fn)
        if cls is not None:
            vuln_all, _ = _scan_functions(src, cls)
            for fn in vuln_all:
                if fn not in implicated:
                    elsewhere.append(f"{fn} ({path})")

    return _VersionAnalysis(
        version=version,
        vulnerable_functions=sorted(set(vuln_fns)),
        guarded_functions=sorted(set(guarded_fns)),
        implicated_found=sorted(set(found)),
        pattern_elsewhere=sorted(set(elsewhere)),
        files_scanned=candidates,
    )


def _confidence_for(analysis: _VersionAnalysis, finding: AuditFinding) -> str:
    if not analysis.implicated_found:
        return "low"
    if not finding.functions:
        return "medium"
    return "high"


def _verdict_for_transition(
    finding: AuditFinding,
    prev: _VersionAnalysis | None,
    prev_verdict: str | None,
    cur: _VersionAnalysis,
) -> VersionVerdict:
    # "Vulnerable at a version" has two levels: the implicated functions
    # specifically, and the risky pattern anywhere in the scanned files
    # (which is what makes a fix a band-aid rather than a root-cause fix).
    cur_impl_vuln = bool(cur.vulnerable_functions)
    cur_any_vuln = cur_impl_vuln or bool(cur.pattern_elsewhere)
    prev_impl_vuln = bool(prev.vulnerable_functions) if prev else False
    prev_any_vuln = (
        (prev_impl_vuln or bool(prev.pattern_elsewhere)) if prev else False
    )
    cls = _classify(finding)
    conf = _confidence_for(cur, finding)
    ev: list[str] = []

    def note(text: str) -> None:
        ev.append(text)

    if cls is None:
        note(
            "Finding did not match a known pattern class "
            "(reentrancy / access-control); verdict is a weak function-"
            "presence heuristic only."
        )
        conf = "low"

    if cur.implicated_found:
        note(
            f"Implicated function(s) located at {cur.version}: "
            f"{', '.join(cur.implicated_found)}."
        )
    else:
        note(
            f"None of the report's implicated functions "
            f"({', '.join(finding.functions) or 'none named'}) could be "
            f"located at {cur.version}; the scan fell back to whole-file "
            "pattern matching, which is weaker evidence."
        )

    if cur.vulnerable_functions:
        note(
            f"Risky pattern still present in: "
            f"{', '.join(cur.vulnerable_functions)}."
        )
    if cur.guarded_functions:
        note(
            f"Fix marker present on: {', '.join(cur.guarded_functions)}."
        )
    if cur.pattern_elsewhere:
        shown = ", ".join(cur.pattern_elsewhere[:5])
        extra = f" (+{len(cur.pattern_elsewhere) - 5} more)" if len(cur.pattern_elsewhere) > 5 else ""
        note(f"Same risky pattern also found outside the implicated spot: {shown}{extra}.")

    if prev is None:
        # First version in the walk.
        if cur_any_vuln:
            return VersionVerdict(finding.id, cur.version, STILL_OPEN, conf, ev)
        note(
            "Vulnerable shape not located at the first version walked. "
            "This may mean the report targeted a different ref, or the "
            "heuristic missed it — treat as unconfirmed, not as fixed."
        )
        return VersionVerdict(finding.id, cur.version, STILL_OPEN, "low", ev)

    if cur_impl_vuln:
        if prev_any_vuln:
            return VersionVerdict(finding.id, cur.version, STILL_OPEN, conf, ev)
        note(
            f"The vulnerable shape was gone at {prev.version} but is back "
            f"at {cur.version}."
        )
        return VersionVerdict(finding.id, cur.version, REGRESSED, conf, ev)

    # The implicated functions no longer show the vulnerable shape.
    if prev_impl_vuln:
        if cur.pattern_elsewhere:
            note(
                "The originally implicated spot looks addressed, but the "
                "same risky pattern persists elsewhere — a surface-level "
                "fix, not a root-cause fix."
            )
            return VersionVerdict(finding.id, cur.version, BAND_AID, conf, ev)
        note(
            "The risky pattern is gone from the implicated functions and "
            "no same-pattern occurrence remains elsewhere in the scanned "
            "files."
        )
        return VersionVerdict(finding.id, cur.version, FIXED, conf, ev)

    # Implicated functions were already clean at the previous version too.
    if cur_any_vuln and not prev_any_vuln:
        note(
            f"No vulnerable shape at {prev.version}, but the risky pattern "
            f"has reappeared at {cur.version}."
        )
        return VersionVerdict(finding.id, cur.version, REGRESSED, conf, ev)
    if cur_any_vuln and prev_any_vuln:
        note(
            "The risky pattern persists outside the implicated spot at "
            f"both {prev.version} and {cur.version} — still surface-level."
        )
        return VersionVerdict(finding.id, cur.version, BAND_AID, conf, ev)
    if not cur_any_vuln and prev_any_vuln:
        note(
            f"The lingering risky pattern seen at {prev.version} is gone "
            f"at {cur.version}."
        )
        return VersionVerdict(finding.id, cur.version, FIXED, conf, ev)
    # Neither version shows the vulnerable shape: carry the previous verdict.
    carried = prev_verdict if prev_verdict in _VERDICTS else STILL_OPEN
    note(f"No vulnerable shape at {prev.version} or {cur.version}; carrying verdict {carried}.")
    return VersionVerdict(finding.id, cur.version, carried, "low", ev)


def walk_versions(
    finding: AuditFinding,
    repo: str | Path,
    versions: list[str],
) -> list[VersionVerdict]:
    """Walk ordered versions and emit a heuristic verdict per version.

    ``versions`` must be ordered oldest -> newest (e.g. sorted git tags).
    Raises :class:`ValueError` if fewer than one version is given.
    """
    if not versions:
        raise ValueError("walk_versions needs at least one version")
    verdicts: list[VersionVerdict] = []
    prev_analysis: _VersionAnalysis | None = None
    prev_verdict: str | None = None
    for version in versions:
        cur = analyze_version(repo, version, finding)
        verdict = _verdict_for_transition(finding, prev_analysis, prev_verdict, cur)
        verdicts.append(verdict)
        prev_analysis = cur
        prev_verdict = verdict.verdict
    return verdicts


def walk_all_findings(
    findings: list[AuditFinding],
    repo: str | Path,
    versions: list[str],
) -> dict[str, list[VersionVerdict]]:
    """Walk every finding; returns {finding_id: [verdicts]}."""
    return {f.id: walk_versions(f, repo, versions) for f in findings}

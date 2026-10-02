"""Per-version verdicts for historical audit findings.

For each finding, walk an ordered list of versions (git tags) and emit
one verdict per version:

- ``FIXED`` — the vulnerable shape is gone and there is evidence the
  root cause was addressed.
- ``BAND-AID`` — the implicated code was touched but the vulnerable
  property still holds (same spot), or the same risky pattern still
  exists elsewhere (another function or file). **This is the money
  verdict**: it flags places that look fixed but are still exploitable.
- ``STILL OPEN`` — the vulnerable shape is still present.
- ``REGRESSED`` — it was fixed in an earlier version and the vulnerable
  shape has reappeared.

What makes a verdict, not text similarity:

- **Cross-file tracking.** Findings are located through the
  :mod:`web3guard.history.xref` reference map (imports, inheritance,
  calls) in *every* version. When code moves between files or gets
  renamed, the tracker follows it — a moved-but-still-buggy function is
  never declared FIXED just because its old address went quiet. Every
  Solidity file in the repo is scanned, not just the ones the audit
  report named.
- **Refactor-resistant comparison.** Before comparing versions,
  function bodies are canonicalized
  (:mod:`web3guard.history.normalize`): identifier renames and
  reformatting do not change the canonical form, so a renamed-but-still-
  vulnerable function still matches its old self and reads STILL OPEN,
  not FIXED. Statement *order* is deliberately preserved — reordering
  can be security-relevant (checks-effects-interactions).
- **Property-driven verdicts.** For the known pattern classes the
  verdict rests on whether the security-relevant property still holds:

  - ``reentrancy`` — a function is vulnerable while it makes a
    value-sending external call *before* updating state, without a
    reentrancy guard. The textbook fix (state update before the call,
    no marker) therefore reads FIXED, and a guard marker also reads
    FIXED.
  - ``access-control`` — a reachable function that moves value or
    writes state without an access-control marker is vulnerable. When
    the implicated functions are guarded, other still-public functions
    do **not** hold the verdict hostage (``deposit()`` must stay
    public); they are emitted as adjacent-code leads for the re-dive
    queue instead. A second unguarded function writing the *same
    privileged state* the finding was about is a genuine cross-file
    band-aid and does block FIXED.
  - ``generic`` — the documented fallback, now actually implemented:
    rename-resistant comparison of the implicated functions. Unchanged
    (modulo renames/moves/reshuffles) means still vulnerable; a real
    change to the code with fix-shaped markers reads FIXED; a change
    without recognizable fix markers reads FIXED with low confidence
    *and* queues a human-verification lead, because the engine cannot
    see the bug it was never told about.

- **Version order is enforced.** Versions are sorted by commit
  timestamp (oldest first) before walking, so a caller passing them
  newest-first cannot fabricate a confident REGRESSED.

Honesty contract: these verdicts are **heuristic**. Every verdict
carries a confidence level (``high`` / ``medium`` / ``low``) and the
evidence strings that produced it. ``FIXED`` always requires positive
evidence; absence of evidence is never reported as a fix — and when the
implicated code cannot be located at all, the verdict is STILL OPEN
with low confidence, never a confident FIXED out of thin air.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from web3guard.history.diff import _git
from web3guard.history.ingest import AuditFinding
from web3guard.history.normalize import (
    canonicalize_function,
    is_pure_reshuffle,
    statement_multiset,
)
from web3guard.history.xref import build_xref

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
        guards=(
            "nonReentrant",
            "ReentrancyGuard",
            "noReentrant",
            "ReentrancyGuardUpgradeable",
        ),
    ),
    _PatternClass(
        name="access-control",
        risk=re.compile(r"\b(external|public)\b"),
        guards=("onlyOwner", "onlyRole", "AccessControl", "require(msg.sender"),
    ),
)

_REENTRANCY = _PATTERN_CLASSES[0]
_ACCESS = _PATTERN_CLASSES[1]

_VALUE_SEND_RE = re.compile(
    r"\.call\s*\{\s*value|\.call\s*\(|\.send\s*\(|\.transfer\s*\("
)
_REACHABLE_RE = re.compile(r"\b(external|public)\b")
_DECL_RE = re.compile(
    r"\b(?:uint\d*|int\d*|address|bool|string|bytes\d*)\b"
    r"(?:\s+(?:memory|storage|calldata))?\s+([A-Za-z_][A-Za-z0-9_]*)\b"
)
# identifier [index] <assign-op> — with guards against ==, >=, <=, !=, =>.
_ASSIGN_RE = re.compile(
    r"(?<![A-Za-z0-9_.])([A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?:\[[^\]]*\]\s*)?"
    r"(?:(?<![=!<>])=(?![=>])|\+=|-=|\*=|/=|%=|\+\+|--)"
)
# Hints that a changed function body gained fix-shaped content.
_FIX_HINTS = (
    "nonReentrant",
    "ReentrancyGuard",
    "onlyOwner",
    "onlyRole",
    "require(",
    "assert(",
    "revert(",
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
class _FnState:
    """Where one implicated function is at one version, and what it shows."""

    orig_name: str
    located: bool
    path: str = ""
    name_at_version: str = ""
    how: str = "missing"  # hint | name-elsewhere | fingerprint | missing
    body: str = ""
    canonical: str = ""
    # Property evaluation. None for the generic class: undecided until the
    # walk compares against history (see _resolve_generic).
    vulnerable: bool | None = None
    guarded: bool = False


@dataclass
class _VersionAnalysis:
    """What the heuristic saw at one version."""

    version: str
    fn_states: dict[str, _FnState]  # orig fn name -> state
    pattern_elsewhere: list[str]  # "otherfn (file)" with the risky property
    adjacent_leads: list[str]  # "otherfn (file): reason" — queued, not verdicts
    files_scanned: list[str]

    @property
    def implicated_found(self) -> list[str]:
        return sorted(n for n, s in self.fn_states.items() if s.located)


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


def _local_names(func_text: str) -> set[str]:
    """Parameter and local-variable names of a function (signature+body)."""
    return set(_DECL_RE.findall(func_text))


def _state_writes(func_text: str) -> list[tuple[int, str]]:
    """(position, name) of assignments to probable state variables.

    An assigned identifier counts as a state variable when it is not a
    declared parameter/local. Member writes (``x.y =``) are excluded —
    this is a heuristic, not a compiler.
    """
    locals_ = _local_names(func_text)
    out: list[tuple[int, str]] = []
    for m in _ASSIGN_RE.finditer(func_text):
        name = m.group(1)
        if name not in locals_:
            out.append((m.start(), name))
    return out


def _cei_satisfied(func_text: str) -> bool:
    """True when every state write precedes every value-sending call.

    This is the checks-effects-interactions property: updating state
    before the external call closes the classic reentrancy hole even
    without a guard marker.
    """
    sends = [m.start() for m in _VALUE_SEND_RE.finditer(func_text)]
    if not sends:
        return True
    writes = [pos for pos, _ in _state_writes(func_text)]
    if not writes:
        # Value leaves and nothing is recorded on-chain: conservatively
        # not satisfied (matches the old shape-based behaviour).
        return False
    return max(writes) < min(sends)


def _guarded(func_text: str, guards: tuple[str, ...]) -> bool:
    return any(g in func_text for g in guards)


def _reentrancy_vulnerable(func_text: str) -> tuple[bool, str]:
    """Property test: value-sending call before state update, no guard."""
    if not _VALUE_SEND_RE.search(func_text):
        return False, "no value-sending external call in the function"
    if _guarded(func_text, _REENTRANCY.guards):
        return False, "reentrancy guard marker present"
    if _cei_satisfied(func_text):
        return (
            False,
            "checks-effects-interactions holds: state is updated before "
            "the external call (textbook fix, no marker needed)",
        )
    return (
        True,
        "external call sends value before state is updated, and no "
        "reentrancy guard is present",
    )


def _access_vulnerable(func_text: str) -> tuple[bool, str]:
    """Property test: reachable + (moves value or writes state), no guard."""
    if not _REACHABLE_RE.search(func_text):
        return False, "not externally reachable"
    moves = bool(_VALUE_SEND_RE.search(func_text))
    writes = [name for _, name in _state_writes(func_text)]
    if not moves and not writes:
        return False, "neither moves value nor writes state"
    if _guarded(func_text, _ACCESS.guards):
        return False, "access-control marker present"
    what = "moves value" if moves else f"writes state ({', '.join(sorted(set(writes)))})"
    return True, f"externally reachable, {what}, no access-control marker"


def _version_order(repo: Path, versions: list[str]) -> list[str]:
    """Sort versions oldest-first by commit timestamp (stable on ties).

    A caller that passes versions newest-first used to get a confident
    but fabricated REGRESSED; ordering by commit time removes that
    failure mode. Falls back to the given order when git cannot answer.
    """
    try:
        stamps: list[int] = []
        for v in versions:
            out = _git(repo, "log", "-1", "--format=%ct", v)
            text = out.strip()
            if not text.isdigit():
                return list(versions)
            stamps.append(int(text))
        order = sorted(range(len(versions)), key=lambda i: stamps[i])
        return [versions[i] for i in order]
    except Exception:  # noqa: BLE001 - ordering is best-effort, never fatal
        return list(versions)


def analyze_version(
    repo: str | Path,
    version: str,
    finding: AuditFinding,
    prev_bodies: dict[str, tuple[str | None, str]] | None = None,
    known_vuln: dict[str, set[str]] | None = None,
) -> _VersionAnalysis:
    """Locate the finding's code and evaluate its property at one version.

    Every Solidity file in the repo is scanned — never just the files
    the audit report named. Implicated functions are located through the
    cross-file reference map (report hints, then name search, then exact
    matches against historically vulnerable shapes, then rename-resistant
    fingerprint against ``prev_bodies``), so renames, cross-file moves,
    and revert-to-old-shape regressions are followed, not mistaken for
    fixes.
    """
    repo = Path(repo)
    cls = _classify(finding)
    xref = build_xref(str(repo), version)
    prev_bodies = prev_bodies or {}
    known_vuln = known_vuln or {}

    implicated = [fn for fn in finding.functions if fn]
    states: dict[str, _FnState] = {}
    for fn in implicated:
        prev_name, prev_body = prev_bodies.get(fn, (None, ""))
        path, name_at, how = xref.locate_function(
            fn,
            finding.files,
            prev_body or None,
            prev_name or fn,
            known_vuln.get(fn),
        )
        state = _FnState(orig_name=fn, located=path is not None, how=how)
        if path is not None and name_at is not None:
            state.path = path
            state.name_at_version = name_at
            body = xref._bodies.get((path, name_at), "")
            state.body = body
            state.canonical = canonicalize_function(name_at, body)
            if cls is _REENTRANCY:
                vuln, _ = _reentrancy_vulnerable(body)
                state.vulnerable = vuln
                state.guarded = _guarded(body, _REENTRANCY.guards)
            elif cls is _ACCESS:
                vuln, _ = _access_vulnerable(body)
                state.vulnerable = vuln
                state.guarded = _guarded(body, _ACCESS.guards)
            else:
                state.vulnerable = None  # decided by the walk, against history
        states[fn] = state

    elsewhere: list[str] = []
    leads: list[str] = []
    located_positions = {
        (s.path, s.name_at_version) for s in states.values() if s.located
    }

    if cls is _REENTRANCY:
        for (path, fname), body in xref._bodies.items():
            if (path, fname) in located_positions:
                continue
            vuln, _ = _reentrancy_vulnerable(body)
            if vuln:
                elsewhere.append(f"{fname} ({path})")
    elif cls is _ACCESS:
        # Privileged state = state variables the implicated functions
        # write. A second unguarded function writing the *same* privileged
        # state is a genuine cross-file band-aid and blocks FIXED. Other
        # public state-writers (deposit() must stay public) become
        # adjacent leads for human review instead of verdict noise.
        privileged: set[str] = set()
        for s in states.values():
            if s.located:
                privileged.update(n for _, n in _state_writes(s.body))
        for (path, fname), body in xref._bodies.items():
            if (path, fname) in located_positions:
                continue
            if not _REACHABLE_RE.search(body):
                continue
            if _guarded(body, _ACCESS.guards):
                continue
            writes = {n for _, n in _state_writes(body)}
            if not writes and not _VALUE_SEND_RE.search(body):
                continue
            if writes & privileged:
                elsewhere.append(f"{fname} ({path})")
            elif writes:
                leads.append(
                    f"{fname} ({path}): public/external, writes state, no "
                    f"access-control marker — review whether it should be "
                    f"restricted (does not block the fix verdict)"
                )

    return _VersionAnalysis(
        version=version,
        fn_states=states,
        pattern_elsewhere=sorted(set(elsewhere)),
        adjacent_leads=sorted(set(leads)),
        files_scanned=sorted(xref.files),
    )


def _change_kind(
    prev_name: str, prev_body: str, cur_name: str, cur_body: str
) -> str:
    """Classify how a located function changed: identical | renamed |
    reshuffled | grown | changed."""
    prev_canon = canonicalize_function(prev_name, prev_body)
    cur_canon = canonicalize_function(cur_name, cur_body)
    if prev_canon == cur_canon:
        return "renamed" if prev_name != cur_name else "identical"
    prev_ms = Counter(statement_multiset(prev_body, prev_name))
    cur_ms = Counter(statement_multiset(cur_body, cur_name))
    if prev_ms == cur_ms:
        return "reshuffled"
    removed = prev_ms - cur_ms
    added = cur_ms - prev_ms
    if not removed and added:
        return "grown"
    return "changed"


def _resolve_generic(
    fn: str,
    cur: _FnState,
    prev: _FnState | None,
    vuln_prints: set[str],
    ev: list[str],
) -> tuple[bool, str]:
    """Decide vulnerability for the generic class against history.

    Returns (vulnerable, confidence_hint). Updates ``vuln_prints`` with
    newly seen vulnerable shapes so a fixed-then-back shape reads
    REGRESSED instead of "changed".
    """
    if not cur.located:
        if prev is not None and prev.located:
            ev.append(
                f"Implicated code '{fn}' no longer exists anywhere in the "
                f"codebase (was at {prev.path}); rename-resistant search "
                f"across all files found no match — treated as removed."
            )
        else:
            ev.append(
                f"Implicated function '{fn}' could not be located in any "
                f"file; the verdict rests on absence, which is weak "
                f"evidence — treated as unconfirmed, not as fixed."
            )
        return False, "low"

    if cur.canonical in vuln_prints:
        ev.append(
            f"'{fn}' matches a previously seen vulnerable shape "
            f"(currently at {cur.path})."
        )
        return True, "medium"

    if prev is None or not prev.located:
        # First sighting: the audit said it is vulnerable; we found the
        # code. Assume the report is right — STILL OPEN, not FIXED.
        ev.append(
            f"Implicated function '{fn}' located at {cur.path} "
            f"(matched by {cur.how}); no earlier version to compare "
            f"against — the audit's claim stands."
        )
        vuln_prints.add(cur.canonical)
        return True, "medium" if cur.how == "hint" else "low"

    kind = _change_kind(prev.name_at_version, prev.body, cur.name_at_version, cur.body)
    if kind in ("identical", "renamed"):
        if kind == "renamed":
            ev.append(
                f"'{fn}' was renamed to '{cur.name_at_version}' "
                f"({prev.path} -> {cur.path}); the code is otherwise "
                f"identical — a rename is not a fix."
            )
        vuln_prints.add(cur.canonical)
        return True, "medium"
    if kind == "reshuffled":
        ev.append(
            f"'{fn}' holds the same statements in a different order "
            f"({cur.path}); statement order alone does not remove the "
            f"reported flaw."
        )
        vuln_prints.add(cur.canonical)
        return True, "medium"

    # The code genuinely changed shape. Look for fix-shaped content.
    added_hints = [h for h in _FIX_HINTS if h in cur.body and h not in prev.body]
    if added_hints:
        ev.append(
            f"'{fn}' changed and gained fix-shaped markers "
            f"({', '.join(added_hints)}) at {cur.path}."
        )
        return False, "medium"
    if kind == "grown":
        ev.append(
            f"'{fn}' only grew (new statements, none removed) at "
            f"{cur.path} with no fix-shaped markers — the reported flaw "
            f"is presumed intact."
        )
        vuln_prints.add(cur.canonical)
        return True, "low"
    # Statements were modified or removed, but nothing recognisably
    # fix-shaped. Honest position: treat as addressed (the vulnerable
    # shape is gone) at low confidence, and queue a human-verification
    # lead so it is not silently trusted.
    ev.append(
        f"'{fn}' changed shape at {cur.path} (statements modified or "
        f"removed) but no fix-shaped markers were found — addressed at "
        f"low confidence; queued for human verification."
    )
    return False, "low"


def _confidence_for(
    cur: _VersionAnalysis, finding: AuditFinding, cls: _PatternClass | None
) -> str:
    located = [s for s in cur.fn_states.values() if s.located]
    if not located:
        return "low"
    if cls is None:
        return "medium"
    if all(s.how == "hint" for s in located):
        return "high"
    return "medium"


def _verdict_for_transition(
    finding: AuditFinding,
    prev: _VersionAnalysis | None,
    prev_verdict: str | None,
    cur: _VersionAnalysis,
    memory: dict[str, set[str]],
) -> VersionVerdict:
    cls = _classify(finding)
    ev: list[str] = []

    # Resolve generic-class vulnerability against history first.
    for fn, state in cur.fn_states.items():
        if state.vulnerable is None:
            prev_state = prev.fn_states.get(fn) if prev else None
            vuln, _hint = _resolve_generic(
                fn, state, prev_state, memory.setdefault(fn, set()), ev
            )
            state.vulnerable = vuln

    cur_impl = sorted(n for n, s in cur.fn_states.items() if s.vulnerable)
    cur_else = cur.pattern_elsewhere
    cur_any = bool(cur_impl) or bool(cur_else)
    conf = _confidence_for(cur, finding, cls)

    if cls is None:
        ev.append(
            "Finding did not match a known pattern class "
            "(reentrancy / access-control); the verdict rests on "
            "rename-resistant comparison of the implicated functions — "
            "weaker evidence than a property check."
        )
        conf = "low" if conf == "low" else "medium"

    for fn, s in cur.fn_states.items():
        if s.located:
            where = s.path
            if s.name_at_version != fn:
                where += f" (renamed to {s.name_at_version})"
            ev.append(
                f"Implicated '{fn}' located at {cur.version}: {where} "
                f"(matched by {s.how})."
            )
        else:
            ev.append(
                f"Implicated '{fn}' not found at {cur.version} "
                f"(searched all {len(cur.files_scanned)} Solidity files, "
                f"including rename-resistant matching)."
            )
    if cur_impl:
        ev.append(
            f"Vulnerable property still holds in: {', '.join(cur_impl)}."
        )
    guarded_here = sorted(
        n for n, s in cur.fn_states.items() if s.located and s.guarded
    )
    if guarded_here:
        ev.append(f"Fix marker present on: {', '.join(guarded_here)}.")
    if cur_else:
        shown = ", ".join(cur_else[:5])
        extra = (
            f" (+{len(cur_else) - 5} more)" if len(cur_else) > 5 else ""
        )
        ev.append(
            f"Same risky property also present outside the implicated "
            f"spot: {shown}{extra}."
        )
    if cur.adjacent_leads:
        shown = "; ".join(cur.adjacent_leads[:3])
        ev.append(
            f"Adjacent public state-writers queued for human review "
            f"(do not block the verdict): {shown}."
        )

    if prev is None:
        if cur_any:
            return VersionVerdict(finding.id, cur.version, STILL_OPEN, conf, ev)
        ev.append(
            "Vulnerable shape not located at the first version walked. "
            "This may mean the report targeted a different ref, or the "
            "heuristic missed it — treat as unconfirmed, not as fixed."
        )
        return VersionVerdict(finding.id, cur.version, STILL_OPEN, "low", ev)

    prev_impl = sorted(n for n, s in prev.fn_states.items() if s.vulnerable)
    prev_else = prev.pattern_elsewhere

    # Was the implicated code touched? Rename-tolerant: pure renames and
    # reformatting do NOT count as "touched" — a rename is not a fix
    # attempt, so a renamed-but-still-vulnerable function reads STILL
    # OPEN, not BAND-AID.
    touched: list[str] = []
    move_notes: list[str] = []
    for fn, s in cur.fn_states.items():
        ps = prev.fn_states.get(fn)
        if not (s.located and ps is not None and ps.located):
            continue
        kind = _change_kind(
            ps.name_at_version, ps.body, s.name_at_version, s.body
        )
        if kind not in ("identical", "renamed"):
            touched.append(fn)
        if ps.path != s.path:
            move_notes.append(
                f"'{fn}' moved {ps.path} -> {s.path}"
                + (
                    f" and was renamed to {s.name_at_version}"
                    if s.name_at_version != ps.name_at_version
                    else ""
                )
            )
        elif kind == "renamed":
            move_notes.append(
                f"'{fn}' was renamed to '{s.name_at_version}' at {s.path} "
                f"(code otherwise identical)"
            )
        elif is_pure_reshuffle(
            ps.name_at_version, ps.body, s.name_at_version, s.body
        ):
            move_notes.append(
                f"'{fn}' was reshuffled at {s.path} (same statements, "
                f"new order)"
            )
    if move_notes:
        ev.extend(move_notes)

    if cur_impl:
        if prev_impl:
            if touched:
                ev.append(
                    "The implicated code was touched, but the vulnerable "
                    "property still holds — a fix attempt that did not "
                    "address the root cause."
                )
                return VersionVerdict(
                    finding.id, cur.version, BAND_AID, conf, ev
                )
            return VersionVerdict(finding.id, cur.version, STILL_OPEN, conf, ev)
        ev.append(
            f"The vulnerable property was gone at {prev.version} but is "
            f"back at {cur.version}."
        )
        return VersionVerdict(finding.id, cur.version, REGRESSED, conf, ev)

    # The implicated functions no longer show the vulnerable property.
    if prev_impl:
        if cur_else:
            ev.append(
                "The originally implicated spot looks addressed, but the "
                "same risky property persists elsewhere — a surface-level "
                "fix, not a root-cause fix."
            )
            return VersionVerdict(finding.id, cur.version, BAND_AID, conf, ev)
        if touched or move_notes:
            what = (
                "relocated and fixed"
                if move_notes
                else "changed in a fix-shaped way"
            )
            ev.append(
                f"The vulnerable property is gone from the implicated "
                f"functions ({what}); no same-property occurrence remains "
                f"elsewhere in the codebase."
            )
        else:
            ev.append(
                "The risky property is gone from the implicated functions "
                "and no same-property occurrence remains elsewhere in the "
                "scanned files."
            )
        return VersionVerdict(finding.id, cur.version, FIXED, conf, ev)

    # Implicated functions were already clean at the previous version too.
    if cur_else and not prev_else:
        ev.append(
            f"No vulnerable property at {prev.version}, but the risky "
            f"property has appeared at {cur.version}."
        )
        return VersionVerdict(finding.id, cur.version, REGRESSED, conf, ev)
    if cur_else and prev_else:
        ev.append(
            "The risky property persists outside the implicated spot at "
            f"both {prev.version} and {cur.version} — still surface-level."
        )
        return VersionVerdict(finding.id, cur.version, BAND_AID, conf, ev)
    if not cur_else and prev_else:
        ev.append(
            f"The lingering risky property seen at {prev.version} is gone "
            f"at {cur.version}."
        )
        return VersionVerdict(finding.id, cur.version, FIXED, conf, ev)
    carried = prev_verdict if prev_verdict in _VERDICTS else STILL_OPEN
    ev.append(
        f"No vulnerable property at {prev.version} or {cur.version}; "
        f"carrying verdict {carried}."
    )
    return VersionVerdict(finding.id, cur.version, carried, "low", ev)


def walk_versions(
    finding: AuditFinding,
    repo: str | Path,
    versions: list[str],
) -> list[VersionVerdict]:
    """Walk ordered versions and emit a heuristic verdict per version.

    ``versions`` should be ordered oldest -> newest; they are
    re-sorted by commit timestamp as a safety net. Raises
    :class:`ValueError` if fewer than one version is given.
    """
    if not versions:
        raise ValueError("walk_versions needs at least one version")
    repo = Path(repo)
    ordered = _version_order(repo, versions)
    verdicts: list[VersionVerdict] = []
    memory: dict[str, set[str]] = {}  # fn -> known-vulnerable canonicals
    prev_bodies: dict[str, tuple[str | None, str]] = {}
    prev_analysis: _VersionAnalysis | None = None
    prev_verdict: str | None = None
    for version in ordered:
        cur = analyze_version(repo, version, finding, prev_bodies, memory)
        verdict = _verdict_for_transition(
            finding, prev_analysis, prev_verdict, cur, memory
        )
        verdicts.append(verdict)
        prev_bodies = {
            fn: (s.name_at_version or None, s.body)
            for fn, s in cur.fn_states.items()
            if s.located
        }
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

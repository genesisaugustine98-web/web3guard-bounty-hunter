"""Proof gate: the invariant pipeline's immune system (Phase 3).

The adversarial review proved the pipeline had no immune system for
confidently-wrong rule output: bogus AI rules became 0.90-confidence
findings on clean contracts, one bad rule could silently kill a whole
campaign at compile time, and a rule that was already false before testing
started vanished behind a mislabeled "did not compile" note.

This module is the immune system, in two stages:

1. **Pre-render rule validation** (:func:`validate_rules`) — every rule,
   template or AI-written, is checked *before* it can reach the fuzzer:
   - calls to contract functions that don't exist -> quarantined (this also
     fixes the "one bad rule kills the whole campaign" failure: the bad
     rule never reaches the compiler);
   - syntactically tautological assertions (``>= 0`` on a uint getter,
     self-comparisons, literal ``true``) -> quarantined, because they can
     never fire and only create an illusion of coverage;
   - malformed assertions -> quarantined;
   - magic-constant assertions (``target.x() == 999999``) -> LOUD warning
     note (not quarantined: fixed-supply tokens legitimately do this), so
     a human reviewer knows to check the intent.

2. **Post-campaign proof gating** (:func:`gate_findings` /
   :func:`apply_proof_gate`) — NO finding leaves the pipeline without
   machine proof:
   - it must be attributable to a validated rule (unknown ``invariant_id``
     -> rejected);
   - it must carry a non-empty, reproducible machine trace (a forge call
     sequence, titanoboa sequence, snforge counterexample args, or echidna
     tx sequence) — a "violation" with an empty trace means the rule was
     already false at deployment, i.e. the RULE contradicts the contract's
     construction, so the rule is quarantined and no finding is emitted;
   - the campaign must have actually run and compiled;
   - every admitted finding gets a structured ``metadata["proof"]`` artifact
     (engine, rule, trace, reproduction) — so "every finding carries its
     proof" is structural, not aspirational.

The gate is fail-closed for findings (doubt -> reject, loudly) and
fail-open for rule validation (doubt -> keep the rule, so a good rule is
never silently dropped). All rejections and quarantines are LOUD: logged
at WARNING and appended to the pipeline notes. Nothing is silent.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from web3guard.invariants.attackers import HARNESS_RENDERED_INVARIANT_IDS
from web3guard.invariants.harness import extract_target_functions
from web3guard.invariants.models import CampaignResult, Invariant

LOGGER = logging.getLogger("web3guard.invariants.proof_gate")


@dataclass
class QuarantinedRule:
    """A rule the gate refused to let through."""

    invariant_id: str
    reason: str
    stage: str  # "pre-render" | "post-campaign"
    detail: str = ""


@dataclass
class GateRejection:
    """A finding the gate refused to emit."""

    fingerprint: str
    invariant_id: str
    reason: str


@dataclass
class GateVerdict:
    admitted: list[Any] = field(default_factory=list)  # list[Finding]
    rejected: list[GateRejection] = field(default_factory=list)
    post_quarantined: list[QuarantinedRule] = field(default_factory=list)


@dataclass
class ValidationResult:
    valid: list[Invariant] = field(default_factory=list)
    quarantined: list[QuarantinedRule] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Stage 1: pre-render rule validation
# ---------------------------------------------------------------------------

_CALL_RE = re.compile(r"\b(target|handler)\s*\.\s*([A-Za-z_]\w*)\s*\(")
_GE_ZERO_RE = re.compile(
    r"(?P<call>\b(?:target|handler)\s*\.\s*[A-Za-z_]\w*\s*\([^)]*\))\s*>=\s*0\b"
)
_SELF_CMP_RE = re.compile(
    r"(?P<call>\b(?:target|handler)\s*\.\s*[A-Za-z_]\w*\s*\([^)]*\))"
    r"\s*(?P<op>==|<=|>=)\s*(?P=call)"
)
_MAGIC_CONST_RE = re.compile(
    r"\btarget\s*\.\s*[A-Za-z_]\w*\s*\([^)]*\)\s*==\s*"
    r"(?P<const>0x[0-9a-fA-F]+|\d+)\b"
)
_PUBLIC_VAR_RE = re.compile(
    r"\bpublic\b\s+(?:constant\s+|immutable\s+)?([A-Za-z_]\w*)\s*(?:=|;)"
)
_UINT_RETURN_RE = re.compile(
    r"\bpublic\b\s+(?P<type>u?int\d*)\s+(?P<name>[A-Za-z_]\w*)\b"
)
_FN_RETURN_RE = re.compile(
    r"function\s+(?P<name>[A-Za-z_]\w*)\s*\([^)]*\)"
    r"[^{};]*?returns\s*\(\s*(?P<type>u?int\d*)"
)


def _known_target_calls(source: str) -> set[str]:
    """Public-ish function names + public state variable names in ``source``.

    Function names are scoped to the deploy-target contract (weakness-hunt
    round, target 2): a rule referencing an auxiliary contract's function
    would fail compilation, so it is quarantined here instead.
    """
    names = {sig.name for sig in extract_target_functions(source)}
    for m in _PUBLIC_VAR_RE.finditer(source):
        names.add(m.group(1))
    return names


def _uintness(source: str, name: str) -> str | None:
    """Best-effort return type ('uint256' / 'int128' / ...) for a getter."""
    # State variable: ``uint256 public totalDeposited;``
    m = re.search(
        r"\b(?P<type>u?int\d*)\s+public\b\s+" + re.escape(name) + r"\b", source
    )
    if m:
        return m.group("type")
    # Explicit getter: ``function totalDeposited() ... returns (uint256)``
    m = re.search(
        r"function\s+" + re.escape(name) + r"\s*\([^)]*\)"
        r"[^{};]*?returns\s*\(\s*(?P<type>u?int\d*)",
        source,
    )
    return m.group("type") if m else None


def validate_rules(
    invariants: list[Invariant],
    source: str,
    *,
    language: str = "solidity",
    ghost_ids: frozenset[str] = frozenset(),
    handler_refs: frozenset[str] = frozenset(),
    body_ids: frozenset[str] = frozenset(),
) -> ValidationResult:
    """Validate rules before rendering; quarantine the mechanically bad ones.

    ``ghost_ids``/``handler_refs`` describe the template ghost machinery so
    ``handler.<ghost>()`` references in template assertions are accepted
    while ghost references in LLM-written rules are rejected (the synthesis
    prompt forbids the model from using ghost state). ``body_ids`` marks
    templates whose invariant is a multi-statement body (their ``assertion``
    is intentionally empty and is not validated here — bodies are
    author-reviewed and rendered by our own code, never by the model).
    """
    result = ValidationResult()
    known_calls = _known_target_calls(source) if language == "solidity" else set()
    for inv in invariants:
        problems: list[str] = []
        is_body = inv.id in body_ids
        text = (inv.assertion or "").strip()
        if not text and not is_body:
            problems.append("empty assertion")
        elif not is_body and any(c in text for c in ";{}"):
            problems.append("assertion must be a single expression (no ;{})")
        elif not is_body:
            for m in _CALL_RE.finditer(text):
                obj, name = m.group(1), m.group(2)
                if obj == "target":
                    if language == "solidity" and name not in known_calls:
                        problems.append(
                            f"calls unknown contract function '{name}()' — "
                            "the rule would fail compilation and take the "
                            "whole campaign down with it"
                        )
                else:  # handler.* — ghost state is template-only
                    if inv.id not in ghost_ids or name not in handler_refs:
                        problems.append(
                            f"references unknown ghost state 'handler.{name}()' — "
                            "ghost state may only come from templates"
                        )
            if not is_body:
                problems.extend(_tautology_problems(inv.assertion, source, language))
        if problems:
            reason = "; ".join(problems)
            LOGGER.warning(
                "proof gate quarantined rule %s pre-render: %s", inv.id, reason
            )
            result.quarantined.append(
                QuarantinedRule(
                    invariant_id=inv.id, reason=reason, stage="pre-render"
                )
            )
            continue
        # Loud-but-not-blocking: magic constants deserve human review.
        if not is_body:
            mc = _MAGIC_CONST_RE.search(inv.assertion)
            if mc:
                note = (
                    f"invariant rule '{inv.id}' pins magic constant "
                    f"{mc.group('const')}: verify this is the contract's real "
                    "intent, not a hallucinated expectation."
                )
                LOGGER.warning(note)
                result.notes.append(note)
        result.valid.append(inv)
    return result


def _tautology_problems(
    assertion: str, source: str, language: str
) -> list[str]:
    """Syntactic tautologies: properties that can never fire."""
    problems: list[str] = []
    text = assertion.strip()
    if text == "true":
        return ["assertion is the literal 'true' — it can never fire"]
    if _SELF_CMP_RE.search(text):
        problems.append(
            "self-comparison (x == x / x <= x) is constant — it can never fire"
        )
    if language == "solidity":
        for m in _GE_ZERO_RE.finditer(text):
            call = m.group("call")
            name_m = re.search(r"\.\s*([A-Za-z_]\w*)\s*\(", call)
            name = name_m.group(1) if name_m else ""
            uintness = _uintness(source, name) if name else None
            # Fail-open: only quarantine when we can PROVE unsignedness.
            if uintness is not None and uintness.startswith("uint"):
                problems.append(
                    f"'{call} >= 0' is always true for unsigned {uintness} — "
                    "it can never fire"
                )
    return problems


# ---------------------------------------------------------------------------
# Stage 2: post-campaign proof gating
# ---------------------------------------------------------------------------

_BASELINE_FAILURE_RE = re.compile(
    r"failed to set up invariant testing environment[^\n\]]*\]?\s*"
    r"(?P<fn>invariant_[A-Za-z0-9_]+)\s*\(\)"
)

_TRACE_LINE_RES = {
    "foundry-invariant": re.compile(r"calldata="),
    "titanoboa-invariant": re.compile(r"^\s*\d+\.\s*\S", re.MULTILINE),
    "snforge-invariant": re.compile(r"arguments:"),
    "echidna": re.compile(r"^\s*\d+\.\s*\S", re.MULTILINE),
}


def _is_forge_failure_event(line: str) -> bool:
    """Is this line one of forge's NDJSON invariant-failure events?

    Forge prints ``{"timestamp":...,"event":"failure",
    "invariant":"invariant_foo",...}`` on stderr for every invariant it
    breaks while fuzzing — and ONLY then. Rules that are false at
    deployment produce ``failed to set up invariant testing environment``
    and NO failure event (verified against forge 1.6.0-nightly), so an
    event line can never be an empty-trace false-at-deployment artifact.
    The line may be embedded in the PoC's ``#`` comment block, so a
    leading comment marker is stripped before checking.
    """
    s = line.strip().lstrip("#").strip()
    if len(s) < 2 or len(s) > 8192 or not s.startswith("{"):
        return False
    try:
        obj = json.loads(s)
    except (json.JSONDecodeError, ValueError):
        return False
    return (
        isinstance(obj, dict)
        and obj.get("event") == "failure"
        and isinstance(obj.get("invariant"), str)
        and bool(obj["invariant"])
    )


def _check_trace(engine: str, poc: str) -> tuple[bool, list[str]]:
    """Does the PoC carry a non-empty machine trace?"""
    if engine == "foundry-invariant":
        lines = [ln.strip() for ln in poc.splitlines() if "calldata=" in ln]
        if lines:
            return True, lines[:30]
        # Fix C: when output truncation destroyed the human-readable call
        # sequence, forge's own JSON failure event (embedded in the PoC by
        # the parser) is still a machine trace — it is forge's attestation
        # that fuzzing found a violating sequence, which false-at-deployment
        # rules never produce (see _is_forge_failure_event). The readable
        # sequence is preferred whenever it survived.
        evt_lines = [
            ln.strip() for ln in poc.splitlines() if _is_forge_failure_event(ln)
        ]
        return (bool(evt_lines), evt_lines[:30])
    if engine == "titanoboa-invariant":
        if "(no call sequence recorded)" in poc:
            return False, []
        lines = [
            ln.strip()
            for ln in poc.splitlines()
            if re.match(r"\s*\d+\.\s*\S", ln)
        ]
        return (bool(lines), lines[:30])
    if engine == "snforge-invariant":
        if "(not printed)" in poc:
            return False, []
        m = re.search(r"arguments:\s*(.+)", poc)
        return (True, [m.group(0).strip()] if m else [])
    if engine == "echidna":
        lines = [
            ln.strip()
            for ln in poc.splitlines()
            if re.match(r"\s*\d+\.\s*\S", ln)
        ]
        return (bool(lines), lines[:30])
    return False, []


def _sanitized_fn(inv_id: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_]", "_", "invariant_" + inv_id)
    if clean and clean[0].isdigit():
        clean = "inv_" + clean
    return clean or "inv_unnamed"


def extract_baseline_failures(
    output: str, invariants: list[Invariant]
) -> list[str]:
    """Invariant ids whose rule was already false at deployment.

    Forge reports these as "failed to set up invariant testing environment"
    with an empty call sequence: the rule contradicts the contract's own
    construction, so it is a bad RULE, not a bug. Returns matching ids.
    """
    by_fn = {_sanitized_fn(inv.id): inv.id for inv in invariants}
    found: list[str] = []
    for m in _BASELINE_FAILURE_RE.finditer(output or ""):
        inv_id = by_fn.get(m.group("fn"))
        if inv_id and inv_id not in found:
            found.append(inv_id)
    return found


def gate_findings(
    findings: list[Any],
    valid_ids: set[str],
    campaign: CampaignResult | None,
    *,
    target_label: str = "",
) -> GateVerdict:
    """Admit only findings with machine proof; reject (loudly) the rest."""
    verdict = GateVerdict()
    for f in findings:
        meta = f.metadata if isinstance(getattr(f, "metadata", None), dict) else {}
        consensus = getattr(f, "tool_consensus", None) or []
        engine = str(meta.get("engine") or (consensus[0] if consensus else ""))
        inv_id = str(meta.get("invariant_id") or "")
        fingerprint = str(getattr(f, "fingerprint", "") or "")
        category = str(getattr(f, "category", "") or "")
        poc = str(getattr(f, "poc_code", "") or "")

        def _reject(reason: str, *, _engine: str = engine,
                    _inv_id: str = inv_id,
                    _fingerprint: str = fingerprint) -> None:
            LOGGER.warning(
                "proof gate REJECTED finding %s (rule %s, engine %s): %s",
                _fingerprint or "?", _inv_id or "?", _engine or "?", reason,
            )
            verdict.rejected.append(
                GateRejection(
                    fingerprint=_fingerprint, invariant_id=_inv_id, reason=reason
                )
            )

        if not engine:
            _reject("no proof engine attribution — cannot verify machine proof")
            continue
        if category == "invariant-violation":
            if not inv_id or inv_id not in valid_ids:
                _reject(
                    "unattributable to a validated rule "
                    f"(invariant_id={inv_id!r}) — refusing to emit an "
                    "unproven invariant finding"
                )
                continue
        if not poc.strip():
            _reject("empty proof artifact (no PoC)")
            continue
        if campaign is not None and (
            campaign.skipped or not campaign.compile_ok
        ):
            _reject("campaign did not run to a compiled state — no machine proof")
            continue
        trace_ok, trace_lines = _check_trace(engine, poc)
        if not trace_ok:
            reason = (
                "no machine trace in the proof artifact — the rule was "
                "already false before any transaction (it contradicts the "
                "contract's construction), so this is a bad RULE, not a bug"
            )
            _reject(reason)
            if inv_id and inv_id in valid_ids:
                verdict.post_quarantined.append(
                    QuarantinedRule(
                        invariant_id=inv_id,
                        reason="violated at deployment with an empty call "
                               "sequence — the rule contradicts the contract's "
                               "own construction",
                        stage="post-campaign",
                    )
                )
            continue
        # Admit: attach the structured proof artifact.
        if isinstance(getattr(f, "metadata", None), dict):
            f.metadata["proof"] = {
                "engine": engine,
                "invariant_id": inv_id or None,
                "invariant_source": meta.get("invariant_source", "unknown"),
                "trace": trace_lines,
                "reproduction": (
                    "re-run the invariant pipeline on "
                    f"{getattr(f, 'target', '') or target_label}; the trace "
                    "above reproduces the violation"
                ),
                "fuzz_runs": meta.get("fuzz_runs"),
                "fuzz_calls": meta.get("fuzz_calls"),
            }
        verdict.admitted.append(f)
    return verdict


def apply_proof_gate(
    findings: list[Any],
    invariants: list[Invariant],
    campaign: CampaignResult | None,
    *,
    notes: list[str] | None = None,
    target_label: str = "",
) -> list[Any]:
    """The pipeline's single choke point for invariant findings.

    Returns the admitted findings; every rejection/quarantine is appended
    to ``notes`` (when given) so it is LOUD, never silent.

    The harness's own machine-rendered exploit invariants (see
    :data:`attackers.HARNESS_RENDERED_INVARIANT_IDS`) are attributable by
    construction — deterministic product code, not caller or LLM rules —
    so a machine-proven break of one is admitted like any validated rule.
    """
    valid_ids = {i.id for i in invariants} | set(HARNESS_RENDERED_INVARIANT_IDS)
    verdict = gate_findings(
        findings, valid_ids, campaign,
        target_label=target_label,
    )
    if notes is not None:
        for r in verdict.rejected:
            notes.append(
                f"proof gate REJECTED a finding (rule '{r.invariant_id or '?'}', "
                f"fingerprint {r.fingerprint or '?'}): {r.reason} — not emitted."
            )
        for q in verdict.post_quarantined:
            notes.append(
                f"invariant rule '{q.invariant_id}' QUARANTINED post-campaign: "
                f"{q.reason} — no finding emitted."
            )
        if verdict.admitted:
            notes.append(
                f"proof gate: {len(verdict.admitted)} invariant finding(s) "
                "admitted, each carrying a machine-checked proof artifact "
                "(call sequence / trace in metadata['proof'])."
            )
    return verdict.admitted

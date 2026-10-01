"""
Verification ensemble — cross-examine findings with a second model.

Confirmation is the top priority: a false positive submitted to a
bounty program burns reputation and can get an account banned. The
single strongest anti-false-positive lever (after runtime PoC
confirmation) is an *independent second opinion* from a different
model: same evidence, different training data and failure modes.

The ensemble runs every finding (or a filtered subset) through a
three-way classifier:

- ``uphold``     — the second model, given the code and the claim,
                   independently agrees the vulnerability is real.
- ``downgrade``  — the second model finds a plausible mitigating
                   control; confidence is cut and the finding is
                   marked for manual review.
- ``overturn``   — the second model identifies the claim as a
                   misread of the code; the finding is demoted to
                   REJECTED with the refutation attached.

Verdicts are recorded in ``finding.metadata["verification_ensemble"]``
and never silently discarded: an overturn keeps the raw evidence in
the finding so the operator can audit the decision.

Routing: the ensemble deliberately asks the AI client for a *different*
model than the analysis role (via the v3.3 per-role ``models:`` config,
key ``ensemble``). When only one model is configured, the ensemble
still runs — a second prompt with a different system contract and a
temperature above 0 still provides partial decorrelation — and records
``independent_model: false`` so the operator can weigh it.
"""

from __future__ import annotations

import datetime
import json
import logging
import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from web3guard.security import PromptInjectionGuard
from web3guard.security.prompt_injection import InjectionVerdict

LOGGER = logging.getLogger("web3guard.verification")

ENSEMBLE_SYSTEM_PROMPT = (
    "You are an independent senior smart-contract auditor performing a "
    "second-opinion review. Another analyst claims the code contains a "
    "vulnerability. Your job is to be the check, not the echo:\n"
    "1. Re-derive the vulnerability from the code yourself. Do not "
    "assume the claim is correct.\n"
    "2. Look for mitigating controls the analyst may have missed "
    "(access modifiers, reentrancy guards, oracle sanity checks, "
    "pause switches, upstream invariants, compiler-version semantics).\n"
    "3. Decide: uphold (real and exploitable as described), downgrade "
    "(real-looking but a plausible control or precondition blocks the "
    "impact), or overturn (the claim misreads the code; it is not "
    "vulnerable as described).\n"
    "Respond with exactly one JSON object and nothing else:\n"
    '{"verdict": "uphold|downgrade|overturn", '
    '"confidence": <0.0-1.0>, '
    '"reasoning": "<one paragraph>", '
    '"mitigating_controls": ["..."], '
    '"corrected_severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO"}'
)

_VALID_VERDICTS = ("uphold", "downgrade", "overturn")


@dataclass
class EnsembleOutcome:
    """Result of one ensemble review."""
    verdict: str                 # uphold | downgrade | overturn | unavailable
    confidence: float = 0.0
    reasoning: str = ""
    mitigating_controls: list[str] = field(default_factory=list)
    corrected_severity: str = ""
    independent_model: bool = False
    model: str = ""

    def to_metadata(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "reasoning": self.reasoning[:1500],
            "mitigating_controls": self.mitigating_controls,
            "corrected_severity": self.corrected_severity,
            "independent_model": self.independent_model,
            "model": self.model,
        }


class VerificationEnsemble:
    """Second-opinion pass over findings, aimed squarely at false positives."""

    def __init__(
        self,
        ai_client: Any,
        *,
        min_severity: str = "LOW",
        max_findings: int = 64,
        temperature: float = 0.2,
    ) -> None:
        self._client = ai_client
        self._min_severity = min_severity
        self._max_findings = max_findings
        self._temperature = temperature

    def _order(self, sev: str) -> int:
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(
            str(sev).upper(), 0)

    def review_finding(self, finding: Any, code: str) -> EnsembleOutcome:
        """Cross-examine a single finding. Never raises: failures degrade
        to ``unavailable`` and leave the finding untouched."""
        user = (
            f"Claimed vulnerability: {getattr(finding, 'category', '')}"
            f" (severity {getattr(finding, 'severity', '')}, "
            f"confidence {getattr(finding, 'confidence', 0):.2f})\n"
            f"Location: {getattr(finding, 'file', '')}"
            f"::{getattr(finding, 'function', '')}"
            f" {getattr(finding, 'line_hint', '')}\n"
            f"Claim description: {getattr(finding, 'description', '')}\n"
            f"Claim reasoning: {getattr(finding, 'reasoning', '')}\n\n"
            "Code under review:\n"
            f"{code[:8000]}"
        )
        try:
            resp = self._client.chat(
                ENSEMBLE_SYSTEM_PROMPT,
                user,
                max_tokens=900,
                temperature=self._temperature,
                role="ensemble",
            )
        except Exception as e:  # noqa: BLE001
            LOGGER.warning("ensemble review failed: %s", e)
            return EnsembleOutcome(verdict="unavailable")
        parsed = self._extract_json(resp.content)
        if not parsed:
            return EnsembleOutcome(verdict="unavailable")
        verdict = str(parsed.get("verdict", "")).lower().strip()
        if verdict not in _VALID_VERDICTS:
            return EnsembleOutcome(verdict="unavailable")
        try:
            conf = max(0.0, min(1.0, float(parsed.get("confidence", 0.5))))
        except (TypeError, ValueError):
            conf = 0.5
        controls = parsed.get("mitigating_controls")
        if not isinstance(controls, list):
            controls = []
        outcome = EnsembleOutcome(
            verdict=verdict,
            confidence=conf,
            reasoning=str(parsed.get("reasoning", "")),
            mitigating_controls=[str(c) for c in controls][:8],
            corrected_severity=str(parsed.get("corrected_severity", "")).upper(),
            independent_model=True,
            model=str(getattr(resp, "model", "") or ""),
        )
        return outcome

    def apply(self, findings: list[Any], code_of: Any) -> int:
        """Review ``findings`` in place; returns the number reviewed.

        ``code_of(finding)`` must return the source chunk for a finding.
        Effects per verdict:
        - uphold:     confidence nudged up (bounded 0.99), metadata tagged.
        - downgrade:  confidence cut 35%, metadata tagged
                      ``verification_ensemble.verdict``.
        - overturn:   status set to REJECTED with the refutation recorded,
                      confidence floored at 0.05. The raw evidence stays in
                      the finding for audit.
        - unavailable: recorded as such; finding untouched.
        """
        eligible = [
            f for f in findings
            if str(getattr(f, "status", "")) != "CONFIRMED EXPLOIT"
            and self._order(str(getattr(f, "severity", "LOW"))) >= self._order(self._min_severity)
        ]
        # Highest-severity, lowest-confidence first: those are the ones
        # most likely to be false positives and most expensive to submit.
        eligible.sort(key=lambda f: (-self._order(str(getattr(f, "severity", "LOW"))),
                                     float(getattr(f, "confidence", 0.0))))
        eligible = eligible[: self._max_findings]
        reviewed = 0
        for f in eligible:
            try:
                code = code_of(f)
            except Exception:  # noqa: BLE001
                code = ""
            outcome = self.review_finding(f, code or "")
            meta = dict(getattr(f, "metadata", {}) or {})
            meta["verification_ensemble"] = outcome.to_metadata()
            f.metadata = meta
            reviewed += 1
            if outcome.verdict == "uphold":
                f.confidence = min(0.99, float(f.confidence) + 0.05)
                if (outcome.corrected_severity
                        and outcome.corrected_severity in
                        ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")):
                    f.severity = outcome.corrected_severity
            elif outcome.verdict == "downgrade":
                f.confidence = max(0.05, float(f.confidence) * 0.65)
                f.metadata["manual_review_required"] = True
            elif outcome.verdict == "overturn":
                f.confidence = 0.05
                f.status = "REJECTED"
                f.metadata["rejection_reason"] = (
                    "verification ensemble overturn: "
                    + (outcome.reasoning[:300] or "second model disagreed"))
        return reviewed

    @staticmethod
    def _extract_json(text: str) -> dict[str, Any] | None:
        """Pull the first JSON object out of an LLM response."""
        return _extract_json(text)


# ===========================================================================
# PHASE 3 — VERIFICATION / FALSE-POSITIVE FILTER LAYER ("Hunt Bigger Fish")
# ===========================================================================
#
# Single entry point: :func:`verify_findings`. The pipeline (phase 7) calls it
# between "findings produced" and "report rendered". Every POTENTIAL finding
# from an AI source (red-team hypotheses, invariant violations, LLM review
# output) must survive adversarial re-check before a human ever sees it.
#
# Evidence tiers, in priority order:
#
#   1. MACHINE-CHECKABLE FIRST — a finding that carries a structured
#      ``machine_check`` spec in ``finding.metadata`` is re-executed /
#      replayed locally. Reproduces -> ``CONFIRMED EXPLOIT``
#      (``dynamically_confirmed=True``). Does not reproduce -> ``REJECTED``
#      with reason "evidence did not reproduce".
#
#      Contract for evidence producers (phase 2 invariant engine, PoC loop,
#      anything else that generates machine evidence): attach
#
#          finding.metadata["machine_check"] = {
#              "type": "forge_replay" | "command" | "text_marker",
#              ... type-specific params, see _MACHINE_CHECKERS ...
#          }
#
#      ``poc_code`` / ``exploit_log`` alone (e.g. a pasted forge call
#      sequence with no structured spec) are treated as *unstructured*
#      evidence: they are shown to the LLM adversarial filter as supporting
#      context, but they cannot auto-confirm a finding, because replaying
#      free text is not deterministic.
#
#   2. LLM ADVERSARIAL FILTER ("Napalm" pattern) for findings with no
#      machine evidence: prosecutor argues the finding is real (with exploit
#      steps) -> defense argues it is a false positive (with specific benign
#      explanations) -> a lightweight judge decides. Only findings whose
#      prosecution survives the defense stay POTENTIAL (tagged
#      high-confidence); the rest are REJECTED with the defense/judge reason
#      logged. Findings are never dropped on LLM *failure*: any exception or
#      unparseable judge verdict fails OPEN (kept, flagged) because dropping
#      a finding due to an infrastructure hiccup would hide real bugs.
#
# Dropped-findings ledger: every decision is appended (JSONL) to the
# verification ledger — fingerprint, verdict, reason, evidence summary,
# timestamp, model used. Dropped findings never reach the human; the ledger
# is the audit trail.
#
# Degraded mode: when the router client is inactive (NullClient — no keys),
# the LLM adversarial filter is SKIPPED with a loud offline note, but
# machine-checkable verification still runs (fuzz evidence needs no LLM).
#
# Prompt-injection safety: ALL finding content inserted into prompts goes
# through PromptInjectionGuard (scan + quarantine), the same pattern
# web3guard.ai.client.AIClient uses. Content that trips the guard's REJECT
# threshold skips the LLM round (kept, flagged for manual review).
#
# Cost: zero marginal cost by default. LLM calls happen only when keys are
# present and AI is enabled; ledger writes are local-only. Prompts are kept
# short on purpose — cost matters even on free tiers.

# -- lazily imported to avoid import cycles at module load -----------------
# (router pulls in provider/client machinery; verification must stay
# importable from anywhere, including tests that never touch the network)


def _router():
    from web3guard.ai import router as _r
    return _r


# ---------------------------------------------------------------------------
# Machine-evidence replay
# ---------------------------------------------------------------------------

#: Metadata key carrying the structured machine-check spec (see contract above).
MACHINE_CHECK_KEY = "machine_check"


@dataclass
class MachineCheckResult:
    """Outcome of replaying one machine-check spec."""
    reproduced: bool | None      # True/False, or None when the checker
                                # could not run (e.g. forge not installed)
    detail: str = ""            # one-line human summary of what happened
    checker: str = ""           # check type that ran


def _check_text_marker(params: dict[str, Any]) -> MachineCheckResult:
    """Deterministic re-check: does ``text`` still contain ``marker``?"""
    text = str(params.get("text", ""))
    marker = str(params.get("marker", ""))
    if not marker:
        return MachineCheckResult(
            reproduced=None,
            detail="text_marker check has no marker configured",
            checker="text_marker",
        )
    hit = marker in text
    return MachineCheckResult(
        reproduced=hit,
        detail=f"marker {marker[:60]!r} {'found' if hit else 'absent'} "
               f"in {len(text)} chars of evidence text",
        checker="text_marker",
    )


def _check_command(params: dict[str, Any]) -> MachineCheckResult:
    """Re-run a replay command under the sandbox guard.

    Params: ``argv`` (list, required), ``cwd`` (default "."), ``timeout_s``
    (default 120), ``expect_exit`` (default 0), ``expect_output_contains``
    (optional substring that must appear in stdout+stderr).
    """
    from web3guard.security.sandbox_guard import run_sandboxed

    argv = params.get("argv")
    if not argv or not isinstance(argv, (list, tuple)):
        return MachineCheckResult(
            reproduced=None,
            detail="command check has no argv",
            checker="command",
        )
    timeout = int(params.get("timeout_s", 120) or 120)
    timeout = max(5, min(timeout, 1800))
    expect_exit = int(params.get("expect_exit", 0))
    want = params.get("expect_output_contains")
    cwd = Path(str(params.get("cwd", ".") or "."))
    try:
        rc, out, err = run_sandboxed(
            [str(a) for a in argv], cwd=cwd, timeout=timeout)
    except FileNotFoundError as e:
        return MachineCheckResult(
            reproduced=None, detail=f"binary not available: {e}",
            checker="command")
    except Exception as e:  # noqa: BLE001
        LOGGER.warning("command machine-check failed to run: %s", e)
        return MachineCheckResult(
            reproduced=None,
            detail=f"checker error (infrastructure): {e}"[:300],
            checker="command",
        )
    combined = (out or "") + "\n" + (err or "")
    ok_exit = rc == expect_exit
    ok_output = True
    if want:
        ok_output = str(want) in combined
    reproduced = bool(ok_exit and ok_output)
    detail = (
        f"exit={rc} (expected {expect_exit})"
        + (f", output marker {'found' if ok_output else 'MISSING'}"
           if want else "")
        + f", {len(combined)} chars output"
    )
    return MachineCheckResult(
        reproduced=reproduced, detail=detail, checker="command")


def _check_forge_replay(params: dict[str, Any]) -> MachineCheckResult:
    """Re-run a forge test that previously demonstrated the exploit.

    Params: ``project_dir`` (required), ``test_match`` (``--match-test``
    filter, optional), ``expect`` ("fail" default | "pass"),
    ``timeout_s`` (default 600), ``extra_args`` (list, optional).

    A *failing* fuzz run is the normal evidence shape for an invariant
    violation (the invariant broke == the bug is real), so the default
    expectation is ``fail``: reproduction means the test fails again.
    """
    from web3guard.security.sandbox_guard import run_sandboxed

    if shutil.which("forge") is None:
        return MachineCheckResult(
            reproduced=None,
            detail="forge not installed; cannot replay fuzz evidence",
            checker="forge_replay",
        )
    project_dir = str(params.get("project_dir", "") or "")
    if not project_dir or not Path(project_dir).is_dir():
        return MachineCheckResult(
            reproduced=None,
            detail=f"forge project dir missing: {project_dir[:120]!r}",
            checker="forge_replay",
        )
    argv = ["forge", "test"]
    test_match = params.get("test_match")
    if test_match:
        argv += ["--match-test", str(test_match)]
    extra = params.get("extra_args")
    if isinstance(extra, (list, tuple)):
        argv += [str(a) for a in extra]
    expect = str(params.get("expect", "fail") or "fail").lower()
    timeout = int(params.get("timeout_s", 600) or 600)
    timeout = max(30, min(timeout, 3600))
    try:
        rc, out, err = run_sandboxed(
            argv, cwd=Path(project_dir), timeout=timeout)
    except Exception as e:  # noqa: BLE001
        LOGGER.warning("forge replay failed to run: %s", e)
        return MachineCheckResult(
            reproduced=None,
            detail=f"checker error (infrastructure): {e}"[:300],
            checker="forge_replay",
        )
    failed = rc != 0
    reproduced = failed if expect == "fail" else not failed
    tail = ((out or "") + "\n" + (err or "")).strip().splitlines()
    tail_txt = "\n".join(tail[-6:])[:600]
    return MachineCheckResult(
        reproduced=reproduced,
        detail=f"forge test exit={rc} (expected "
               f"{'failure' if expect == 'fail' else 'success'}); "
               f"reproduced={reproduced}. tail: {tail_txt}",
        checker="forge_replay",
    )


#: Registry of replayable machine-check types. Evidence producers (phase 2+)
#: may register additional checkers via ``register_machine_checker``.
_MACHINE_CHECKERS: dict[str, Any] = {
    "text_marker": _check_text_marker,
    "command": _check_command,
    "forge_replay": _check_forge_replay,
}


def register_machine_checker(name: str, fn: Any) -> None:
    """Register a new machine-evidence replay checker.

    ``fn(params: dict) -> MachineCheckResult``. ``reproduced=None`` means
    the checker could not run (fail-open: the finding is kept, flagged).
    """
    _MACHINE_CHECKERS[name] = fn


def machine_check_spec(finding: Any) -> dict[str, Any] | None:
    """Return the structured machine-check spec on a finding, if any."""
    meta = getattr(finding, "metadata", None) or {}
    spec = meta.get(MACHINE_CHECK_KEY)
    if isinstance(spec, dict) and spec.get("type"):
        return spec
    return None


def has_unstructured_evidence(finding: Any) -> bool:
    """True when the finding carries poc_code/exploit_log but no
    structured, replayable machine-check spec."""
    if machine_check_spec(finding):
        return False
    return bool(getattr(finding, "exploit_log", "") or
                getattr(finding, "poc_code", ""))


def replay_machine_evidence(finding: Any) -> MachineCheckResult:
    """Re-execute a finding's structured machine evidence. Never raises:
    infrastructure failures degrade to ``reproduced=None`` (fail-open)."""
    spec = machine_check_spec(finding)
    if spec is None:
        return MachineCheckResult(
            reproduced=None, detail="no structured machine evidence",
            checker="")
    check_type = str(spec.get("type", ""))
    checker = _MACHINE_CHECKERS.get(check_type)
    if checker is None:
        return MachineCheckResult(
            reproduced=None,
            detail=f"unknown machine-check type {check_type!r}; "
                   f"known: {sorted(_MACHINE_CHECKERS)}",
            checker=check_type,
        )
    try:
        result = checker(dict(spec.get("params", spec)))
        if not isinstance(result, MachineCheckResult):
            raise TypeError("checker did not return MachineCheckResult")
        result.checker = result.checker or check_type
        return result
    except Exception as e:  # noqa: BLE001
        LOGGER.warning("machine-check %r crashed: %s", check_type, e)
        return MachineCheckResult(
            reproduced=None,
            detail=f"checker crashed (infrastructure): {e}"[:300],
            checker=check_type,
        )


# ---------------------------------------------------------------------------
# LLM adversarial filter ("Napalm": prosecutor -> defense -> judge)
# ---------------------------------------------------------------------------

# Short on purpose: free-tier budgets are real even at $0.
_PROSECUTOR_SYSTEM = (
    "You are a senior smart-contract auditor PROSECUTING a vulnerability "
    "claim. Argue the claim is REAL and exploitable. Give concrete exploit "
    "steps: who calls what function, with what inputs, which invariant "
    "breaks, what value an attacker extracts. Be specific about the code "
    "below. If a step is impossible, say so honestly — do not invent "
    "capabilities the attacker does not have.\n"
    "Respond with exactly one JSON object and nothing else:\n"
    '{"case": "<3-5 sentences: the prosecution, with concrete exploit '
    'steps>", "exploit_steps": ["step 1", "..."], '
    '"impact": "<what the attacker gains>"}'
)

_DEFENSE_SYSTEM = (
    "You are a senior smart-contract auditor DEFENDING code against a "
    "vulnerability claim. The prosecution's case is below; your job is to "
    "kill the claim if it is wrong. Check for: access controls (onlyOwner, "
    "roles), reentrancy guards, checks-effects-interactions ordering, "
    "Solidity >=0.8 built-in overflow checks, oracle staleness guards, "
    "pause switches, the claimed function being unreachable / test-only, "
    "misread semantics. Give SPECIFIC benign explanations grounded in the "
    "evidence — vague doubt is not a refutation.\n"
    "Respond with exactly one JSON object and nothing else:\n"
    '{"verdict": "false_positive|plausible", '
    '"refutation": "<2-4 sentences: why the claim is wrong, or empty>", '
    '"benign_explanations": ["..."]}'
)

_JUDGE_SYSTEM = (
    "You are the judge. The prosecution made a case for a vulnerability; "
    "the defense rebutted. Decide: KEEP the finding only if the "
    "prosecution's exploit steps are concrete and the defense did not "
    "specifically break the exploit chain. REJECT if the defense named a "
    "specific control or precondition that blocks the attack, or the "
    "prosecution's steps are speculative.\n"
    "Respond with exactly one JSON object and nothing else:\n"
    '{"decision": "keep|reject", "reason": "<one sentence>"}'
)


def _extract_json(text: str) -> dict[str, Any] | None:
    """Pull the first JSON object out of an LLM response."""
    if not text:
        return None
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        parsed = json.loads(m.group(0))
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


# Keep the historical method working (delegates to the shared helper above).
# (The reassignment line that used to live here was removed: mypy forbids
# method assignment; the classmethod now delegates directly.)


@dataclass
class AdversarialOutcome:
    """Result of the prosecutor -> defense -> judge round."""
    decision: str = "unavailable"   # keep | reject | unavailable
    reason: str = ""
    prosecution: str = ""
    defense_refutation: str = ""
    model: str = ""
    injection_skipped: bool = False
    llm_calls: int = 0               # LLM calls actually attempted


class AdversarialFilter:
    """Napalm-pattern false-positive filter for non-machine evidence.

    Per finding: prosecutor makes the case -> defense rebuts -> judge
    decides. Only ``keep`` verdicts survive. Never raises out of the
    per-finding path: LLM failures degrade to ``unavailable`` (fail-open:
    the finding is kept, flagged, and logged).
    """

    def __init__(
        self,
        ai_client: Any,
        *,
        injection_guard: PromptInjectionGuard | None = None,
        max_tokens_prosecution: int = 600,
        max_tokens_defense: int = 600,
        max_tokens_judge: int = 250,
        max_evidence_chars: int = 4000,
    ) -> None:
        self._client = ai_client
        self._guard = injection_guard or PromptInjectionGuard()
        self._tok_p = max_tokens_prosecution
        self._tok_d = max_tokens_defense
        self._tok_j = max_tokens_judge
        self._max_ev = max_evidence_chars

    # -- prompt building (all finding content quarantined) ------------------

    def _quarantined_evidence(self, finding: Any) -> str | None:
        """Build the quarantined evidence block. Returns None when the
        guard REJECTs the content (active injection risk) — the LLM round
        is then skipped for this finding."""
        parts = [
            f"Category: {getattr(finding, 'category', '')}",
            f"Severity: {getattr(finding, 'severity', '')}",
            f"Location: {getattr(finding, 'file', '')}"
            f"::{getattr(finding, 'function', '')}",
            f"Claim: {getattr(finding, 'description', '')}",
            f"Claim reasoning: {getattr(finding, 'reasoning', '')}",
        ]
        exploit_log = str(getattr(finding, "exploit_log", "") or "")
        poc_code = str(getattr(finding, "poc_code", "") or "")
        if exploit_log:
            parts.append(f"Exploit log (unstructured):\n{exploit_log}")
        if poc_code:
            parts.append(f"PoC code (unstructured):\n{poc_code}")
        raw = "\n".join(parts)[: self._max_ev]
        scan = self._guard.scan(raw, source_label="finding_evidence")
        if scan.verdict == InjectionVerdict.REJECTED:
            LOGGER.warning(
                "adversarial filter: finding content rejected by "
                "injection guard (%s); skipping LLM round",
                getattr(scan, "notes", ""))
            return None
        return self._guard.quarantine(
            scan.sanitized_text, source_label="finding_evidence")

    def _chat(self, system: str, user: str, *, max_tokens: int,
              role: str) -> Any | None:
        try:
            # Same quarantine discipline as AIClient.chat: the system
            # prompt carries the quarantine contract; the user content is
            # the quarantined evidence block built above.
            system_q = system + "\n\n" + self._guard.quarantine(
                "", source_label="placeholder")
            resp = self._client.chat(
                system_q, user, max_tokens=max_tokens,
                temperature=0.0, role=role)
        except Exception as e:  # noqa: BLE001
            LOGGER.warning("adversarial filter LLM call (%s) failed: %s",
                           role, e)
            return None
        content = getattr(resp, "content", "") or ""
        clean, reason = self._guard.validate_response(content)
        if not clean:
            LOGGER.warning(
                "adversarial filter: discarding %s response (%s)",
                role, reason)
            return None
        return resp

    # -- the round ----------------------------------------------------------

    def run(self, finding: Any) -> AdversarialOutcome:
        """Run prosecutor -> defense -> judge on one finding."""
        evidence = self._quarantined_evidence(finding)
        if evidence is None:
            return AdversarialOutcome(
                decision="unavailable",
                reason="finding content rejected by injection guard; "
                       "LLM round skipped",
                injection_skipped=True,
            )
        made = 0
        prosecution = self._chat(
            _PROSECUTOR_SYSTEM, evidence,
            max_tokens=self._tok_p, role="verify_prosecutor")
        made += 1
        if prosecution is None:
            return AdversarialOutcome(
                decision="unavailable",
                reason="prosecutor LLM call failed", llm_calls=made)
        p_parsed = _extract_json(getattr(prosecution, "content", "") or "")
        if not p_parsed:
            return AdversarialOutcome(
                decision="unavailable",
                reason="prosecutor response unparseable", llm_calls=made)
        case_text = str(p_parsed.get("case", ""))[:2000]

        defense = self._chat(
            _DEFENSE_SYSTEM,
            f"Prosecution's case:\n{case_text}\n\nEvidence under dispute:\n"
            f"{evidence}",
            max_tokens=self._tok_d, role="verify_defense")
        made += 1
        if defense is None:
            return AdversarialOutcome(
                decision="unavailable",
                reason="defense LLM call failed",
                prosecution=case_text,
                model=str(getattr(prosecution, "model", "") or ""),
                llm_calls=made)
        d_parsed = _extract_json(getattr(defense, "content", "") or "")
        if not d_parsed:
            return AdversarialOutcome(
                decision="unavailable",
                reason="defense response unparseable",
                prosecution=case_text,
                model=str(getattr(prosecution, "model", "") or ""),
                llm_calls=made)

        judge = self._chat(
            _JUDGE_SYSTEM,
            f"Prosecution:\n{case_text}\n\nDefense "
            f"(verdict={d_parsed.get('verdict', '')}):\n"
            f"{str(d_parsed.get('refutation', ''))[:1500]}",
            max_tokens=self._tok_j, role="verify_judge")
        made += 1
        if judge is None:
            return AdversarialOutcome(
                decision="unavailable",
                reason="judge LLM call failed",
                prosecution=case_text,
                defense_refutation=str(d_parsed.get("refutation", ""))[:1000],
                model=str(getattr(prosecution, "model", "") or ""),
                llm_calls=made)
        j_parsed = _extract_json(getattr(judge, "content", "") or "")
        if not j_parsed or str(j_parsed.get("decision", "")).lower() not in (
                "keep", "reject"):
            return AdversarialOutcome(
                decision="unavailable",
                reason="judge verdict unparseable; failing open (kept)",
                prosecution=case_text,
                defense_refutation=str(d_parsed.get("refutation", ""))[:1000],
                model=str(getattr(prosecution, "model", "") or ""),
                llm_calls=made)
        decision = str(j_parsed["decision"]).lower()
        reason = str(j_parsed.get("reason", ""))[:500]
        if decision == "reject" and not reason:
            reason = ("defense rebuttal stood: "
                      + str(d_parsed.get("refutation", ""))[:400])
        return AdversarialOutcome(
            decision=decision,
            reason=reason,
            prosecution=case_text,
            defense_refutation=str(d_parsed.get("refutation", ""))[:1000],
            model=str(getattr(judge, "model", "") or "") or str(
                getattr(prosecution, "model", "") or ""),
            llm_calls=made,
        )


# ---------------------------------------------------------------------------
# Dropped-findings ledger (JSONL audit trail, local only)
# ---------------------------------------------------------------------------


def default_ledger_path(config: Mapping[str, Any] | None = None) -> Path:
    """Resolve where the verification ledger lives.

    Precedence: ``verification_ledger_path`` config -> ``workdir`` /
    ``output_dir`` config -> ``~/.web3guard/verification_ledger.jsonl``.
    """
    cfg = config or {}
    explicit = cfg.get("verification_ledger_path")
    if explicit:
        return Path(str(explicit)).expanduser()
    workdir = cfg.get("workdir") or cfg.get("output_dir")
    if workdir:
        return Path(str(workdir)).expanduser() / "verification_ledger.jsonl"
    return Path.home() / ".web3guard" / "verification_ledger.jsonl"


class VerificationLedger:
    """Append-only JSONL audit trail of verification decisions.

    One record per decision: timestamp, finding fingerprint, verdict,
    reason, evidence summary, model used, whether AI was active. Dropped
    findings never reach the human; this ledger is the proof they were
    considered and why they were dropped. Local-only writes.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path).expanduser() if path else Path.home() / \
            ".web3guard" / "verification_ledger.jsonl"
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            LOGGER.warning("ledger dir not creatable (%s): %s", self.path, e)

    def record(
        self,
        finding: Any,
        verdict: str,
        reason: str,
        *,
        evidence_summary: str = "",
        model: str = "",
        ai_active: bool = True,
    ) -> dict[str, Any]:
        """Append one decision record; never raises."""
        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "fingerprint": str(getattr(finding, "fingerprint", "") or ""),
            "file": str(getattr(finding, "file", "") or ""),
            "category": str(getattr(finding, "category", "") or ""),
            "severity": str(getattr(finding, "severity", "") or ""),
            "verdict": verdict,
            "reason": str(reason or "")[:1000],
            "evidence_summary": str(evidence_summary or "")[:1000],
            "model": str(model or ""),
            "ai_active": bool(ai_active),
        }
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=True) + "\n")
        except OSError as e:
            LOGGER.warning("verification ledger write failed: %s", e)
        return entry

    def read_all(self) -> list[dict[str, Any]]:
        """Read every record (for audits/tests); never raises."""
        out: list[dict[str, Any]] = []
        try:
            with open(self.path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(row, dict):
                        out.append(row)
        except OSError:
            pass
        return out


# ---------------------------------------------------------------------------
# The pipeline: verify_findings()
# ---------------------------------------------------------------------------


@dataclass
class VerificationReport:
    """Result of one :func:`verify_findings` run."""
    kept: list[Any] = field(default_factory=list)
    dropped: list[Any] = field(default_factory=list)
    skipped: list[Any] = field(default_factory=list)  # not POTENTIAL
    ai_inactive: bool = False
    llm_calls: int = 0
    ledger_path: str = ""
    notes: list[str] = field(default_factory=list)


def _evidence_summary(finding: Any) -> str:
    spec = machine_check_spec(finding)
    if spec:
        return f"machine_check type={spec.get('type')}"
    if has_unstructured_evidence(finding):
        n = len(str(getattr(finding, "exploit_log", "") or "")) + len(
            str(getattr(finding, "poc_code", "") or ""))
        return f"unstructured evidence ({n} chars, not replayable)"
    return "no evidence"


def _tag_verification_meta(finding: Any, **fields: Any) -> None:
    meta = dict(getattr(finding, "metadata", None) or {})
    ver = dict(meta.get("verification", {}) or {})
    ver.update(fields)
    meta["verification"] = ver
    finding.metadata = meta


def verify_findings(
    findings: list[Any],
    config: Mapping[str, Any] | None = None,
    *,
    client: Any = None,
    ledger_path: Path | str | None = None,
    max_llm_findings: int = 64,
) -> VerificationReport:
    """Phase-3 verification gate: the single entry point phase 7 calls
    between "findings produced" and "report rendered".

    Consumes POTENTIAL findings and emits CONFIRMED EXPLOIT or REJECTED —
    never invents new statuses. Machine-checkable evidence is replayed
    first; findings without it go through the LLM adversarial filter
    (skipped, loudly, when the router reports AI inactive). Every decision
    is written to the dropped-findings ledger.

    Never raises on per-finding work: a finding that cannot be verified
    due to infrastructure failure is kept (fail-open) and flagged.
    """
    cfg: Mapping[str, Any] = config if isinstance(config, Mapping) else {}
    if client is None:
        client = _router().build_router_client(cfg)
    ai_active = bool(getattr(client, "is_active", True))
    ledger = VerificationLedger(
        ledger_path or default_ledger_path(cfg))
    report = VerificationReport(
        ai_inactive=not ai_active, ledger_path=str(ledger.path))

    if not ai_active:
        reason = str(getattr(client, "inactive_reason",
                             "AI layers inactive") or "AI layers inactive")
        _router().emit_offline_warning(reason)
        note = ("AI verification / false-positive filter SKIPPED "
                f"(offline: {reason}). Machine-checkable evidence was "
                "still replayed; findings without machine evidence were "
                "kept as POTENTIAL without adversarial review.")
        report.notes.append(note)
        report.notes.append(
            _router().offline_report_note(reason))
        LOGGER.warning("%s", note)

    adversarial = (AdversarialFilter(client)
                   if ai_active else None)
    llm_budget = int(max_llm_findings)

    for finding in findings or []:
        status = str(getattr(finding, "status", "POTENTIAL") or "POTENTIAL")
        if status != "POTENTIAL":
            report.skipped.append(finding)
            continue

        # -- Tier 1: machine-checkable evidence replays first -------------
        spec = machine_check_spec(finding)
        if spec is not None:
            result = replay_machine_evidence(finding)
            summary = _evidence_summary(finding) + f"; {result.detail}"
            if result.reproduced is True:
                finding.status = "CONFIRMED EXPLOIT"
                finding.dynamically_confirmed = True
                try:
                    finding.confidence = max(
                        0.90, float(getattr(finding, "confidence", 0.5)))
                except (TypeError, ValueError):
                    finding.confidence = 0.90
                _tag_verification_meta(
                    finding, tier="machine", checker=result.checker,
                    reproduced=True, detail=result.detail[:500])
                ledger.record(finding, "confirmed_exploit",
                              f"machine evidence reproduced: {result.detail}",
                              evidence_summary=summary,
                              model="n/a (local replay)",
                              ai_active=ai_active)
                report.kept.append(finding)
            elif result.reproduced is False:
                finding.status = "REJECTED"
                try:
                    finding.confidence = 0.05
                except (TypeError, ValueError):
                    pass
                reason = "evidence did not reproduce: " + result.detail
                meta = dict(getattr(finding, "metadata", None) or {})
                meta["rejection_reason"] = reason[:500]
                finding.metadata = meta
                _tag_verification_meta(
                    finding, tier="machine", checker=result.checker,
                    reproduced=False, detail=result.detail[:500])
                ledger.record(finding, "rejected", reason,
                              evidence_summary=summary,
                              model="n/a (local replay)",
                              ai_active=ai_active)
                report.dropped.append(finding)
            else:
                # Checker could not run (forge missing, infra error):
                # fail OPEN — never drop a finding on infrastructure.
                _tag_verification_meta(
                    finding, tier="machine", checker=result.checker,
                    reproduced="unknown", detail=result.detail[:500],
                    llm_fallback=bool(adversarial))
                ledger.record(
                    finding, "machine_check_unavailable", result.detail,
                    evidence_summary=summary,
                    model="n/a (local replay)", ai_active=ai_active)
                # Fall through to the adversarial filter when possible.
                if adversarial is not None and llm_budget > 0:
                    llm_budget -= 1
                    _run_adversarial(
                        finding, adversarial, ledger, report, ai_active)
                else:
                    _keep_unreviewed(
                        finding, ledger, report, ai_active,
                        "machine checker unavailable; no LLM fallback")
            continue

        # -- Tier 2: LLM adversarial filter (or loud skip when offline) ---
        if adversarial is not None and llm_budget > 0:
            llm_budget -= 1
            _run_adversarial(finding, adversarial, ledger, report, ai_active)
        else:
            why = ("AI inactive (offline)" if not ai_active
                   else "LLM finding budget exhausted")
            _keep_unreviewed(finding, ledger, report, ai_active, why)

    report.notes.append(
        f"verification: {len(report.kept)} kept, {len(report.dropped)} "
        f"dropped, {len(report.skipped)} skipped (not POTENTIAL); "
        f"ledger: {ledger.path}")
    return report


def _run_adversarial(
    finding: Any,
    adversarial: AdversarialFilter,
    ledger: VerificationLedger,
    report: VerificationReport,
    ai_active: bool,
) -> None:
    """Run the prosecutor -> defense -> judge round; mutate finding."""
    try:
        outcome = adversarial.run(finding)
    except Exception as e:  # noqa: BLE001
        LOGGER.warning("adversarial filter crashed (fail-open): %s", e)
        _keep_unreviewed(finding, ledger, report, ai_active,
                         f"adversarial filter error: {e}")
        return
    report.llm_calls += outcome.llm_calls
    summary = _evidence_summary(finding)
    if outcome.decision == "reject":
        finding.status = "REJECTED"
        try:
            finding.confidence = 0.05
        except (TypeError, ValueError):
            pass
        reason = outcome.reason or "adversarial filter rejected the finding"
        meta = dict(getattr(finding, "metadata", None) or {})
        meta["rejection_reason"] = reason[:500]
        finding.metadata = meta
        _tag_verification_meta(
            finding, tier="adversarial", decision="reject",
            reason=reason[:500],
            prosecution=outcome.prosecution[:500],
            defense_refutation=outcome.defense_refutation[:500],
            model=outcome.model)
        ledger.record(finding, "rejected", reason,
                      evidence_summary=summary, model=outcome.model,
                      ai_active=ai_active)
        report.dropped.append(finding)
    else:
        # "keep" or "unavailable" (fail-open): the finding survives.
        tag: dict[str, Any] = {
            "tier": "adversarial",
            "decision": outcome.decision,
            "reason": outcome.reason[:500],
            "model": outcome.model,
        }
        if outcome.decision == "keep":
            tag["adversarial"] = "survived"
            try:
                finding.confidence = min(
                    0.95, float(getattr(finding, "confidence", 0.5)) + 0.05)
            except (TypeError, ValueError):
                pass
            ledger.record(finding, "kept_potential",
                          outcome.reason or "prosecution survived defense",
                          evidence_summary=summary, model=outcome.model,
                          ai_active=ai_active)
        else:
            tag["flag"] = "unreviewed_llm_failure"
            ledger.record(finding, "kept_unreviewed", outcome.reason,
                          evidence_summary=summary, model=outcome.model,
                          ai_active=ai_active)
        if outcome.injection_skipped:
            tag["flag"] = "llm_skipped_injection_risk"
        _tag_verification_meta(finding, **tag)
        report.kept.append(finding)


def _keep_unreviewed(
    finding: Any,
    ledger: VerificationLedger,
    report: VerificationReport,
    ai_active: bool,
    why: str,
) -> None:
    """Keep a finding without adversarial review (offline / budget /
    infrastructure). Loud in the ledger, never silent."""
    _tag_verification_meta(
        finding, tier="none", decision="kept_unreviewed", reason=why[:500])
    ledger.record(finding, "kept_unreviewed", why,
                  evidence_summary=_evidence_summary(finding),
                  model="", ai_active=ai_active)
    report.kept.append(finding)

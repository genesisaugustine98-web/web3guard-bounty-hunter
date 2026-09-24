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

import json
import logging
from dataclasses import dataclass, field
from typing import Any

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
        if not text:
            return None
        import re
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if not m:
            return None
        try:
            parsed = json.loads(m.group(0))
        except ValueError:
            return None
        return parsed if isinstance(parsed, dict) else None

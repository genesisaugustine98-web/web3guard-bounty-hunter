"""Machine-verified confirmation gate for exploit findings.

Industry-standard "no fakes, no hallucination" rule: a finding earns
``CONFIRMED EXPLOIT`` status **only** from reproducible machine evidence,
never from an LLM's opinion. Every check here is deterministic and
re-runnable:

1. **Grounding** — the finding's source file must resolve on disk and its
   SHA-256 hash is recorded at confirmation time (no ghost findings, and
   later integrity checks can detect the evidence no longer matches the
   code).
2. **Impact evidence** — the sandbox run must emit a non-zero
   machine-readable impact marker (``impact_gain:`` / ``impact_loss:``).
   "1 passed" is not evidence; silent success confirms nothing.
3. **Negative control** — where a differential patch mutator exists for
   the category, the same PoC must FAIL on the patched copy. Without a
   negative control the finding can still confirm, but its confidence is
   capped (an honest downgrade, not an invented upgrade).
4. **Replay** — the PoC must reproduce non-zero impact on an independent
   second sandbox run. One lucky pass is not reproducibility.
5. **Integrity re-check** — the source hash is re-verified before
   replay, binding the evidence to the exact bytes that were analyzed.

The gate is deliberately separate from the LLM exploit loop so it can be
unit-tested without any model and reused by any caller that holds a
sandbox factory.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

LOGGER = logging.getLogger("web3guard.security.confirmation")

# Findings confirmed without a negative control (no differential mutator
# for their category) are held at this ceiling so reports can always
# distinguish "fully verified" from "verified, less controlled".
NO_NEGATIVE_CONTROL_CAP = 0.92

SandboxFactory = Callable[..., Any]


class _SandboxLike(Protocol):
    def write_and_run(self, code: str, fingerprint: str,
                      timeout: int = 90) -> tuple[bool, str]: ...


@dataclass
class ConfirmationVerdict:
    """Outcome of the confirmation gate for one finding."""
    confirmed: bool
    reason: str
    checks: dict[str, str] = field(default_factory=dict)
    impact_gain: int = 0
    impact_loss: int = 0
    source_sha256: str = ""

    @property
    def negative_control(self) -> str:
        return self.checks.get("negative_control", "absent")


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


class ConfirmationGate:
    """Run the evidence checklist that stands between a PoC and status.

    ``sandbox_factory`` is typically :func:`web3guard.sandbox.create_sandbox`
    (patched in tests). ``differential_fn`` is
    :func:`web3guard.sandbox.differential.run_differential`. Both are
    injected so the gate owns policy, not plumbing.
    """

    def __init__(
        self,
        sandbox_factory: SandboxFactory,
        differential_fn: Callable[..., Any] | None,
        extract_impact: Callable[[str], Any] | None,
        workdir: Path,
        *,
        fork_url: str | None = None,
        replay_timeout: int = 120,
        require_negative_control: bool = False,
    ) -> None:
        self._sandbox_factory = sandbox_factory
        self._differential_fn = differential_fn
        self._extract_impact = extract_impact
        self._workdir = workdir
        self._fork_url = fork_url
        self._replay_timeout = replay_timeout
        self._require_negative_control = require_negative_control

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _ground(self, target_path: Path, finding: Any) -> Path | None:
        """Resolve the finding's file and bind its hash.

        Returns the resolved path, or None when the finding cannot be
        grounded (ghost finding). The SHA-256 is stored in
        ``finding.metadata["source_sha256"]``.
        """
        candidate = target_path / str(finding.file)
        path = candidate if candidate.is_file() else Path(str(finding.file))
        if not path.is_file():
            return None
        finding.metadata["source_sha256"] = file_sha256(path)
        return path

    @staticmethod
    def _impact_of(output: str) -> tuple[int, int] | None:
        """Return (gain, loss) when the output carries non-zero machine
        impact evidence, else None (no markers, or all-zero)."""
        from web3guard.languages.base import parse_impact_marker
        evidence = parse_impact_marker(output or "")
        if evidence is None or not evidence.confirmed:
            return None
        return evidence.gain, evidence.loss

    def _negative_control(
        self, adapter: Any, target_path: Path, finding: Any, poc_code: str,
        fingerprint: str,
    ) -> str:
        """Return the differential status, or ``"absent"`` when no
        mutator exists for the category. Any non-``confirmed`` outcome
        fails the finding — the exploit must NOT survive the patch."""
        if self._differential_fn is None:
            return "absent"
        try:
            outcome = self._differential_fn(
                adapter, target_path, self._workdir, poc_code, fingerprint,
                finding.category, fork_url=self._fork_url,
            )
        except Exception as e:  # noqa: BLE001
            LOGGER.warning("differential confirmation failed: %s", e)
            return "differential-error"
        return str(getattr(outcome, "status", "differential-error"))

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def evaluate(
        self,
        finding: Any,
        adapter: Any,
        target_path: Path,
        poc_code: str,
        first_run_ok: bool,
        first_run_output: str,
    ) -> ConfirmationVerdict:
        """Apply the full checklist. Mutates ``finding.metadata`` only;
        the caller decides whether to flip status."""
        checks: dict[str, str] = {}
        source_sha = ""

        # 1. Grounding — no file, no confirmation.
        ground_path = self._ground(target_path, finding)
        if ground_path is None:
            return ConfirmationVerdict(
                False, f"source file not found: {finding.file}", checks)
        source_sha = str(finding.metadata.get("source_sha256", ""))
        checks["grounding"] = "bound"
        checks["source_sha256"] = source_sha[:12]

        # 2. Impact evidence — the first sandbox run must have passed AND
        #    emitted non-zero machine markers.
        if not first_run_ok:
            return ConfirmationVerdict(False, "sandbox run failed", checks)
        impact = self._impact_of(first_run_output)
        if impact is None:
            return ConfirmationVerdict(
                False, "no non-zero impact evidence in sandbox output", checks)
        gain, loss = impact
        checks["impact_evidence"] = f"gain={gain} loss={loss}"

        # 3. Negative control — patch the vulnerability, exploit must die.
        diff_status = self._negative_control(
            adapter, target_path, finding, poc_code,
            finding.fingerprint or "exploit",
        )
        checks["negative_control"] = diff_status
        if diff_status in ("patched-still-passes", "vulnerable-failed",
                           "differential-error"):
            return ConfirmationVerdict(
                False, f"negative control failed: {diff_status}", checks,
                impact_gain=gain, impact_loss=loss, source_sha256=source_sha)
        if (diff_status in ("absent", "no-mutator")
                and self._require_negative_control):
            return ConfirmationVerdict(
                False,
                "negative control unavailable for category "
                f"({diff_status}) and strict mode is on", checks,
                impact_gain=gain, impact_loss=loss, source_sha256=source_sha)

        # 4+5. Replay on an independent second sandbox run, after
        #     re-verifying the source bytes still hash to what we bound.
        #     A mutation between grounding and replay (TOCTOU) must fail
        #     loudly instead of confirming against different bytes.
        if file_sha256(ground_path) != source_sha:
            return ConfirmationVerdict(
                False, "source changed during confirmation "
                "(hash mismatch before replay)", checks,
                impact_gain=gain, impact_loss=loss, source_sha256=source_sha)
        checks["source_reverified"] = "bound"
        replay = self._sandbox_factory(
            adapter, target_path, self._workdir, fork_url=self._fork_url)
        if replay is None:
            return ConfirmationVerdict(
                False, "replay sandbox init failed", checks,
                impact_gain=gain, impact_loss=loss, source_sha256=source_sha)
        try:
            replay_ok, replay_out = replay.write_and_run(
                poc_code, f"{finding.fingerprint or 'exploit'}-replay",
                timeout=self._replay_timeout)
        except Exception as e:  # noqa: BLE001
            return ConfirmationVerdict(
                False, f"replay run error: {e}", checks,
                impact_gain=gain, impact_loss=loss, source_sha256=source_sha)
        replay_impact = self._impact_of(replay_out) if replay_ok else None
        checks["replay"] = (
            f"gain={replay_impact[0]} loss={replay_impact[1]}"
            if replay_impact else "failed")
        if replay_impact is None:
            return ConfirmationVerdict(
                False, "replay did not reproduce non-zero impact", checks,
                impact_gain=gain, impact_loss=loss, source_sha256=source_sha)

        return ConfirmationVerdict(
            True, "all checks passed", checks,
            impact_gain=gain, impact_loss=loss, source_sha256=source_sha)


def apply_verdict(finding: Any, verdict: ConfirmationVerdict) -> None:
    """Flip a finding to CONFIRMED only on a passing verdict.

    Findings confirmed without a negative control keep CONFIRMED status
    (the impact evidence is real) but carry the confidence cap and a
    metadata marker so downstream consumers can treat them honestly.
    """
    finding.metadata["confirmation"] = {
        "confirmed": verdict.confirmed,
        "reason": verdict.reason,
        "checks": dict(verdict.checks),
    }
    if verdict.confirmed:
        finding.status = "CONFIRMED EXPLOIT"
        finding.metadata["impact_gain"] = verdict.impact_gain
        finding.metadata["impact_loss"] = verdict.impact_loss
        if verdict.negative_control in ("absent", "no-mutator"):
            finding.confidence = min(finding.confidence, NO_NEGATIVE_CONTROL_CAP)
            finding.metadata["confirmation"]["negative_control"] = "absent"
        if verdict.source_sha256:
            finding.metadata["source_sha256"] = verdict.source_sha256

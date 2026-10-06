"""Tests for the machine-verified confirmation gate (v3.4).

"No fakes, no hallucination": a finding earns CONFIRMED EXPLOIT only
from reproducible machine evidence. These tests pin every gate check —
impact evidence, negative control, replay, source binding — plus the
path that routes static discovery findings through the same loop.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.sandbox.differential import DifferentialOutcome  # noqa: E402
from web3guard.scanner import Scanner  # noqa: E402
from web3guard.security.confirmation import (  # noqa: E402
    NO_NEGATIVE_CONTROL_CAP,
    ConfirmationGate,
    apply_verdict,
)

_VAULT = (
    "pragma solidity ^0.8.0;\n"
    "contract Vault {\n"
    "    mapping(address => uint) public balances;\n"
    "    function withdraw() public {\n"
    "        uint amt = balances[msg.sender];\n"
    "        (bool ok, ) = msg.sender.call{value: amt}(\"\");\n"
    "        balances[msg.sender] = 0;\n"
    "    }\n"
    "}\n"
)


class _Adapter:
    """Minimal Solidity-like adapter for gate unit tests."""

    class _Runner:
        name = "foundry"
        runtime_confirmable = True

    language = type("L", (), {"value": "solidity"})()
    test_runner = _Runner()


class _Finding:
    """Duck-typed finding (avoids depending on dataclass internals)."""

    def __init__(self, file: str = "Vault.sol", category: str = "reentrancy",
                 fingerprint: str = "fp1", confidence: float = 0.9):
        self.target = "t"
        self.language = "solidity"
        self.file = file
        self.function = "withdraw"
        self.category = category
        self.severity = "HIGH"
        self.confidence = confidence
        self.status = "POTENTIAL"
        self.fingerprint = fingerprint
        self.line_hint = "5-7"
        self.poc_code = ""
        self.exploit_log = ""
        self.metadata: dict = {}


class _SeqSandbox:
    """Sandbox returning a scripted (ok, output) sequence."""

    def __init__(self, outcomes: list[tuple[bool, str]]) -> None:
        self._outcomes = list(outcomes)
        self.calls: list[str] = []

    def write_and_run(self, code: str, fingerprint: str, timeout: int = 90):
        self.calls.append(fingerprint)
        return self._outcomes.pop(0) if self._outcomes else (False, "exhausted")


class _SeqFactory:
    def __init__(self, per_instance: list[tuple[bool, str]]) -> None:
        self._per_instance = per_instance
        self.instances = 0

    def __call__(self, *a, **k):
        self.instances += 1
        return _SeqSandbox(list(self._per_instance))


_IMPACT = (True, "impact_gain: 100\n1 passed")


@pytest.fixture
def target(tmp_path: Path) -> Path:
    (tmp_path / "Vault.sol").write_text(_VAULT, encoding="utf-8")
    return tmp_path


def _gate(factory, differential=None, **kw) -> ConfirmationGate:
    return ConfirmationGate(
        sandbox_factory=factory,
        differential_fn=differential,
        extract_impact=None,
        workdir=Path("/tmp"),
        **kw,
    )


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def test_ghost_file_is_refused(tmp_path: Path) -> None:
    gate = _gate(_SeqFactory([_IMPACT, _IMPACT]))
    verdict = gate.evaluate(_Finding(file="missing.sol"), _Adapter(),
                            tmp_path, "// poc", True, "impact_gain: 1")
    assert not verdict.confirmed
    assert "not found" in verdict.reason
    assert verdict.checks.get("grounding") is None


def test_nested_basename_is_grounded_recursively(tmp_path: Path) -> None:
    """A finding carrying only a bare filename (e.g. Cairo's ``src/``
    layout) grounds via recursive basename search under the target."""
    nested = tmp_path / "src"
    nested.mkdir()
    (nested / "reward.cairo").write_text("// cairo", encoding="utf-8")
    gate = _gate(_SeqFactory([_IMPACT, _IMPACT]))
    finding = _Finding(file="reward.cairo")
    path = gate._ground(tmp_path, finding)
    assert path == nested / "reward.cairo"
    assert finding.metadata["source_sha256"]


def test_ambiguous_basename_is_not_grounded(tmp_path: Path) -> None:
    """Two files with the same basename: grounding refuses to guess."""
    for sub in ("a", "b"):
        d = tmp_path / sub
        d.mkdir()
        (d / "dup.cairo").write_text("// cairo", encoding="utf-8")
    gate = _gate(_SeqFactory([_IMPACT, _IMPACT]))
    assert gate._ground(tmp_path, _Finding(file="dup.cairo")) is None


def test_no_impact_evidence_is_refused(target: Path) -> None:
    """A sandbox pass with no machine markers confirms nothing."""
    gate = _gate(_SeqFactory([_IMPACT]))
    verdict = gate.evaluate(_Finding(), _Adapter(), target, "// poc",
                            True, "1 passed; 0 failed")
    assert not verdict.confirmed
    assert "no non-zero impact evidence" in verdict.reason


def test_zero_impact_is_refused(target: Path) -> None:
    gate = _gate(_SeqFactory([_IMPACT]))
    verdict = gate.evaluate(_Finding(), _Adapter(), target, "// poc",
                            True, "impact_gain: 0")
    assert not verdict.confirmed


def test_failing_first_run_is_refused(target: Path) -> None:
    gate = _gate(_SeqFactory([_IMPACT]))
    verdict = gate.evaluate(_Finding(), _Adapter(), target, "// poc",
                            False, "Assertion failed")
    assert not verdict.confirmed
    assert "sandbox run failed" in verdict.reason


def test_patched_still_passing_blocks_confirmation(target: Path) -> None:
    """Negative control: exploit surviving the patch kills the finding."""
    gate = _gate(_SeqFactory([_IMPACT, _IMPACT]),
                 differential=lambda *a, **k: DifferentialOutcome(
                     "patched-still-passes"))
    verdict = gate.evaluate(_Finding(), _Adapter(), target, "// poc",
                            True, "impact_gain: 100")
    assert not verdict.confirmed
    assert "negative control failed" in verdict.reason


def test_replay_failure_blocks_confirmation(target: Path) -> None:
    """One lucky pass is not reproducibility."""
    # The gate only builds the replay sandbox (the first run belongs to
    # the caller), so the script holds the replay outcome alone.
    factory = _SeqFactory([(False, "replay assertion failed")])
    gate = _gate(factory, differential=lambda *a, **k: DifferentialOutcome(
        "confirmed"))
    verdict = gate.evaluate(_Finding(), _Adapter(), target, "// poc",
                            True, "impact_gain: 100")
    assert not verdict.confirmed
    assert "replay" in verdict.reason
    assert factory.instances == 1  # replay used a fresh sandbox instance


def test_source_hash_is_bound_and_rechecked(target: Path) -> None:
    """Integrity: evidence must not survive a mutation of the source."""
    factory = _SeqFactory([(False, "assertion failed")])
    gate = _gate(factory, differential=lambda *a, **k: DifferentialOutcome(
        "confirmed"))
    finding = _Finding()
    verdict = gate.evaluate(finding, _Adapter(), target, "// poc",
                            True, "impact_gain: 100")
    assert not verdict.confirmed
    # The hash bound at grounding time is recorded in metadata.
    assert finding.metadata["source_sha256"]


def test_full_pass_confirms_with_evidence(target: Path) -> None:
    factory = _SeqFactory([_IMPACT, _IMPACT])
    gate = _gate(factory, differential=lambda *a, **k: DifferentialOutcome(
        "confirmed"))
    verdict = gate.evaluate(_Finding(), _Adapter(), target, "// poc",
                            True, "impact_gain: 100")
    assert verdict.confirmed
    assert verdict.impact_gain == 100
    assert verdict.checks["grounding"] == "bound"
    assert verdict.checks["negative_control"] == "confirmed"
    assert verdict.checks["replay"].startswith("gain=100")
    assert verdict.source_sha256


def test_absent_negative_control_caps_confidence(target: Path) -> None:
    """Without a mutator the finding still confirms, but honestly downgraded."""
    factory = _SeqFactory([_IMPACT, _IMPACT])
    gate = _gate(factory, differential=lambda *a, **k: DifferentialOutcome(
        "no-mutator"))
    finding = _Finding(confidence=0.95)
    verdict = gate.evaluate(finding, _Adapter(), target, "// poc",
                            True, "impact_gain: 100")
    assert verdict.confirmed
    apply_verdict(finding, verdict)
    assert finding.status == "CONFIRMED EXPLOIT"
    assert finding.confidence == NO_NEGATIVE_CONTROL_CAP
    assert finding.metadata["confirmation"]["negative_control"] == "absent"


def test_strict_mode_refuses_without_negative_control(target: Path) -> None:
    factory = _SeqFactory([_IMPACT, _IMPACT])
    gate = _gate(factory, differential=None, require_negative_control=True)
    verdict = gate.evaluate(_Finding(), _Adapter(), target, "// poc",
                            True, "impact_gain: 100")
    assert not verdict.confirmed
    assert "negative control" in verdict.reason


# ---------------------------------------------------------------------------
# Scanner integration: static discovery findings reach confirmation
# ---------------------------------------------------------------------------


class _StaticOnlyAIClient:
    """Analysis says 'clean' (no AI finding); exploit role returns a PoC."""

    def __init__(self, poc_code: str) -> None:
        self._poc = poc_code

    def chat(self, system: str, user: str, **kwargs):
        role = kwargs.get("role", "analysis")

        class _R:
            content = ""

        if role == "exploit":
            _R.content = f"```solidity\n{self._poc}\n```"
        else:
            _R.content = json.dumps({"status": "clean"})
        return _R()

    class _Cost:
        def summary(self):
            return {"total_cost_usd": 0.0}

    def cost_tracker(self):
        return self._Cost()


_VALID_POC = (
    "pragma solidity ^0.8.0;\n"
    "import \"forge-std/Test.sol\";\n"
    "contract ExploitTest is Test {\n"
    "    function test_exploit() public {\n"
    "        uint before = 100;\n"
    "        uint after = 0;\n"
    "        assertEq(after, 0);\n"
    "        assert(after < before);\n"
    '        emit log_named_uint("impact_gain", before - after);\n'
    "    }\n"
    "}\n"
)


class _AlwaysPassSandbox:
    def write_and_run(self, code: str, fingerprint: str, timeout: int = 90):
        return True, "impact_gain: 100\nPASSED"


def _static_target(tmp_path: Path) -> Path:
    (tmp_path / "Vault.sol").write_text(_VAULT, encoding="utf-8")
    return tmp_path


def _scan_cfg(**over) -> dict:
    cfg = {
        "enable_ai_analysis": True,
        "enable_discovery": True,
        "enable_exploit": True,
        "max_exploit_attempts": 1,
        "enable_differential": True,
        "enable_runtime_confirmation": True,
        "runtime_confirmation_min_severity": "MEDIUM",
        "enable_reachability": False,
        "enable_self_critique": False,
        "enable_economic_analyzer": False,
        "enable_secret_scan": False,
        "enable_attack_sequence_brainstorm": False,
        "enable_role_map": False,
        "enable_verification_ensemble": False,
        "use_ai_planning": False,
    }
    cfg.update(over)
    return cfg


def _findings_by_file(result, suffix: str):
    return [f for f in result.targets[0].findings if f.file.endswith(suffix)]


def test_static_finding_reaches_confirmation(tmp_path: Path, monkeypatch):
    import web3guard.scanner as scanner_mod
    from web3guard import sandbox as sandbox_mod

    monkeypatch.setattr(sandbox_mod, "create_sandbox",
                        lambda *a, **k: _AlwaysPassSandbox())
    monkeypatch.setattr(scanner_mod, "run_differential",
                        lambda *a, **k: DifferentialOutcome("confirmed"))
    scanner = Scanner(config=_scan_cfg(), workdir=tmp_path,
                      ai_client=_StaticOnlyAIClient(_VALID_POC))
    result = scanner.scan([str(_static_target(tmp_path)) + "|max"])
    vault = _findings_by_file(result, "Vault.sol")
    assert vault, "static engine should flag the reentrancy vault"
    statuses = [f.status for f in vault]
    assert any(st == "CONFIRMED EXPLOIT" for st in statuses), statuses
    confirmed = [f for f in vault if f.status == "CONFIRMED EXPLOIT"][0]
    assert confirmed.metadata["confirmation"]["checks"]["negative_control"] \
        == "confirmed"
    assert confirmed.metadata["impact_gain"] == 100
    assert confirmed.poc_code  # evidence retained


def test_static_finding_without_evidence_stays_potential(
        tmp_path: Path, monkeypatch):
    from web3guard import sandbox as sandbox_mod

    class _NoMarker:
        def write_and_run(self, code, fingerprint, timeout=90):
            return True, "1 passed"

    monkeypatch.setattr(sandbox_mod, "create_sandbox",
                        lambda *a, **k: _NoMarker())
    scanner = Scanner(config=_scan_cfg(), workdir=tmp_path,
                      ai_client=_StaticOnlyAIClient(_VALID_POC))
    result = scanner.scan([str(_static_target(tmp_path)) + "|max"])
    vault = _findings_by_file(result, "Vault.sol")
    assert vault
    assert all("CONFIRMED" not in f.status for f in vault)


def test_low_severity_static_finding_skips_confirmation(
        tmp_path: Path, monkeypatch):
    """Below the severity floor the expensive loop is never entered."""
    from web3guard import sandbox as sandbox_mod

    class _Spy(_AlwaysPassSandbox):
        calls = 0

        def write_and_run(self, code, fingerprint, timeout=90):
            type(self).calls += 1
            return super().write_and_run(code, fingerprint, timeout)

    monkeypatch.setattr(sandbox_mod, "create_sandbox", lambda *a, **k: _Spy())
    scanner = Scanner(config=_scan_cfg(
        runtime_confirmation_min_severity="CRITICAL"),
        workdir=tmp_path, ai_client=_StaticOnlyAIClient(_VALID_POC))
    result = scanner.scan([str(_static_target(tmp_path)) + "|max"])
    vault = _findings_by_file(result, "Vault.sol")
    assert vault  # still discovered
    assert all(f.status != "CONFIRMED EXPLOIT" for f in vault)
    assert _Spy.calls == 0  # exploit loop never ran


def test_gate_disabled_keeps_static_findings_unconfirmed(
        tmp_path: Path, monkeypatch):
    """enable_runtime_confirmation=False is the kill switch: static
    findings never enter the exploit loop (v3.5 behavior)."""
    from web3guard import sandbox as sandbox_mod

    class _Spy(_AlwaysPassSandbox):
        calls = 0

        def write_and_run(self, code, fingerprint, timeout=90):
            type(self).calls += 1
            return super().write_and_run(code, fingerprint, timeout)

    monkeypatch.setattr(sandbox_mod, "create_sandbox", lambda *a, **k: _Spy())
    scanner = Scanner(config=_scan_cfg(enable_runtime_confirmation=False),
                      workdir=tmp_path,
                      ai_client=_StaticOnlyAIClient(_VALID_POC))
    result = scanner.scan([str(_static_target(tmp_path)) + "|max"])
    vault = _findings_by_file(result, "Vault.sol")
    assert vault  # still discovered and reported
    assert all(f.status != "CONFIRMED EXPLOIT" for f in vault)
    assert _Spy.calls == 0  # exploit loop never ran for static findings


# ---------------------------------------------------------------------------
# Mutation tests: the gate must not confirm against mutated source bytes
# ---------------------------------------------------------------------------


def test_toctou_mutation_before_replay_is_refused(target: Path) -> None:
    """Mutate the source between grounding and replay: the gate must
    refuse, not confirm against different bytes with the old hash.

    The mutation lands inside the negative-control step (the realistic
    TOCTOU window: grounding -> differential -> re-verify -> replay).
    """
    vault = target / "Vault.sol"
    original = vault.read_text(encoding="utf-8")

    def _mutating_differential(*a, **k):
        # Attacker (or a concurrent edit) patches the file after
        # grounding but before the replay re-verification.
        vault.write_text(original.replace(
            "balances[msg.sender] = 0;",
            "balances[msg.sender] = 0; // patched"), encoding="utf-8")
        return DifferentialOutcome("confirmed")

    factory = _SeqFactory([_IMPACT])
    gate = _gate(factory, differential=_mutating_differential)
    verdict = gate.evaluate(_Finding(), _Adapter(), target, "// poc",
                            True, "impact_gain: 100")
    assert not verdict.confirmed
    assert "changed during confirmation" in verdict.reason
    assert verdict.checks.get("source_reverified") is None
    # The bound hash still refers to the pre-mutation bytes.
    assert verdict.source_sha256


def test_mutation_after_grounding_keeps_original_hash(target: Path) -> None:
    """Even when refused, the verdict's hash must identify the bytes that
    were actually analyzed — never the mutated ones."""
    import hashlib
    vault = target / "Vault.sol"
    original = vault.read_text(encoding="utf-8")
    original_hash = hashlib.sha256(original.encode()).hexdigest()

    def _mutating_differential(*a, **k):
        vault.write_text(original + "\n// trailing comment\n",
                         encoding="utf-8")
        return DifferentialOutcome("confirmed")

    factory = _SeqFactory([_IMPACT])
    gate = _gate(factory, differential=_mutating_differential)
    verdict = gate.evaluate(_Finding(), _Adapter(), target, "// poc",
                            True, "impact_gain: 100")
    assert not verdict.confirmed
    assert verdict.source_sha256 == original_hash


def test_unmutated_source_passes_reverification(target: Path) -> None:
    """Sanity: without mutation the new re-verification check passes and
    a fully-evidenced finding still confirms."""
    factory = _SeqFactory([_IMPACT])
    gate = _gate(factory, differential=lambda *a, **k: DifferentialOutcome(
        "confirmed"))
    verdict = gate.evaluate(_Finding(), _Adapter(), target, "// poc",
                            True, "impact_gain: 100")
    assert verdict.confirmed
    assert verdict.checks["source_reverified"] == "bound"


def test_negative_control_mutation_kills_exploit(target: Path) -> None:
    """The differential mutator patches the vuln; if the PoC still passes
    on the patched copy, confirmation is refused (exploit not specific)."""
    factory = _SeqFactory([_IMPACT])
    gate = _gate(factory, differential=lambda *a, **k: DifferentialOutcome(
        "patched-still-passes"))
    verdict = gate.evaluate(_Finding(), _Adapter(), target, "// poc",
                            True, "impact_gain: 100")
    assert not verdict.confirmed
    assert "negative control failed" in verdict.reason

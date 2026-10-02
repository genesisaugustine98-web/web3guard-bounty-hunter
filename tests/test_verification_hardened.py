"""Phase 4 hardening tests: the verification lie detector under attack.

All LLM clients here are fakes with scripted responses — no keys, no
network. The fixtures model the adversarial campaign's trust-killers:

- ROGUE judge: always confirms (high confidence, no cited evidence).
- TIMEOUT fixture: raises TimeoutError on judge roles.
- DISAGREEING judges: judge 1 keeps, judge 2 rejects (and vice versa).

Machine-evidence replays use a fake ``forge`` shell script on a
monkeypatched PATH (never the real toolchain), plus direct unit tests of
the kill-code detection.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from web3guard.ai import verification as V
from web3guard.scanner import Finding

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class RoleScriptClient:
    """Fake client: scripted response per role; unscripted roles get "{}"."""

    def __init__(self, scripts: dict[str, str],
                 model: str = "fake-model") -> None:
        self.scripts = dict(scripts)
        self.calls: list[dict[str, Any]] = []
        self.is_active = True
        self.inactive_reason = ""
        self.model = model

    def chat(self, system: str, user: str, **kwargs: Any) -> Any:
        role = str(kwargs.get("role", ""))
        self.calls.append({"role": role, "system": system, "user": user})
        content = self.scripts.get(role, "{}")
        return SimpleNamespace(content=content, model=self.model,
                               raw={}, provider="fake")


class ExplodingClient(RoleScriptClient):
    """Fake client that raises on selected roles (timeouts / outages)."""

    def __init__(self, scripts: dict[str, str], fail_roles: set[str],
                 exc: type[BaseException] = TimeoutError) -> None:
        super().__init__(scripts)
        self.fail_roles = set(fail_roles)
        self.exc = exc

    def chat(self, system: str, user: str, **kwargs: Any) -> Any:
        role = str(kwargs.get("role", ""))
        if role in self.fail_roles:
            raise self.exc(f"simulated {self.exc.__name__} on {role}")
        return super().chat(system, user, **kwargs)


_finding_counter = 0


def _finding(**kw: Any) -> Finding:
    global _finding_counter
    f = Finding(
        target="t", language="solidity", file="Vault.sol",
        function="withdraw", category="reentrancy",
        severity="HIGH", confidence=0.6,
        description="External call before state update in withdraw().",
        reasoning="Claimed reentrant: msg.sender called before "
                  "balances[msg.sender]=0.",
        status="POTENTIAL",
        fingerprint="fp-hardened-" + str(_finding_counter),
    )
    _finding_counter += 1
    for k, v in kw.items():
        setattr(f, k, v)
    return f


def _ledger(tmp_path: Path) -> Path:
    return tmp_path / "ledger.jsonl"


def _read_ledger(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines()
            if line.strip()]


_PROSECUTOR_OK = json.dumps({
    "case": "Attacker calls withdraw(), reenters via fallback, drains funds.",
    "exploit_steps": ["call withdraw", "reenter in fallback", "drain"],
    "impact": "full vault drain",
})
_DEFENSE_PLAUSIBLE = json.dumps({
    "verdict": "plausible",
    "refutation": "",
    "benign_explanations": [],
})


def _judge_json(decision: str, confidence: Any = None,
                reason: str = "test reason",
                cited: list[str] | None = None) -> str:
    doc: dict[str, Any] = {"decision": decision, "reason": reason}
    if confidence is not None:
        doc["confidence"] = confidence
    if cited is not None:
        doc["cited_evidence"] = cited
    return json.dumps(doc)


# The ROGUE judge: always confirms, max confidence, zero cited evidence —
# exactly the shape the adversarial campaign showed poisons the filter.
_ROGUE_KEEP = _judge_json("keep", 0.99,
                          "definitely vulnerable, trust me",
                          cited=[])
_HONEST_KEEP = _judge_json(
    "keep", 0.82, "exploit steps concrete; no control breaks the chain",
    cited=["withdraw() makes external call before balances[msg.sender]=0",
           "no reentrancy guard on withdraw"])
_HONEST_REJECT = _judge_json(
    "reject", 0.88, "nonReentrant modifier on withdraw() blocks reentry",
    cited=["withdraw() carries OpenZeppelin nonReentrant",
           "checks-effects-interactions ordering in place"])


def _patch_runsandboxed(monkeypatch: pytest.MonkeyPatch,
                        rc: int, out: str = "", err: str = "") -> None:
    """Patch the sandbox runner to return a canned (rc, stdout, stderr),
    and make ``shutil.which("forge")`` resolve.

    The checker logic (kill-code mapping, output markers, expect
    validation) is what these tests pin down; the sandbox itself is
    covered by one real end-to-end test below.
    """
    import shutil as _shutil

    import web3guard.security.sandbox_guard as sg

    def fake(command: Any, *, cwd: Any, timeout: int,
             **kw: Any) -> tuple[int, str, str]:
        return (rc, out, err)

    monkeypatch.setattr(sg, "run_sandboxed", fake)
    real_which = _shutil.which

    def fake_which(cmd: Any, *a: Any, **k: Any) -> Any:
        if cmd == "forge":
            return "/fake/bin/forge"
        return real_which(cmd, *a, **k)

    monkeypatch.setattr(_shutil, "which", fake_which)


# Canned forge outputs (realistic shapes).
_FORGE_FAIL_OUT = (
    "Ran 1 test for test/Vault.t.sol:VaultTest\n"
    "[FAIL: assertion failed: 100 != 99] test_withdraw_drains() (gas: 12345)\n"
    "Suite result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 1.23s\n"
)
_FORGE_OK_OUT = (
    "Ran 1 test for test/Vault.t.sol:VaultTest\n"
    "[PASS] test_withdraw_ok() (gas: 9999)\n"
    "Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 0.50s\n"
)
_FORGE_COMPILE_ERROR_OUT = (
    "Compiler run failed:\n"
    "Error (1234): Identifier already declared.\n"
)


# ---------------------------------------------------------------------------
# (a) Rogue-always-confirm judge -> zero phantom CONFIRMEDs
# ---------------------------------------------------------------------------


def test_rogue_overconfident_judge_discarded_no_phantom_confirm(
        tmp_path: Path) -> None:
    """Rogue judge (keep @0.99, no citations) is discarded as uncalibrated;
    the honest second judge's reject leaves a lone reject after a primary
    failure -> ESCALATE. Never CONFIRMED, never silently dropped."""
    f = _finding()
    client = RoleScriptClient({
        "verify_prosecutor": _PROSECUTOR_OK,
        "verify_defense": _DEFENSE_PLAUSIBLE,
        "verify_judge": _ROGUE_KEEP,          # rogue primary
        "verify_judge_2": _HONEST_REJECT,     # honest second opinion
    })
    rep = V.verify_findings([f], {}, client=client,
                            ledger_path=_ledger(tmp_path))
    assert f.status == "POTENTIAL"            # kept visible...
    assert f.status != "CONFIRMED EXPLOIT"    # ...never phantom-confirmed
    assert rep.kept == [f] and not rep.dropped
    assert rep.escalated == [f]
    assert f.metadata["verification"]["decision"] == "escalate"
    assert f.metadata.get("manual_review_required") is True
    entries = _read_ledger(_ledger(tmp_path))
    assert entries[-1]["verdict"] == "escalate"
    assert entries[-1]["reason"]


def test_two_rogue_judges_cannot_mint_confirmed(tmp_path: Path) -> None:
    """Even when BOTH judges are rogue always-confirmers, the worst case
    is an unavailable panel -> kept unreviewed. Zero CONFIRMEDs."""
    f = _finding()
    client = RoleScriptClient({
        "verify_prosecutor": _PROSECUTOR_OK,
        "verify_defense": _DEFENSE_PLAUSIBLE,
        "verify_judge": _ROGUE_KEEP,
        "verify_judge_2": _ROGUE_KEEP,
    })
    rep = V.verify_findings([f], {}, client=client,
                            ledger_path=_ledger(tmp_path))
    assert f.status == "POTENTIAL"
    assert "CONFIRMED" not in f.status
    assert rep.kept == [f] and not rep.dropped
    assert f.metadata["verification"]["decision"] == "unavailable"


def test_rogue_plausible_keep_vs_honest_reject_escalates(
        tmp_path: Path) -> None:
    """A *believable* rogue (keep @0.8 WITH citations passes validation)
    vs an honest reject -> disagreement + no machine evidence ->
    ESCALATE. The finding stays visible; nothing is confirmed."""
    rogue_believable = _judge_json(
        "keep", 0.8, "looks exploitable to me",
        cited=["external call present"])  # passes schema+calibration
    f = _finding()
    client = RoleScriptClient({
        "verify_prosecutor": _PROSECUTOR_OK,
        "verify_defense": _DEFENSE_PLAUSIBLE,
        "verify_judge": rogue_believable,
        "verify_judge_2": _HONEST_REJECT,
    })
    rep = V.verify_findings([f], {}, client=client,
                            ledger_path=_ledger(tmp_path))
    assert f.status == "POTENTIAL"
    assert rep.escalated == [f] and not rep.dropped
    ver = f.metadata["verification"]
    assert ver["decision"] == "escalate"
    assert ver["judge_disagreement"] is True
    assert ver["uncertainty"]  # human-readable uncertainty stated


def test_rogue_judges_with_reproducing_machine_evidence_confirm(
        tmp_path: Path) -> None:
    """Disagreement + genuinely reproducing machine evidence ->
    CONFIRMED EXPLOIT (machine-decided — the sanctioned path)."""
    f = _finding()
    f.metadata["machine_check"] = {
        "type": "text_marker",
        "text": "forge output: invariant VIOLATED on [deposit, withdraw]",
        "marker": "VIOLATED",
    }
    client = RoleScriptClient({
        "verify_prosecutor": _PROSECUTOR_OK,
        "verify_defense": _DEFENSE_PLAUSIBLE,
        "verify_judge": _ROGUE_KEEP,
        "verify_judge_2": _HONEST_REJECT,
    })
    rep = V.verify_findings([f], {}, client=client,
                            ledger_path=_ledger(tmp_path))
    assert f.status == "CONFIRMED EXPLOIT"
    assert rep.kept == [f]
    entries = _read_ledger(_ledger(tmp_path))
    assert entries[-1]["verdict"] == "confirmed_exploit"


# ---------------------------------------------------------------------------
# (b) Timeouts / kills / errors -> UNKNOWN, never phantom CONFIRMED
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rc", [124, 137, 143, -9])
def test_kill_exit_codes_are_infrastructure_not_evidence(rc: int) -> None:
    assert V._killed_by_infrastructure(rc) is not None


@pytest.mark.parametrize("rc", [0, 1, 2, 101])
def test_normal_exit_codes_are_not_kills(rc: int) -> None:
    assert V._killed_by_infrastructure(rc) is None


def test_forge_timeout_exit_124_is_unknown_not_confirmed(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The campaign's HIGH killer: a killed (124) forge run under
    expect='fail' used to read as 'bug reproduced' -> phantom CONFIRMED.
    Now it is UNKNOWN."""
    _patch_runsandboxed(monkeypatch, 124, "", "timed out after 60s")
    result = V._check_forge_replay(
        {"project_dir": str(tmp_path), "expect": "fail"})
    assert result.reproduced is None
    assert "timeout" in result.detail


def test_forge_timeout_full_pipeline_never_confirms(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    f = _finding()
    _patch_runsandboxed(monkeypatch, 124, "", "timed out after 60s")
    f.metadata["machine_check"] = {
        "type": "forge_replay", "project_dir": str(tmp_path),
        "expect": "fail", "timeout_s": 60,
    }
    client = RoleScriptClient({
        "verify_prosecutor": _PROSECUTOR_OK,
        "verify_defense": _DEFENSE_PLAUSIBLE,
        "verify_judge": _HONEST_KEEP,
        "verify_judge_2": _HONEST_REJECT,  # disagree; machine can't arbitrate
    })
    rep = V.verify_findings([f], {}, client=client,
                            ledger_path=_ledger(tmp_path))
    assert f.status == "POTENTIAL"          # UNKNOWN -> kept visible
    assert f.status != "CONFIRMED EXPLOIT"
    assert rep.escalated == [f] and not rep.dropped
    entries = _read_ledger(_ledger(tmp_path))
    assert entries[0]["verdict"] == "machine_check_unavailable"
    assert "timeout" in entries[0]["reason"]
    assert entries[-1]["verdict"] == "escalate"


def test_command_timeout_is_unknown_not_rejection(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Mirror image: a timed-out *passing* replay must not read as
    'evidence did not reproduce' -> REJECTED. It is UNKNOWN."""
    _patch_runsandboxed(monkeypatch, 124, "", "timed out after 60s")
    result = V._check_command(
        {"argv": ["echo", "hi"], "cwd": str(tmp_path),
         "expect_exit": 0, "timeout_s": 60})
    assert result.reproduced is None
    assert "timeout" in result.detail


def test_forge_compile_error_is_unknown_not_confirmed(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Nonzero exit with no test-execution markers (compile error) is
    infrastructure noise — not a reproduced bug."""
    _patch_runsandboxed(monkeypatch, 1, _FORGE_COMPILE_ERROR_OUT, "")
    result = V._check_forge_replay(
        {"project_dir": str(tmp_path), "expect": "fail"})
    assert result.reproduced is None
    assert "without running tests" in result.detail


def test_typo_expect_is_unknown_not_silent_pass(tmp_path: Path) -> None:
    """expect='fial' used to silently mean 'pass' and kill true findings.
    Now it is UNKNOWN, loudly — before the environment is even checked."""
    result = V._check_forge_replay(
        {"project_dir": str(tmp_path), "expect": "fial"})
    assert result.reproduced is None
    assert "invalid expect" in result.detail


def test_real_sandbox_forge_timeout_end_to_end(tmp_path: Path) -> None:
    """One real trip through run_sandboxed (privilege drop and all): a
    forge that exits 124 maps to UNKNOWN. Uses world-traversable dirs
    under /tmp so the sandboxed user can execute."""
    import shutil
    import tempfile

    bindir = Path(tempfile.mkdtemp(prefix="w3g-bin-", dir="/tmp"))
    proj = Path(tempfile.mkdtemp(prefix="w3g-proj-", dir="/tmp"))
    try:
        bindir.chmod(0o755)
        proj.chmod(0o755)
        script = bindir / "forge"
        script.write_text("#!/bin/sh\nexit 124\n", encoding="utf-8")
        script.chmod(0o755)
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = str(bindir) + os.pathsep + old_path
        try:
            result = V._check_forge_replay(
                {"project_dir": str(proj), "expect": "fail"})
        finally:
            os.environ["PATH"] = old_path
        assert result.reproduced is None
        assert "timeout" in result.detail
    finally:
        shutil.rmtree(bindir, ignore_errors=True)
        shutil.rmtree(proj, ignore_errors=True)


def test_llm_timeout_on_judges_maps_to_unknown_kept(
        tmp_path: Path) -> None:
    f = _finding()
    client = ExplodingClient(
        {"verify_prosecutor": _PROSECUTOR_OK,
         "verify_defense": _DEFENSE_PLAUSIBLE},
        fail_roles={"verify_judge", "verify_judge_2"},
        exc=TimeoutError)
    rep = V.verify_findings([f], {}, client=client,
                            ledger_path=_ledger(tmp_path))
    assert f.status == "POTENTIAL"  # fail-open: kept, never dropped
    assert rep.kept == [f] and not rep.dropped
    assert f.metadata["verification"]["decision"] == "unavailable"
    entries = _read_ledger(_ledger(tmp_path))
    assert entries[-1]["verdict"] == "kept_unreviewed"
    assert "both judges failed" in entries[-1]["reason"]


def test_empty_judge_response_is_unknown(tmp_path: Path) -> None:
    f = _finding()
    client = RoleScriptClient({
        "verify_prosecutor": _PROSECUTOR_OK,
        "verify_defense": _DEFENSE_PLAUSIBLE,
        "verify_judge": "",               # empty answer
        "verify_judge_2": "   ",          # whitespace-only answer
    })
    rep = V.verify_findings([f], {}, client=client,
                            ledger_path=_ledger(tmp_path))
    assert f.status == "POTENTIAL"
    assert rep.kept == [f] and not rep.dropped


def test_second_judge_timeout_degrades_loudly_but_keeps(
        tmp_path: Path) -> None:
    """Primary keep + second judge times out -> kept (fail-open), with the
    missing second opinion recorded — not silently treated as agreement."""
    f = _finding()
    client = ExplodingClient(
        {"verify_prosecutor": _PROSECUTOR_OK,
         "verify_defense": _DEFENSE_PLAUSIBLE,
         "verify_judge": _HONEST_KEEP},
        fail_roles={"verify_judge_2"}, exc=TimeoutError)
    rep = V.verify_findings([f], {}, client=client,
                            ledger_path=_ledger(tmp_path))
    assert f.status == "POTENTIAL"
    assert rep.kept == [f]
    ver = f.metadata["verification"]
    assert ver["decision"] == "keep"
    assert "unavailable" in ver["second_opinion"]
    entries = _read_ledger(_ledger(tmp_path))
    assert entries[-1]["verdict"] == "kept_potential"


# ---------------------------------------------------------------------------
# Judge schema validation + calibration (unit)
# ---------------------------------------------------------------------------


def test_judge_schema_rejects_malformed_verdicts() -> None:
    bad = [
        "this is not json",
        "{}",
        json.dumps({"decision": "maybe", "reason": "x"}),
        json.dumps({"decision": "keep"}),                    # no reason
        json.dumps({"decision": "keep", "reason": "   "}),   # empty reason
        json.dumps({"reason": "no decision field"}),
        json.dumps(["keep"]),                                # not a dict
    ]
    for content in bad:
        verdict, why = V._validate_judge_output(content)
        assert verdict is None, content
        assert why


def test_judge_calibration_discards_overconfident_uncited() -> None:
    verdict, _ = V._validate_judge_output(
        _judge_json("keep", 0.99, "so sure", cited=[]))
    assert verdict is None  # 0.99 with no citations -> discarded


def test_judge_calibration_accepts_cited_or_modest() -> None:
    v, _ = V._validate_judge_output(_HONEST_KEEP)  # 0.82 + citations
    assert v is not None and v.decision == "keep"
    v, _ = V._validate_judge_output(
        _judge_json("reject", 0.99, "blocked",
                    cited=["nonReentrant on withdraw"]))
    assert v is not None and v.decision == "reject"
    v, _ = V._validate_judge_output(
        _judge_json("keep", 0.8, "looks bad"))  # modest, uncited -> usable
    assert v is not None and v.confidence == pytest.approx(0.8)
    v, _ = V._validate_judge_output(_judge_json("keep", 0.5, "meh"))
    assert v is not None and v.confidence == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# (c) Disagreeing judges + no machine evidence -> ESCALATE, kept visible
# ---------------------------------------------------------------------------


def test_disagreeing_judges_escalate_finding_stays_visible(
        tmp_path: Path) -> None:
    f = _finding()
    client = RoleScriptClient({
        "verify_prosecutor": _PROSECUTOR_OK,
        "verify_defense": _DEFENSE_PLAUSIBLE,
        "verify_judge": _HONEST_KEEP,
        "verify_judge_2": _HONEST_REJECT,
    })
    rep = V.verify_findings([f], {}, client=client,
                            ledger_path=_ledger(tmp_path))
    assert f.status == "POTENTIAL"        # still visible to the human...
    assert f.status != "CONFIRMED EXPLOIT"  # ...but never confirmed
    assert rep.kept == [f]
    assert rep.escalated == [f]
    assert rep.dropped == []
    ver = f.metadata["verification"]
    assert ver["decision"] == "escalate"
    assert ver["uncertainty"]
    assert f.metadata["manual_review_required"] is True
    entries = _read_ledger(_ledger(tmp_path))
    assert entries[-1]["verdict"] == "escalate"
    assert "disagree" in entries[-1]["reason"]


def test_disagreement_reversed_order_also_escalates(tmp_path: Path) -> None:
    """Order must not matter: reject-then-keep disagrees just the same."""
    f = _finding()
    f.metadata["machine_check"] = {"type": "nope_not_real"}  # replay -> None
    client = RoleScriptClient({
        "verify_prosecutor": _PROSECUTOR_OK,
        "verify_defense": _DEFENSE_PLAUSIBLE,
        "verify_judge": _HONEST_REJECT,   # primary rejects...
        "verify_judge_2": _HONEST_KEEP,   # ...second keeps -> disagree
    })
    rep = V.verify_findings([f], {}, client=client,
                            ledger_path=_ledger(tmp_path))
    # Machine evidence inconclusive + judges split -> ESCALATE, not dropped.
    assert f.status == "POTENTIAL"
    assert rep.escalated == [f] and not rep.dropped


def test_dual_reject_with_inconclusive_machine_rejects(tmp_path: Path) -> None:
    """Two agreeing judges CAN drop a finding (dual-judge agreement is a
    sanctioned rejection path) — with both reasons logged."""
    f = _finding()
    f.metadata["machine_check"] = {"type": "nope_not_real"}  # replay -> None
    client = RoleScriptClient({
        "verify_prosecutor": _PROSECUTOR_OK,
        "verify_defense": _DEFENSE_PLAUSIBLE,
        "verify_judge": _HONEST_REJECT,
        "verify_judge_2": _HONEST_REJECT,
    })
    rep = V.verify_findings([f], {}, client=client,
                            ledger_path=_ledger(tmp_path))
    assert f.status == "REJECTED"
    assert rep.dropped == [f]
    assert "nonReentrant" in f.metadata["rejection_reason"]
    entries = _read_ledger(_ledger(tmp_path))
    assert entries[-1]["verdict"] == "rejected"
    assert "two judges agree" in entries[-1]["reason"]


def test_dual_keep_survives_as_potential(tmp_path: Path) -> None:
    f = _finding()
    client = RoleScriptClient({
        "verify_prosecutor": _PROSECUTOR_OK,
        "verify_defense": _DEFENSE_PLAUSIBLE,
        "verify_judge": _HONEST_KEEP,
        "verify_judge_2": _HONEST_KEEP,
    })
    rep = V.verify_findings([f], {}, client=client,
                            ledger_path=_ledger(tmp_path))
    assert f.status == "POTENTIAL"
    assert rep.kept == [f] and not rep.dropped and not rep.escalated
    assert f.metadata["verification"]["adversarial"] == "survived"
    assert "two judges agree" in f.metadata["verification"]["reason"]
    entries = _read_ledger(_ledger(tmp_path))
    assert entries[-1]["verdict"] == "kept_potential"


def test_lone_reject_after_second_judge_failure_escalates(
        tmp_path: Path) -> None:
    """Primary rejects, machine evidence inconclusive, second judge times
    out -> we KNOW we're missing the second opinion -> ESCALATE, not drop."""
    f = _finding()
    f.metadata["machine_check"] = {"type": "nope_not_real"}
    client = ExplodingClient(
        {"verify_prosecutor": _PROSECUTOR_OK,
         "verify_defense": _DEFENSE_PLAUSIBLE,
         "verify_judge": _HONEST_REJECT},
        fail_roles={"verify_judge_2"}, exc=TimeoutError)
    rep = V.verify_findings([f], {}, client=client,
                            ledger_path=_ledger(tmp_path))
    assert f.status == "POTENTIAL"
    assert rep.escalated == [f] and not rep.dropped
    assert f.metadata["verification"]["decision"] == "escalate"


# ---------------------------------------------------------------------------
# (d) Happy path: genuine machine evidence still CONFIRMs (no regression)
# ---------------------------------------------------------------------------


def test_genuine_forge_failure_confirms_exploit(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    f = _finding()
    _patch_runsandboxed(monkeypatch, 1, _FORGE_FAIL_OUT, "")
    f.metadata["machine_check"] = {
        "type": "forge_replay", "project_dir": str(tmp_path),
        "expect": "fail", "timeout_s": 60,
    }
    client = RoleScriptClient({})  # must never be consulted
    rep = V.verify_findings([f], {}, client=client,
                            ledger_path=_ledger(tmp_path))
    assert f.status == "CONFIRMED EXPLOIT"
    assert f.dynamically_confirmed is True
    assert f.confidence >= 0.90
    assert rep.kept == [f] and not rep.dropped
    assert client.calls == []
    entries = _read_ledger(_ledger(tmp_path))
    assert entries[-1]["verdict"] == "confirmed_exploit"


def test_genuine_forge_success_disproves_claim(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """expect='fail' but the suite passes with test-execution markers ->
    the evidence genuinely does not reproduce -> REJECTED (with reason)."""
    f = _finding()
    _patch_runsandboxed(monkeypatch, 0, _FORGE_OK_OUT, "")
    f.metadata["machine_check"] = {
        "type": "forge_replay", "project_dir": str(tmp_path),
        "expect": "fail", "timeout_s": 60,
    }
    rep = V.verify_findings([f], {}, client=RoleScriptClient({}),
                            ledger_path=_ledger(tmp_path))
    assert f.status == "REJECTED"
    assert rep.dropped == [f]
    entries = _read_ledger(_ledger(tmp_path))
    assert entries[-1]["verdict"] == "rejected"


def test_text_alias_runs_like_text_marker(tmp_path: Path) -> None:
    """The 'text' check type advertised in older docs now works instead of
    silently never running."""
    f = _finding()
    f.metadata["machine_check"] = {
        "type": "text", "text": "VIOLATED here", "marker": "VIOLATED"}
    rep = V.verify_findings([f], {}, client=RoleScriptClient({}),
                            ledger_path=_ledger(tmp_path))
    assert f.status == "CONFIRMED EXPLOIT"
    assert rep.kept == [f]


# ---------------------------------------------------------------------------
# (e) Fail-open: AI hiccups never drop a finding silently
# ---------------------------------------------------------------------------


def test_every_unknown_path_keeps_finding_and_logs_reason(
        tmp_path: Path) -> None:
    """Sweep: every hiccup shape -> finding kept, ledger row with reason."""
    scenarios = {
        "judge_timeout": ExplodingClient(
            {"verify_prosecutor": _PROSECUTOR_OK,
             "verify_defense": _DEFENSE_PLAUSIBLE},
            {"verify_judge", "verify_judge_2"}, TimeoutError),
        "judge_garbage": RoleScriptClient({
            "verify_prosecutor": _PROSECUTOR_OK,
            "verify_defense": _DEFENSE_PLAUSIBLE,
            "verify_judge": "not json", "verify_judge_2": "[1,2,3]"}),
        "judge_empty": RoleScriptClient({
            "verify_prosecutor": _PROSECUTOR_OK,
            "verify_defense": _DEFENSE_PLAUSIBLE,
            "verify_judge": "", "verify_judge_2": ""}),
        "prosecutor_blows_up": ExplodingClient(
            {"verify_defense": _DEFENSE_PLAUSIBLE,
             "verify_judge": _HONEST_KEEP, "verify_judge_2": _HONEST_KEEP},
            {"verify_prosecutor"}, RuntimeError),
    }
    for name, client in scenarios.items():
        f = _finding()
        ledger = tmp_path / f"ledger-{name}.jsonl"
        rep = V.verify_findings([f], {}, client=client, ledger_path=ledger)
        assert f.status == "POTENTIAL", name
        assert rep.kept == [f] and not rep.dropped, name
        entries = _read_ledger(ledger)
        assert entries, name
        assert all(e["reason"] for e in entries), name


def test_second_judge_disabled_keeps_legacy_behavior(tmp_path: Path) -> None:
    """Opt-out still available: single-judge mode behaves as before."""
    f = _finding()
    client = RoleScriptClient({
        "verify_prosecutor": _PROSECUTOR_OK,
        "verify_defense": _DEFENSE_PLAUSIBLE,
        "verify_judge": _HONEST_KEEP,
    })
    rep = V.verify_findings([f], {}, client=client, second_judge=False,
                            ledger_path=_ledger(tmp_path))
    assert f.status == "POTENTIAL"
    assert rep.kept == [f]
    roles = [c["role"] for c in client.calls]
    assert "verify_judge_2" not in roles

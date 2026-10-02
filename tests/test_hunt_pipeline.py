"""Tests for web3guard.hunt (Phase 7: end-to-end wiring).

Every AI surface uses fakes: a keyless environment for the offline
degrade path, and scripted stand-in clients for the AI-active path. No
network, no real keys. The invariant stage runs for real (forge is
installed on this machine) with tiny fuzz bounds.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.ai.verification import verify_findings  # noqa: E402
from web3guard.hunt import (  # noqa: E402
    HuntResult,
    drain_trigger_queue,
    hunt_report_dict,
    normalize_config,
    run_hunt,
    write_hunt_report,
)
from web3guard.invariants.models import PipelineResult  # noqa: E402
from web3guard.scanner import Finding  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures: contracts, fake git history, audit report, fake AI clients
# ---------------------------------------------------------------------------

_VAULT_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] -= amount;
    }
}
"""

# Vault with public totalSupply/totalAssets getters -> the keyless template
# invariant (tmpl-solvency-1-1) fires, and the planted skim() bug breaks it.
_VULN_VAULT_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnVault {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    uint256 public totalAssets;

    function deposit() external payable {
        uint256 shares = msg.value;
        balanceOf[msg.sender] += shares;
        totalSupply += shares;
        totalAssets += msg.value;
    }

    function skim() external {
        balanceOf[msg.sender] += 1 ether;
        totalSupply += 1 ether;
    }

    function withdraw(uint256 shares) external {
        uint256 assets = shares * totalAssets / totalSupply;
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        totalAssets -= assets;
        payable(msg.sender).transfer(assets);
    }
}
"""

_REPORT_MD = """\
# Vault Protocol Security Audit

Auditor: TrailGuard Security
Date: 2026-03-15

## [H-01] Reentrancy in `withdraw` allows draining the vault (High)

The `withdraw(uint256 amount)` function in `contracts/Vault.sol` sends
Ether with `msg.sender.call{value: amount}("")` before it updates
`balances[msg.sender]`. A malicious contract can re-enter `withdraw`
during the external call and drain the vault.

Recommendation: follow checks-effects-interactions or add a reentrancy
guard to every function that sends Ether.
"""

_VAULT_V1 = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send fail");
        balances[msg.sender] -= amount;
    }

    function withdrawAll() external {
        uint256 amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send fail");
        balances[msg.sender] = 0;
    }
}
"""

# v2.0: band-aid — withdraw guarded, withdrawAll keeps the same bug.
_VAULT_V2 = _VAULT_V1.replace(
    "function withdraw(uint256 amount) external {",
    "function withdraw(uint256 amount) external nonReentrant {",
).replace(
    "contract Vault {",
    "contract Vault { uint256 private _guard;",
)

# v3.0: proper fix — both Ether-sending functions guarded.
_VAULT_V3 = _VAULT_V2.replace(
    "function withdrawAll() external {",
    "function withdrawAll() external nonReentrant {",
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True,
        env={"PATH": "/usr/bin:/bin", "GIT_AUTHOR_NAME": "t",
             "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
             "GIT_COMMITTER_EMAIL": "t@t", "HOME": str(repo)},
    )


@pytest.fixture()
def vault_dir(tmp_path: Path) -> Path:
    d = tmp_path / "vault"
    d.mkdir()
    (d / "Vault.sol").write_text(_VAULT_SRC)
    return d


@pytest.fixture()
def vuln_vault_dir(tmp_path: Path) -> Path:
    d = tmp_path / "vulnvault"
    d.mkdir()
    (d / "VulnVault.sol").write_text(_VULN_VAULT_SRC)
    return d


@pytest.fixture()
def versioned_repo(tmp_path: Path) -> Path:
    """Git repo with tags v1.0 (vuln) -> v2.0 (band-aid: withdraw guarded,
    withdrawAll keeps the same reentrancy bug)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "contracts").mkdir()
    _git(repo, "init", "-q")
    for tag, src in (("v1.0", _VAULT_V1), ("v2.0", _VAULT_V2)):
        (repo / "contracts" / "Vault.sol").write_text(src)
        _git(repo, "add", ".")
        _git(repo, "commit", "-qm", tag)
        _git(repo, "tag", tag)
    return repo


@pytest.fixture()
def versioned_repo_three_tags(tmp_path: Path) -> Path:
    """Git repo with tags v1.0 (vuln) -> v2.0 (band-aid) -> v3.0 (both
    Ether-sending functions guarded: the proper fix)."""
    repo = tmp_path / "repo3"
    repo.mkdir()
    (repo / "contracts").mkdir()
    _git(repo, "init", "-q")
    for tag, src in (("v1.0", _VAULT_V1), ("v2.0", _VAULT_V2),
                     ("v3.0", _VAULT_V3)):
        (repo / "contracts" / "Vault.sol").write_text(src)
        _git(repo, "add", ".")
        _git(repo, "commit", "-qm", tag)
        _git(repo, "tag", tag)
    return repo


@pytest.fixture()
def audit_report(tmp_path: Path) -> Path:
    p = tmp_path / "audit.md"
    p.write_text(_REPORT_MD)
    return p


class _FakeCostTracker:
    def total_cost(self) -> float:
        return 0.0


class _FakeResponse:
    def __init__(self, content: str) -> None:
        self.content = content
        self.model = "fake-test-model"
        self.raw: dict[str, Any] = {}


class FakeActiveClient:
    """Scripted stand-in for the router client; never touches the network."""

    def __init__(self, judge_decision: str = "reject") -> None:
        self.judge_decision = judge_decision

    @property
    def is_active(self) -> bool:
        return True

    @property
    def inactive_reason(self) -> str:
        return ""

    def offline_report_note(self) -> str:
        return ""

    def cost_tracker(self) -> _FakeCostTracker:
        return _FakeCostTracker()

    def chat(self, system: str, user: str, **kwargs: Any) -> _FakeResponse:
        role = str(kwargs.get("role", ""))
        if role == "verify_prosecutor":
            return _FakeResponse(json.dumps({
                "case": "The claim looks plausible on its face.",
                "exploit_steps": ["step 1"], "impact": "funds at risk"}))
        if role == "verify_defense":
            return _FakeResponse(json.dumps({
                "verdict": "false_positive",
                "refutation": "Test defense: the code path is unreachable.",
                "benign_explanations": ["test-only code"]}))
        if role == "verify_judge":
            return _FakeResponse(json.dumps({
                "decision": self.judge_decision,
                "reason": f"Test judge says {self.judge_decision}"}))
        # Red-team roles: return no hypotheses so the stage stays quiet.
        return _FakeResponse(json.dumps({"hypotheses": []}))


def _keyless_config(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "ai_enabled": False,  # force the offline degrade path hermetically
        "hunt": {
            "fuzz_runs": 16,
            "fuzz_depth": 5,
            "fuzz_timeout_s": 60,
            "max_invariant_contracts": 2,
            "max_redteam_files": 2,
        },
    }
    if extra:
        cfg.update(extra)
    return cfg


def _planted_fp() -> Finding:
    return Finding(
        target="test", language="solidity", file="Vault.sol",
        function="withdraw", category="reentrancy", severity="HIGH",
        description="Planted false positive for the verification test.",
        status="POTENTIAL",
    )


# ---------------------------------------------------------------------------
# Pipeline order + stage skipping
# ---------------------------------------------------------------------------


def test_stage_order_and_skip_flags(vault_dir: Path, tmp_path: Path) -> None:
    result = run_hunt(
        str(vault_dir), _keyless_config(), workdir=tmp_path,
        skip_invariants=True, skip_redteam=True, skip_verify=True,
        skip_history=True, router_env={},
    )
    assert [s.name for s in result.stages] == [
        "static", "invariants", "redteam", "verify", "history"]
    assert result.stage("static").ran  # type: ignore[union-attr]
    for name in ("invariants", "redteam", "verify", "history"):
        stage = result.stage(name)
        assert stage is not None and not stage.ran
        assert stage.skipped_reason  # every skip says WHY
    assert result.ok


def test_keyless_degraded_run_produces_useful_report(
        vuln_vault_dir: Path, tmp_path: Path) -> None:
    """No keys: static + template invariants + machine verification still
    run, the report says loudly what was skipped and why."""
    out = tmp_path / "reports"
    result = run_hunt(
        str(vuln_vault_dir), _keyless_config(), workdir=tmp_path,
        out_dir=out, skip_history=True, router_env={},
    )
    assert not result.ai_active
    assert result.ok
    # The invariant fuzzing really ran and caught the planted skim() bug.
    inv_stage = result.stage("invariants")
    assert inv_stage is not None and inv_stage.ran
    assert inv_stage.findings >= 1
    assert any(f.category == "invariant-violation"
               for f in result.ai_findings)
    # Verification ran (machine evidence replay; LLM debate loudly skipped).
    verify_stage = result.stage("verify")
    assert verify_stage is not None and verify_stage.ran
    # Offline notes are loud in the human report.
    md = (out / "hunt-report.md").read_text(encoding="utf-8")
    assert "no API keys" in md
    assert "AI red-team" in md
    # Plain-English finding rendering, no raw JSON in the human report.
    assert "In plain terms" in md
    assert "What to do next" in md
    assert "never submits findings" in md
    txt = (out / "hunt-report.txt").read_text(encoding="utf-8")
    assert "**" not in txt  # markdown stripped for chat
    assert "In plain terms" in txt


# ---------------------------------------------------------------------------
# Verification actually filters AI findings
# ---------------------------------------------------------------------------


def test_verification_rejects_planted_fp(tmp_path: Path) -> None:
    """A planted false positive is rejected by the adversarial filter and
    counted as dropped — not shown as a finding."""
    finding = _planted_fp()
    report = verify_findings(
        [finding], {"ai_enabled": True}, client=FakeActiveClient("reject"),
        ledger_path=tmp_path / "ledger.jsonl")
    assert finding.status == "REJECTED"
    assert report.dropped == [finding]
    assert report.kept == []
    assert "rejection_reason" in (finding.metadata or {})


def test_verification_keeps_when_judge_says_keep(tmp_path: Path) -> None:
    finding = _planted_fp()
    report = verify_findings(
        [finding], {"ai_enabled": True}, client=FakeActiveClient("keep"),
        ledger_path=tmp_path / "ledger.jsonl")
    assert finding.status == "POTENTIAL"
    assert report.kept == [finding]
    assert report.dropped == []


def test_hunt_applies_verification_to_ai_findings(
        vault_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end: the hunt's verify stage drops the planted FP; the human
    report counts it as thrown away instead of showing it."""

    def _fake_pipeline(contract_path: Any, config: Any,
                       notes: Any = None) -> PipelineResult:
        if notes is not None:
            notes.append("fake invariant pipeline (test)")
        return PipelineResult(findings=[_planted_fp()], notes=notes or [])

    monkeypatch.setattr(
        "web3guard.hunt.run_invariant_pipeline_full", _fake_pipeline)
    out = tmp_path / "reports"
    result = run_hunt(
        str(vault_dir), _keyless_config(), workdir=tmp_path, out_dir=out,
        skip_redteam=True, skip_history=True,
        router_client=FakeActiveClient("reject"),
    )
    assert len(result.rejected) == 1
    assert all(f.status == "REJECTED" for f in result.rejected)
    assert not any(f.category == "reentrancy" and "Planted" in f.description
                   for f in result.findings)
    md = (out / "hunt-report.md").read_text(encoding="utf-8")
    assert "thrown away" in md
    assert "Planted false positive" not in md.split("thrown away")[0]


def test_machine_evidence_replay_confirms_without_ai(tmp_path: Path) -> None:
    """A finding with replayable machine evidence is CONFIRMED EXPLOIT by
    the local re-run alone — no AI needed."""
    finding = _planted_fp()
    finding.metadata["machine_check"] = {
        "type": "text_marker",
        "text": "the quick brown fox jumps",
        "marker": "brown fox",
    }
    report = verify_findings(
        [finding], {"ai_enabled": False},
        ledger_path=tmp_path / "ledger.jsonl")
    assert finding.status == "CONFIRMED EXPLOIT"
    assert report.kept == [finding]


def test_json_report_contains_machine_evidence(tmp_path: Path) -> None:
    finding = _planted_fp()
    finding.metadata["machine_check"] = {
        "type": "text_marker",
        "text": "the quick brown fox jumps",
        "marker": "brown fox",
    }
    verify_findings([finding], {"ai_enabled": False},
                    ledger_path=tmp_path / "ledger.jsonl")
    result = HuntResult(target="test", findings=[finding],
                        rejected=[],
                        stages=[])
    payload = hunt_report_dict(result)
    jf = payload["findings"][0]
    assert jf["metadata"]["machine_check"]["type"] == "text_marker"
    assert jf["metadata"]["verification"]["tier"] == "machine"
    assert jf["status"] == "CONFIRMED EXPLOIT"


# ---------------------------------------------------------------------------
# History verdicts in the report
# ---------------------------------------------------------------------------


def test_history_verdicts_appear_in_report(
        versioned_repo: Path, audit_report: Path, tmp_path: Path) -> None:
    out = tmp_path / "reports"
    result = run_hunt(
        str(versioned_repo), _keyless_config(), workdir=tmp_path,
        out_dir=out, history_report=audit_report,
        skip_invariants=True, skip_redteam=True, router_env={},
    )
    hist_stage = result.stage("history")
    assert hist_stage is not None and hist_stage.ran
    assert result.history is not None
    assert result.history["versions"] == ["v1.0", "v2.0"]
    md = (out / "hunt-report.md").read_text(encoding="utf-8")
    assert "What changed between versions" in md
    # H-01: STILL OPEN at v1.0 -> BAND-AID at v2.0 (withdraw guarded,
    # withdrawAll keeps the same bug).
    assert "patched only on the surface" in md
    assert "**v2.0**: 1 patched only on the surface" in md
    # The band-aid verdict lands on the re-dive list.
    assert result.redive_added, "band-aid verdict should queue a re-dive"
    assert "Worth a second look" in md


def test_redive_queue_populated_end_to_end_from_hunt(
        versioned_repo_three_tags: Path, audit_report: Path,
        tmp_path: Path) -> None:
    """The hunt pipeline wires the hardened RediveQueue.sync_from_history().

    Timeline here is v1.0 (vuln) -> v2.0 (band-aid: withdrawAll still
    buggy) -> v3.0 (proper fix). The band-aid only exists MID-history —
    the old latest-version-only logic looked at v3.0 (FIXED) and queued
    nothing. The hardened sync must land the v2.0 band-aid in the
    persistent queue, and re-running must not duplicate it.
    """
    out = tmp_path / "reports"

    def _hunt() -> Any:
        return run_hunt(
            str(versioned_repo_three_tags), _keyless_config(),
            workdir=tmp_path, out_dir=out, history_report=audit_report,
            skip_static=True, skip_invariants=True, skip_redteam=True,
            skip_verify=True, router_env={},
        )

    result = _hunt()
    hist_stage = result.stage("history")
    assert hist_stage is not None and hist_stage.ran
    assert result.history is not None
    assert result.history["versions"] == ["v1.0", "v2.0", "v3.0"]
    # Mid-history band-aid made it onto the re-dive list.
    assert result.redive_added, \
        "mid-history band-aid should queue a re-dive"
    reasons = [item["reason"] for item in result.redive_added]
    assert any("BAND-AID" in reason and "v2.0" in reason
               for reason in reasons), reasons
    # The persistent queue file was populated end-to-end (this is the
    # product's real queue, not a test-only object).
    queue_path = tmp_path / ".web3guard" / "redive_queue.json"
    assert queue_path.is_file(), "sync must write the persistent queue"
    payload = json.loads(queue_path.read_text(encoding="utf-8"))
    items = [e for e in payload if e.get("finding_id") == "H-01"]
    assert items, "queue JSON must carry the synced H-01 item"
    assert all(e.get("status") == "open" for e in items)
    # The later FIXED verdict annotates the item (verify-and-resolve),
    # never auto-resolves it.
    assert any(
        ev.get("event") == "superseded-noted"
        for e in items for ev in e.get("events", [])
    ), "FIXED-at-v3.0 should annotate, not close, the open item"
    # Re-running the hunt is idempotent: same items, no duplicates.
    _hunt()
    payload2 = json.loads(queue_path.read_text(encoding="utf-8"))
    assert len(payload2) == len(payload), \
        "re-running the hunt must not duplicate queue items"


def test_history_skipped_without_tags(
        vault_dir: Path, tmp_path: Path) -> None:
    result = run_hunt(
        str(vault_dir), _keyless_config(), workdir=tmp_path,
        skip_static=True, skip_invariants=True, skip_redteam=True,
        skip_verify=True, router_env={},
    )
    stage = result.stage("history")
    assert stage is not None and not stage.ran
    assert "git" in stage.skipped_reason.lower()


def test_since_tag_limits_versions(
        versioned_repo: Path, audit_report: Path, tmp_path: Path) -> None:
    result = run_hunt(
        str(versioned_repo), _keyless_config(), workdir=tmp_path,
        history_report=audit_report, since_tag="v1.0",
        skip_static=True, skip_invariants=True, skip_redteam=True,
        skip_verify=True, router_env={},
    )
    assert result.history is not None
    assert result.history["versions"] == ["v2.0"]


# ---------------------------------------------------------------------------
# Watch: trigger queue consumer
# ---------------------------------------------------------------------------

def _hunt_all_skipped_kwargs() -> dict[str, Any]:
    return {"skip_static": True, "skip_invariants": True, "skip_redteam": True,
            "skip_verify": True, "skip_history": True}


def test_watch_consumer_dedupes(tmp_path: Path, vault_dir: Path) -> None:
    from web3guard.discovery.targeting_state import open_targeting_state
    from web3guard.discovery.upgrade_watch import TriggerQueue, UpgradeTrigger

    workdir = tmp_path / "work"
    workdir.mkdir()
    state = open_targeting_state(workdir)
    queue = TriggerQueue(state)
    queue.push(UpgradeTrigger(kind="git_tag", project="vault",
                              repo_path=str(vault_dir),
                              old_version="v1.0", new_version="v2.0"))
    queue.push(UpgradeTrigger(kind="git_tag", project="vault",
                              repo_path=str(vault_dir),
                              old_version="v1.0", new_version="v2.0"))
    assert len(queue) == 1  # queue itself dedupes identical triggers

    first = drain_trigger_queue(
        workdir, _keyless_config(), hunt_kwargs=_hunt_all_skipped_kwargs())
    assert first["processed"] == 1
    assert len(queue) == 0

    # Running again processes nothing: per-trigger done markers dedupe.
    second = drain_trigger_queue(
        workdir, _keyless_config(), hunt_kwargs=_hunt_all_skipped_kwargs())
    assert second["processed"] == 0
    assert second["skipped"] == 0
    assert second["errors"] == 0

    # Results were recorded per trigger id.
    done = [k for k in
            (r["k"] for r in
             state._store.local.query_all("SELECT k FROM state_kv"))
            if "watch:done:" in k]
    assert len(done) == 1


def test_watch_skips_address_only_triggers(tmp_path: Path) -> None:
    from web3guard.discovery.targeting_state import open_targeting_state
    from web3guard.discovery.upgrade_watch import TriggerQueue, UpgradeTrigger

    workdir = tmp_path / "work"
    workdir.mkdir()
    state = open_targeting_state(workdir)
    queue = TriggerQueue(state)
    queue.push(UpgradeTrigger(kind="proxy_upgrade", project="prox",
                              proxy_address="0x1234",
                              old_implementation="0xaaa",
                              new_implementation="0xbbb"))
    summary = drain_trigger_queue(
        workdir, _keyless_config(), hunt_kwargs=_hunt_all_skipped_kwargs())
    assert summary["processed"] == 0
    assert summary["skipped"] == 1
    record = summary["results"][0]
    assert record["status"] == "skipped"
    assert "no local code" in record["reason"].lower()


def test_watch_recovers_orphaned_claims(tmp_path: Path, vault_dir: Path) -> None:
    """A trigger claimed but never finished (crash) is re-queued and
    processed on the next drain."""
    from web3guard.discovery.targeting_state import open_targeting_state
    from web3guard.discovery.upgrade_watch import UpgradeTrigger

    workdir = tmp_path / "work"
    workdir.mkdir()
    state = open_targeting_state(workdir)
    trigger = UpgradeTrigger(kind="git_tag", project="vault",
                             repo_path=str(vault_dir),
                             old_version="v1.0", new_version="v2.0")
    state.set(f"watch:processing:{trigger.trigger_id}", trigger.to_dict())
    summary = drain_trigger_queue(
        workdir, _keyless_config(), hunt_kwargs=_hunt_all_skipped_kwargs())
    assert summary["requeued_orphans"] == 1
    assert summary["processed"] == 1


# ---------------------------------------------------------------------------
# Errors, config, CLI wiring
# ---------------------------------------------------------------------------


def test_bad_target_reports_error_not_clean_scan(tmp_path: Path) -> None:
    out = tmp_path / "reports"
    result = run_hunt(
        str(tmp_path / "does-not-exist"), _keyless_config(),
        workdir=tmp_path, out_dir=out, router_env={},
    )
    assert not result.ok
    assert result.error
    assert result.findings == []
    md = (out / "hunt-report.md").read_text(encoding="utf-8")
    assert "could not be scanned" in md.lower()


def test_cli_hunt_bad_target_exits_3(tmp_path: Path) -> None:
    from web3guard.cli import main

    out = tmp_path / "reports"
    rc = main(["--workdir", str(tmp_path), "hunt",
               str(tmp_path / "does-not-exist"), "--out", str(out),
               "--skip-invariants", "--skip-redteam", "--skip-history"])
    assert rc == 3
    assert (out / "hunt-report.md").exists()


def test_config_hunt_section_deep_merge(tmp_path: Path) -> None:
    cfg = normalize_config({"hunt": {"fuzz_runs": 64}})
    assert cfg["hunt"]["fuzz_runs"] == 64
    # Untouched defaults survive a partial user block.
    assert cfg["hunt"]["redteam"] == "auto"
    assert cfg["hunt"]["verify_max_llm_findings"] == 64
    assert cfg["hunt"]["roe"]["never_auto_submit"] is True
    # Fuzz bounds are forwarded to the invariants section the phase-2
    # pipeline reads.
    assert cfg["invariants"]["runs"] == 64


def test_write_hunt_report_formats(tmp_path: Path) -> None:
    result = HuntResult(target="test", findings=[_planted_fp()],
                        stages=[])
    written = write_hunt_report(result, tmp_path, formats=["md", "txt", "json"])
    assert set(written) == {"md", "txt", "json"}
    payload = json.loads((tmp_path / "hunt-report.json").read_text())
    assert payload["hunt"]["target"] == "test"
    assert len(payload["findings"]) == 1
    with pytest.raises(ValueError):
        write_hunt_report(result, tmp_path, formats=["pdf"])


# ---------------------------------------------------------------------------
# Self-improvement loop, iteration 7 (discovery + hunt CLI):
# mixed tag sorting must never crash the history stage.
# ---------------------------------------------------------------------------


def test_version_key_mixed_tags_sort_without_crash() -> None:
    from web3guard.hunt import _version_key

    tags = ["v1.2", "v1.x", "v1.10", "2.0rc1", "v2.0", "not-a-version",
            "v1.2-beta", "1.9"]
    ordered = sorted(tags, key=_version_key)  # must not raise TypeError
    # Numeric ordering still holds for pure version tags.
    assert ordered.index("v1.2") < ordered.index("v1.10")
    assert ordered.index("v1.2") < ordered.index("1.9")
    assert ordered.index("v1.10") < ordered.index("v2.0")
    # Non-version tags sort after the version-like ones, not crashing.
    assert ordered.index("not-a-version") > ordered.index("v2.0")


def test_cli_hunt_max_redteam_files_wired(tmp_path: Path) -> None:
    """--max-redteam-files reaches run_hunt's config like its sibling flag."""
    import web3guard.hunt
    from web3guard.cli import main

    captured: dict[str, Any] = {}

    def _fake_run_hunt(target: str, config: Any, **kwargs: Any):
        captured["max_redteam_files"] = dict(config).get(
            "hunt", {}).get("max_redteam_files")
        captured["target"] = target
        return web3guard.hunt.HuntResult(target=target, stages=[])

    monkey = pytest.MonkeyPatch()
    monkey.setattr(web3guard.hunt, "run_hunt", _fake_run_hunt)
    try:
        rc = main(["--workdir", str(tmp_path), "hunt", str(tmp_path),
                   "--out", str(tmp_path / "reports"),
                   "--max-redteam-files", "3",
                   "--skip-static", "--skip-invariants", "--skip-redteam",
                   "--skip-verify", "--skip-history"])
    finally:
        monkey.undo()
    assert rc == 0
    assert captured["max_redteam_files"] == 3

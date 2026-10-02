"""Tests for the Phase 2 invariant synthesis + fuzzing pipeline.

Everything here runs WITHOUT real AI keys and WITHOUT network: the LLM is
a scripted fake, and the only test that touches ``forge`` is guarded by
``pytest.mark.skipif`` so CI never fails where Foundry is absent.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.ai.provider import ChatResponse  # noqa: E402
from web3guard.ai.router import build_router_client  # noqa: E402
from web3guard.invariants import (  # noqa: E402
    FuzzBounds,
    discover_forge,
    parse_forge_output,
    register_renderer,
    render_project,
    render_solidity_project,
    run_invariant_pipeline,
    synthesize_invariants,
    template_invariants,
)
from web3guard.invariants.fuzz import FOUNDRY_FORGE  # noqa: E402
from web3guard.invariants.models import Invariant  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_VULN_VAULT_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnVault {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    uint256 public totalAssets;

    function deposit() external payable {
        uint256 shares = msg.value; // 1:1
        balanceOf[msg.sender] += shares;
        totalSupply += shares;
        totalAssets += msg.value;
    }

    // PLANTED BUG: anyone can mint shares for free.
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

_CLEAN_VAULT_SRC = _VULN_VAULT_SRC.replace(
    """
    // PLANTED BUG: anyone can mint shares for free.
    function skim() external {
        balanceOf[msg.sender] += 1 ether;
        totalSupply += 1 ether;
    }
""",
    "",
).replace("contract VulnVault", "contract CleanVault")

_BARE_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Bare {
    uint256 public x;
    function setX(uint256 v) external { x = v; }
}
"""

# Phase 3 widened the template registry: these are the templates that match
# the VulnVault fixture (solvency + two ghost-state temporal templates).
_VULN_VAULT_TEMPLATE_IDS = {
    "tmpl-solvency-1-1",
    "tmpl-cum-flow-conservation",
    "tmpl-no-unbacked-balance",
}


def _write(tmp_path: Path, name: str, src: str) -> Path:
    p = tmp_path / name
    p.write_text(src)
    return p


class FakeClient:
    """Scripted stand-in for the router client; never touches the network."""

    def __init__(self, content: str) -> None:
        self._content = content

    @property
    def is_active(self) -> bool:
        return True

    def chat(self, system: str, user: str, **kwargs) -> ChatResponse:
        return ChatResponse(
            content=self._content,
            model="fake",
            prompt_tokens=0,
            completion_tokens=0,
            total_tokens=0,
            finish_reason="stop",
            raw={},
            provider="fake",
            latency_ms=0,
            cost_usd=0.0,
        )


_GOOD_LLM_JSON = """[
  {
    "id": "no-free-mint",
    "statement": "Shares can only be created by depositing assets.",
    "assertion": "target.totalSupply() <= target.totalAssets()",
    "variables": ["totalSupply", "totalAssets"],
    "functions": ["deposit", "skim"],
    "rationale": "Free mints break vault solvency.",
    "bug_class": "accounting-desync"
  },
  {
    "id": "withdraw-bounded",
    "statement": "Nobody can withdraw more than the vault holds.",
    "assertion": "target.totalAssets() >= 0",
    "variables": ["totalAssets"],
    "functions": ["withdraw"],
    "rationale": "Over-withdrawal drains the vault.",
    "bug_class": "accounting-desync",
    "severity": "CRITICAL"
  }
]"""


# ---------------------------------------------------------------------------
# Template synthesis (keyless baseline)
# ---------------------------------------------------------------------------


def test_template_invariants_fire_on_public_getters() -> None:
    invs = template_invariants(_VULN_VAULT_SRC)
    ids = {i.id for i in invs}
    assert "tmpl-solvency-1-1" in ids
    solv = next(i for i in invs if i.id == "tmpl-solvency-1-1")
    assert solv.assertion == "target.totalSupply() == target.totalAssets()"
    assert solv.source == "template"
    assert solv.severity == "HIGH"


def test_template_invariants_absent_without_getters() -> None:
    assert template_invariants(_BARE_SRC) == []


def test_template_invariants_match_explicit_getter_functions() -> None:
    src = _BARE_SRC.replace(
        "uint256 public x;",
        "uint256 private _ts; uint256 private _ta;\n"
        "    function totalSupply() external view returns (uint256) { return _ts; }\n"
        "    function totalAssets() external view returns (uint256) { return _ta; }",
    )
    assert any(i.id == "tmpl-solvency-1-1" for i in template_invariants(src))


# ---------------------------------------------------------------------------
# LLM synthesis (fake client)
# ---------------------------------------------------------------------------


def test_synthesize_inactive_client_falls_back_to_templates() -> None:
    client = build_router_client({"ai_enabled": False}, env={})
    assert not client.is_active
    result = synthesize_invariants(_VULN_VAULT_SRC, client, {}, contract_name="VulnVault")
    assert not result.ai_used
    assert {i.id for i in result.invariants} == _VULN_VAULT_TEMPLATE_IDS
    assert result.notes, "the AI skip must be LOUD"
    assert any("SKIPPED" in n for n in result.notes)


def test_synthesize_parses_valid_llm_json() -> None:
    result = synthesize_invariants(
        _VULN_VAULT_SRC, FakeClient(_GOOD_LLM_JSON), {}, contract_name="VulnVault"
    )
    assert result.ai_used
    by_id = {i.id: i for i in result.invariants}
    assert "tmpl-solvency-1-1" in by_id  # templates always present
    assert "no-free-mint" in by_id
    llm_inv = by_id["no-free-mint"]
    assert llm_inv.source == "llm"
    assert llm_inv.assertion == "target.totalSupply() <= target.totalAssets()"
    assert llm_inv.variables == ["totalSupply", "totalAssets"]
    assert llm_inv.severity == "HIGH"  # derived from bug_class
    assert by_id["withdraw-bounded"].severity == "CRITICAL"  # explicit kept


def test_synthesize_rejects_malformed_json() -> None:
    result = synthesize_invariants(
        _VULN_VAULT_SRC, FakeClient("this is not json {{{"), {}, contract_name="VulnVault"
    )
    assert not result.ai_used
    assert {i.id for i in result.invariants} == _VULN_VAULT_TEMPLATE_IDS
    assert any("rejected" in n for n in result.notes)


def test_synthesize_rejects_schema_violations() -> None:
    bad = '[{"id": "x", "statement": "no assertion field"}]'
    result = synthesize_invariants(
        _VULN_VAULT_SRC, FakeClient(bad), {}, contract_name="VulnVault"
    )
    assert not result.ai_used
    assert {i.id for i in result.invariants} == _VULN_VAULT_TEMPLATE_IDS


def test_synthesize_rejects_statement_like_assertions() -> None:
    bad = (
        '[{"id": "x", "statement": "s", '
        '"assertion": "target.a() == 1; target.b();"}]'
    )
    result = synthesize_invariants(
        _VULN_VAULT_SRC, FakeClient(bad), {}, contract_name="VulnVault"
    )
    assert not result.ai_used


def test_synthesize_dedupes_ids_against_templates() -> None:
    dup = (
        '[{"id": "tmpl-solvency-1-1", "statement": "s", '
        '"assertion": "target.totalSupply() == target.totalAssets()"}]'
    )
    result = synthesize_invariants(
        _VULN_VAULT_SRC, FakeClient(dup), {}, contract_name="VulnVault"
    )
    assert not result.ai_used
    assert {i.id for i in result.invariants} == _VULN_VAULT_TEMPLATE_IDS


# ---------------------------------------------------------------------------
# Harness rendering (no forge needed — pure string checks)
# ---------------------------------------------------------------------------


def test_harness_renders_complete_foundry_project() -> None:
    # Default rendering is the Phase 1 ATTACK harness (attack_enabled=True
    # is the FuzzBounds default): handler + attacker contracts, deeper
    # call sequences, fixed campaign seed.
    invs = template_invariants(_VULN_VAULT_SRC)
    bounds = FuzzBounds(runs=64, depth=8, timeout_seconds=120)
    files = render_solidity_project(_VULN_VAULT_SRC, "VulnVault", invs, bounds)
    assert set(files) == {
        "foundry.toml",
        "src/VulnVault.sol",
        "test/Invariant.t.sol",
        "test/AttackHandler.sol",
        "test/attackers/DonationAttacker.sol",
        "test/attackers/ReentrancyAttacker.sol",
        "test/attackers/ApprovalDrainer.sol",
    }
    assert files["src/VulnVault.sol"] == _VULN_VAULT_SRC
    test_src = files["test/Invariant.t.sol"]
    assert "contract InvariantTest" in test_src
    assert 'import "../src/VulnVault.sol";' in test_src
    assert "function invariant_tmpl_solvency_1_1() public view" in test_src
    assert "assert(target.totalSupply() == target.totalAssets());" in test_src
    assert 'import "forge-std' not in test_src  # no dependency downloads
    assert "invariant_attacker_no_profit" in test_src  # harness-level exploit check
    handler_src = files["test/AttackHandler.sol"]
    assert "act_attack_reenter" in handler_src  # the simulator attacks now
    assert "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D" in handler_src
    toml = files["foundry.toml"]
    assert "runs = 64" in toml
    assert "depth = 64" in toml  # attack depth: well beyond the old 15-call ceiling
    assert 'seed = "0x539"' in toml  # fixed default campaign seed (1337)
    assert "ffi = false" in toml
    assert "fs_permissions = []" in toml


def test_harness_legacy_render_without_attack_flag() -> None:
    # attack=False keeps the old plain moneyless harness for baselining.
    invs = template_invariants(_VULN_VAULT_SRC)
    bounds = FuzzBounds(runs=64, depth=8, timeout_seconds=120)
    files = render_solidity_project(
        _VULN_VAULT_SRC, "VulnVault", invs, bounds, attack=False
    )
    assert set(files) == {"foundry.toml", "src/VulnVault.sol", "test/Invariant.t.sol"}
    assert "AttackHandler" not in files["test/Invariant.t.sol"]
    assert "depth = 8" in files["foundry.toml"]


def test_harness_renderer_registry_allows_new_languages() -> None:
    with pytest.raises(ValueError, match="no invariant harness renderer"):
        render_project("move", "module x {}", "X", [], FuzzBounds())

    def fake_renderer(src: str, name: str, invs: list[Invariant], bounds: FuzzBounds):
        return {"move.toml": f"# {name}"}

    register_renderer("move", fake_renderer)
    try:
        files = render_project("move", "module x {}", "X", [], FuzzBounds())
        assert files == {"move.toml": "# X"}
    finally:
        from web3guard.invariants import harness as harness_mod

        del harness_mod._RENDERERS["move"]


# ---------------------------------------------------------------------------
# forge output parsing (canned logs — no forge needed)
# ---------------------------------------------------------------------------

_FAIL_LOG = """\
Compiling 2 files with Solc 0.8.34
Solc 0.8.34 finished in 18.52ms
Compiler run successful!

Ran 1 test for test/Invariant.t.sol:InvariantTest
[FAIL: panic: assertion failed (0x01)]

\t[Sequence] (original: 2, shrunk: 1)

\t\tsender=0x0000000000000000000000000000000000000079 addr=[src/VulnVault.sol:VulnVault]0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f calldata=skim() args=[]
 invariant_tmpl_solvency_1_1() (runs: 0, calls: 0, reverts: 0)

Suite result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 3.72ms (3.72ms CPU time)

Failing tests:
Encountered 1 failing test in test/Invariant.t.sol:InvariantTest
[FAIL: panic: assertion failed (0x01)]

\t[Sequence] (original: 2, shrunk: 1)

\t\tsender=0x0000000000000000000000000000000000000079 addr=[src/VulnVault.sol:VulnVault]0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f calldata=skim() args=[]
 invariant_tmpl_solvency_1_1() (runs: 0, calls: 0, reverts: 0)
"""

_CLEAN_LOG = """\
Ran 1 test for test/Invariant.t.sol:InvariantTest
[PASS] invariant_tmpl_solvency_1_1() (runs: 64, calls: 960, reverts: 0)
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 12.1ms
"""

_COMPILE_FAIL_LOG = """\
Compiler run failed:
Error (2314): Expected ';' but got '}'.
 --> src/VulnVault.sol:12:5
"""


def test_parse_forge_failure_log_yields_finding_with_sequence() -> None:
    invs = template_invariants(_VULN_VAULT_SRC)
    findings, campaign = parse_forge_output(
        _FAIL_LOG, invs, contract_path="VulnVault.sol",
        contract_name="VulnVault", target_label="VulnVault",
    )
    assert campaign.compile_ok
    assert not campaign.clean
    assert len(findings) == 1
    f = findings[0]
    assert f.status == "POTENTIAL"
    assert f.category == "invariant-violation"
    assert f.function == "invariant_tmpl_solvency_1_1"
    assert f.severity == "HIGH"
    assert f.confidence >= 0.85  # sequence + seen twice (test + summary)
    assert f.tool_consensus == ["foundry-invariant"]
    assert f.dynamically_confirmed is True
    assert "skim()" in f.poc_code  # the exact failing call sequence
    assert "sender=" in f.poc_code
    assert f.metadata["invariant_id"] == "tmpl-solvency-1-1"
    assert f.metadata["bug_class"] == "accounting-desync"
    assert f.fingerprint.startswith("invariant-")


def test_parse_forge_clean_log_yields_no_findings() -> None:
    invs = template_invariants(_VULN_VAULT_SRC)
    findings, campaign = parse_forge_output(_CLEAN_LOG, invs)
    assert findings == []
    assert campaign.compile_ok
    assert campaign.clean
    assert campaign.runs == 64


def test_parse_forge_compile_failure_is_not_a_finding() -> None:
    findings, campaign = parse_forge_output(_COMPILE_FAIL_LOG, [])
    assert findings == []
    assert not campaign.compile_ok
    assert not campaign.clean


# ---------------------------------------------------------------------------
# Pipeline degradation (no forge needed — discovery is stubbed)
# ---------------------------------------------------------------------------


def test_pipeline_skips_gracefully_without_forge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import web3guard.invariants.pipeline as pipeline_mod

    monkeypatch.setattr(pipeline_mod, "discover_forge", lambda config: None)
    monkeypatch.setattr(pipeline_mod, "run_echidna_fallback", lambda *a, **k: [])
    target = _write(tmp_path, "VulnVault.sol", _VULN_VAULT_SRC)
    notes: list[str] = []
    findings = run_invariant_pipeline(target, {"ai_enabled": False}, notes=notes)
    assert findings == []
    assert any("SKIPPED" in n for n in notes)


def test_pipeline_skips_non_solidity(tmp_path: Path) -> None:
    target = _write(tmp_path, "notes.txt", "hello")
    notes: list[str] = []
    assert run_invariant_pipeline(target, {"ai_enabled": False}, notes=notes) == []
    assert any("no harness renderer" in n for n in notes)


def test_pipeline_skips_missing_file(tmp_path: Path) -> None:
    notes: list[str] = []
    assert (
        run_invariant_pipeline(tmp_path / "nope.sol", {"ai_enabled": False}, notes=notes)
        == []
    )
    assert any("not found" in n for n in notes)


def test_fuzz_bounds_from_config() -> None:
    b = FuzzBounds.from_config({"invariants": {"runs": 64, "depth": 8, "timeout_seconds": 60}})
    assert (b.runs, b.depth, b.timeout_seconds) == (64, 8, 60)
    b2 = FuzzBounds.from_config({"invariants": {"runs": -5, "depth": "x"}})
    assert (b2.runs, b2.depth) == (256, 15)  # invalid values keep defaults
    assert FuzzBounds.from_config({}).runs == 256
    assert FuzzBounds.from_config(None).runs == 256


def test_discover_forge_prefers_env_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = tmp_path / "forge"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("WEB3GUARD_FORGE_BIN", str(fake))
    assert discover_forge({}) == str(fake)


def test_discover_forge_returns_none_when_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEB3GUARD_FORGE_BIN", raising=False)
    monkeypatch.setattr("web3guard.invariants.fuzz.FOUNDRY_FORGE", Path("/nonexistent/forge"))
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert discover_forge({}) is None


# ---------------------------------------------------------------------------
# Real end-to-end fuzz (only where forge is actually installed)
# ---------------------------------------------------------------------------

_FORGE_AVAILABLE = shutil.which("forge") is not None or FOUNDRY_FORGE.exists()


@pytest.mark.skipif(not _FORGE_AVAILABLE, reason="forge not installed")
def test_e2e_vulnerable_vault_violation_is_caught(tmp_path: Path) -> None:
    target = _write(tmp_path, "VulnVault.sol", _VULN_VAULT_SRC)
    notes: list[str] = []
    findings = run_invariant_pipeline(
        target,
        {"ai_enabled": False, "invariants": {"runs": 64, "depth": 8, "timeout_seconds": 240}},
        notes=notes,
    )
    assert not any("fuzz campaign SKIPPED" in n for n in notes), notes
    # Three findings now: tmpl-solvency-1-1, tmpl-no-unbacked-balance AND
    # tmpl-cum-flow-conservation (the widened registry catches the skim bug
    # three ways: share/asset desync, unbacked balances, and value-out >
    # value-in over call history).
    assert len(findings) == 3
    by_id = {f.metadata["invariant_id"] for f in findings}
    assert by_id == {
        "tmpl-solvency-1-1",
        "tmpl-no-unbacked-balance",
        "tmpl-cum-flow-conservation",
    }, by_id
    f = findings[0]
    assert f.status == "POTENTIAL"
    assert f.category == "invariant-violation"
    assert "skim()" in f.poc_code  # the planted free-mint is the counterexample
    assert f.dynamically_confirmed is True


@pytest.mark.skipif(not _FORGE_AVAILABLE, reason="forge not installed")
def test_e2e_clean_vault_produces_no_findings(tmp_path: Path) -> None:
    target = _write(tmp_path, "CleanVault.sol", _CLEAN_VAULT_SRC)
    notes: list[str] = []
    findings = run_invariant_pipeline(
        target,
        {"ai_enabled": False, "invariants": {"runs": 64, "depth": 8, "timeout_seconds": 240}},
        notes=notes,
    )
    assert not any("fuzz campaign SKIPPED" in n for n in notes), notes
    assert findings == []

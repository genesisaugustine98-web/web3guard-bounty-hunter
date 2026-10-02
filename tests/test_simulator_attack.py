"""Tests for the Phase 1 attack-simulator upgrade.

The old simulator could only make simple *moneyless* direct calls, which is
why the adversarial campaign proved reentrancy, value-flow bugs, and
time-dependent logic structurally invisible to it. These tests prove the
upgraded simulator actually attacks, using REAL forge campaigns (skipped
where forge is absent):

- fixture (a): a reentrancy vault the legacy harness misses, now caught
  through a deployed attacker contract with an exact call-sequence PoC;
- fixture (b): a payable fee-accounting bug the legacy harness misses
  (value is always 0 there, so the fee is always 0), now caught once the
  simulator sends ETH with its calls.

No LLM is involved anywhere here: invariants are hand-written, so no API
keys are needed and nothing phones home.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.invariants import attackers as attackers_mod  # noqa: E402
from web3guard.invariants import strategies as strategies_mod  # noqa: E402
from web3guard.invariants.fuzz import (  # noqa: E402
    _extract_strategy_markers,
    run_fuzz_campaign,
)
from web3guard.invariants.harness import (  # noqa: E402
    extract_functions,
    render_solidity_project,
)
from web3guard.invariants.models import FunctionSig, FuzzBounds, Invariant  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures: the two planted-bug contracts
# ---------------------------------------------------------------------------

#: (a) Reentrancy vault. withdraw() sends ETH, then writes back a STALE
#: balance snapshot -- a reentrant call passes the balance check twice and
#: drains other users' deposits. Uncatchable without an attacker contract.
_REENTER_VAULT_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ReenterVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposited;
    uint256 public totalWithdrawn;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposited += msg.value;
    }

    // PLANTED BUG: state is written back from a stale snapshot AFTER the
    // external call, so reentering passes the balance check again.
    function withdraw(uint256 amount) external {
        uint256 bal = balances[msg.sender];
        require(bal >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] = bal - amount;
        totalWithdrawn += amount;
    }
}
"""

#: (b) Fee vault. deposit() takes a 1% fee that LEAVES the vault but credits
#: the user (and totalDeposits) the full gross amount: every deposit
#: under-collateralizes the vault by the fee. Invisible when msg.value is
#: always 0, because the fee is then always 0 too.
_FEE_VAULT_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FeeVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    uint256 public totalWithdrawn;
    uint256 public constant FEE_BPS = 100; // 1%
    address public treasury;

    constructor() {
        treasury = msg.sender;
    }

    // PLANTED BUG: the fee leaves the vault, but the user is credited --
    // and totalDeposits records -- the FULL gross amount.
    function deposit() external payable {
        uint256 fee = (msg.value * FEE_BPS) / 10000;
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        (bool ok, ) = treasury.call{value: fee}("");
        require(ok, "fee transfer failed");
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        totalWithdrawn += amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
"""

_BARE_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Bare {
    uint256 public x;
    function setX(uint256 v) external { x = v; }
}
"""


def _inv(id_: str, assertion: str) -> Invariant:
    return Invariant(id=id_, statement=id_, assertion=assertion)


# ---------------------------------------------------------------------------
# Unit: models (additive attack fields)
# ---------------------------------------------------------------------------


def test_seed_defaults_to_1337_and_is_overridable() -> None:
    assert FuzzBounds().seed == 1337
    assert FuzzBounds.from_config({"invariants": {"seed": 42}}).seed == 42
    assert FuzzBounds.from_config({}).seed == 1337


def test_attack_is_on_by_default_and_depth_exceeds_15() -> None:
    b = FuzzBounds()
    assert b.attack_enabled is True
    assert b.effective_depth == 64
    assert b.effective_depth > 15
    legacy = FuzzBounds.from_config({"invariants": {"attack_enabled": False}})
    assert legacy.attack_enabled is False
    assert legacy.effective_depth == 15  # the old ceiling, for baselining
    # the string "false" must not coerce to True
    assert (
        FuzzBounds.from_config({"invariants": {"attack_enabled": "false"}}).attack_enabled is False
    )


def test_attack_knobs_from_config() -> None:
    b = FuzzBounds.from_config(
        {"invariants": {"attack_depth": 96, "attack_max_value_wei": 5, "strategy_epsilon": 0.5}}
    )
    assert (b.attack_depth, b.attack_max_value_wei, b.strategy_epsilon) == (96, 5, 0.5)
    assert b.effective_depth == 96
    bad = FuzzBounds.from_config({"invariants": {"strategy_epsilon": 7.0, "attack_depth": -3}})
    assert bad.strategy_epsilon == 0.25
    assert bad.attack_depth == 64


# ---------------------------------------------------------------------------
# Unit: attackers.py
# ---------------------------------------------------------------------------


def test_detect_vault_interface_finds_deposit_withdraw_pair() -> None:
    fns = [
        FunctionSig("deposit", [], "payable"),
        FunctionSig("withdraw", [("uint256", "amount")], ""),
    ]
    v = attackers_mod.detect_vault_interface(fns)
    assert v is not None
    assert (v.deposit_fn, v.withdraw_fn, v.withdraw_sig) == (
        "deposit",
        "withdraw",
        "withdraw(uint256)",
    )


def test_detect_vault_interface_rejects_unattackable_shapes() -> None:
    # withdraw with no amount param: not drivable by the attacker
    fns = [FunctionSig("deposit", [], "payable"), FunctionSig("withdraw", [], "")]
    assert attackers_mod.detect_vault_interface(fns) is None
    # no pair at all
    assert (
        attackers_mod.detect_vault_interface([FunctionSig("setX", [("uint256", "v")], "")]) is None
    )
    # alias pair (stake/unstake) works too
    fns2 = [FunctionSig("stake", [], "payable"), FunctionSig("unstake", [("uint256", "a")], "")]
    v2 = attackers_mod.detect_vault_interface(fns2)
    assert v2 is not None and v2.deposit_fn == "stake"


def test_select_attackers_deploys_reentrancy_for_vault() -> None:
    fns = extract_functions(_REENTER_VAULT_SRC)
    specs, notes = attackers_mod.select_attackers("pragma solidity ^0.8.20;", fns)
    names = [s.name for s in specs]
    assert "ReentrancyAttacker" in names
    assert "DonationAttacker" in names
    assert "ApprovalDrainer" not in names  # no approve() here
    assert any("approval" in n for n in notes)


def test_select_attackers_bare_contract_gets_donation_only() -> None:
    fns = extract_functions(_BARE_SRC)
    specs, notes = attackers_mod.select_attackers("pragma solidity ^0.8.20;", fns)
    assert [s.name for s in specs] == ["DonationAttacker"]
    assert len(notes) == 2  # honest notes about what was NOT deployed


def test_attacker_sources_are_syntactically_balanced() -> None:
    for gen in (
        attackers_mod.reentrancy_attacker_source,
        attackers_mod.approval_drainer_source,
        attackers_mod.donation_attacker_source,
    ):
        src = gen()
        assert src.count("{") == src.count("}"), gen.__name__
        assert "pragma solidity" in src
        assert "contract " in src


# ---------------------------------------------------------------------------
# Unit: strategies.py
# ---------------------------------------------------------------------------


def test_strategy_weights_favor_attackers_on_vault_like_targets() -> None:
    fns = extract_functions(_REENTER_VAULT_SRC)
    feats = strategies_mod.contract_features(_REENTER_VAULT_SRC, fns)
    assert feats["has_payable"] and feats["vault_pair"] and feats["has_external_call"]
    weights = strategies_mod.weight_strategies(feats)
    assert weights["attacker-contract"] > weights["direct"]
    assert weights["value-heavy"] > weights["direct"]


def test_bandit_selection_is_deterministic_for_fixed_seed() -> None:
    fns = extract_functions(_REENTER_VAULT_SRC)
    weights = strategies_mod.weight_strategies(
        strategies_mod.contract_features(_REENTER_VAULT_SRC, fns)
    )
    sel1 = strategies_mod.EpsilonGreedySelector(epsilon=0.0, seed=1337)
    sel2 = strategies_mod.EpsilonGreedySelector(epsilon=0.0, seed=1337)
    assert [sel1.select(weights).name for _ in range(5)] == [
        sel2.select(weights).name for _ in range(5)
    ]
    # with no learning, the best prior weight wins: attacker-contract
    assert sel1.select(weights).name == "attacker-contract"


def test_bandit_learns_from_rewards() -> None:
    sel = strategies_mod.EpsilonGreedySelector(epsilon=0.0, seed=7)
    sel.update("direct", 0.0)
    sel.update("time-warped", 1.0)
    sel.update("time-warped", 1.0)
    assert sel.values["time-warped"] == pytest.approx(1.0)
    assert sel.counts["time-warped"] == 2
    # now the learned winner beats the prior-weight winner
    assert sel.select().name == "time-warped"


def test_bandit_state_round_trips_through_disk(tmp_path: Path) -> None:
    sel = strategies_mod.EpsilonGreedySelector(epsilon=0.3, seed=99)
    sel.update("mixed", 1.0)
    p = tmp_path / "state.json"
    sel.save(p)
    sel2 = strategies_mod.EpsilonGreedySelector.load(p, epsilon=0.3, seed=99)
    assert sel2.values["mixed"] == pytest.approx(1.0)
    assert sel2.counts["mixed"] == 1
    # corrupt file -> fresh selector, never a crash
    p.write_text("{not json")
    sel3 = strategies_mod.EpsilonGreedySelector.load(p, epsilon=0.3, seed=99)
    assert sel3.counts["mixed"] == 0


def test_attribute_strategies_maps_poc_to_strategy() -> None:
    assert strategies_mod.attribute_strategies("1. calldata=act_attack_reenter(uint256)") == {
        "attacker-contract"
    }
    assert "value-heavy" in strategies_mod.attribute_strategies(
        "calldata=act_donateForcedEth(uint256)"
    )
    assert "time-warped" in strategies_mod.attribute_strategies(
        "calldata=act_warpTime(uint256,uint256)"
    )
    assert strategies_mod.attribute_strategies("nothing here") == set()


def test_record_campaign_outcome_credits_finding_strategies(tmp_path: Path) -> None:
    p = tmp_path / "s.json"
    strategies_mod.record_campaign_outcome(
        p, ["direct", "value-heavy"], ["poc: act_attack_reenter(uint256) broke it"]
    )
    data = json.loads(p.read_text())
    assert data["values"]["attacker-contract"] == pytest.approx(1.0)
    assert data["values"]["direct"] == pytest.approx(0.05)  # participation reward


def test_plan_campaign_picks_attacker_contract_for_vault() -> None:
    fns = extract_functions(_REENTER_VAULT_SRC)
    weights, primary, attacker_names, _sel = strategies_mod.plan_campaign(
        _REENTER_VAULT_SRC, fns, state_path=None
    )
    assert primary.name == "attacker-contract"
    assert "ReentrancyAttacker" in attacker_names
    assert set(weights) == {s.name for s in strategies_mod.PORTFOLIO}


# ---------------------------------------------------------------------------
# Unit: harness rendering (no forge)
# ---------------------------------------------------------------------------


def test_attack_render_emits_handler_attackers_and_seed() -> None:
    invs = [
        _inv(
            "reenter-solvency",
            "address(target).balance == target.totalDeposits() - target.totalWithdrawn()",
        )
    ]
    bounds = FuzzBounds(runs=32, depth=16, timeout_seconds=120)
    files = render_solidity_project(_REENTER_VAULT_SRC, "ReenterVault", invs, bounds)
    assert set(files) == {
        "foundry.toml",
        "src/ReenterVault.sol",
        "test/Invariant.t.sol",
        "test/AttackHandler.sol",
        "test/attackers/DonationAttacker.sol",
        "test/attackers/ReentrancyAttacker.sol",
        "test/attackers/ApprovalDrainer.sol",
    }
    handler = files["test/AttackHandler.sol"]
    for action in (
        "act_attack_reenter",
        "act_heist",
        "act_warpTime",
        "act_adaptiveAssault",
        "act_donateForcedEth",
        "act_vaultCycle",
        "act_deposit",
        "act_withdraw",
    ):
        assert f"function {action}(" in handler, action
    # cheatcodes without forge-std, via the documented VM address
    assert "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D" in handler
    assert 'import "forge-std' not in handler
    # campaign seed baked into the on-chain bandit PRNG
    assert "WG_CAMPAIGN_SEED = 1337" in handler
    # strategy plan markers for fuzz.py bookkeeping
    test_src = files["test/Invariant.t.sol"]
    assert "// WG-PRIMARY-STRATEGY: attacker-contract" in test_src
    assert "invariant_attacker_no_profit" in test_src
    assert "AttackHandler" in test_src
    toml = files["foundry.toml"]
    assert "depth = 64" in toml  # well beyond the old 15-call ceiling
    assert 'seed = "0x539"' in toml  # 1337 in hex
    assert "ffi = false" in toml


def test_legacy_render_is_unchanged_without_attack_flag() -> None:
    invs = [_inv("x", "target.x() == 0")]
    files = render_solidity_project(_BARE_SRC, "Bare", invs, FuzzBounds(), attack=False)
    assert set(files) == {"foundry.toml", "src/Bare.sol", "test/Invariant.t.sol"}
    assert "AttackHandler" not in files["test/Invariant.t.sol"]
    assert "depth = 15" in files["foundry.toml"]


def test_render_without_vault_pair_skips_scripted_reentrancy() -> None:
    files = render_solidity_project(_BARE_SRC, "Bare", [], FuzzBounds())
    handler = files["test/AttackHandler.sol"]
    for action in ("act_attack_reenter", "act_heist", "act_adaptiveAssault"):
        assert f"function {action}(" not in handler, action
    # ... but value + time attacks are still available
    assert "function act_warpTime(" in handler
    assert "function act_donateForcedEth(" in handler
    assert "function act_setX(" in handler


def test_extract_strategy_markers() -> None:
    files = render_solidity_project(_REENTER_VAULT_SRC, "ReenterVault", [], FuzzBounds())
    strategies_used, primary = _extract_strategy_markers(files)
    assert primary == "attacker-contract"
    assert set(strategies_used) == {s.name for s in strategies_mod.PORTFOLIO}
    legacy = render_solidity_project(_BARE_SRC, "Bare", [], FuzzBounds(), attack=False)
    assert _extract_strategy_markers(legacy) == ([], "")


# ---------------------------------------------------------------------------
# E2E: real forge campaigns (fail-before / pass-after)
# ---------------------------------------------------------------------------

_FORGE_BIN = Path.home() / "workspace" / "tools" / "foundry" / "bin" / "forge"
_SOLC_BIN = (
    Path.home()
    / "workspace"
    / "tools"
    / "foundry"
    / "sandbox-home"
    / ".svm"
    / "0.8.34"
    / "solc-0.8.34"
)
_FORGE_AVAILABLE = _FORGE_BIN.is_file()
needs_forge = pytest.mark.skipif(not _FORGE_AVAILABLE, reason="forge not installed")


@pytest.fixture(scope="module")
def _forge_bundle() -> dict:
    """Make forge + solc runnable under the sandbox's privilege drop.

    pytest runs as root, and run_sandboxed() drops the child to `nobody`,
    which cannot traverse /home/hatch (drwxrwx---) -- and neither can it
    traverse pytest's own 0700 tmp dirs. So the pinned forge binary and
    the cached solc are copied to a world-traversable dir directly under
    /tmp for the duration of the test module. Pure test scaffolding: the
    product code is untouched.
    """
    import tempfile

    if not _SOLC_BIN.is_file():
        pytest.skip("cached solc 0.8.34 not available")
    root = Path(tempfile.mkdtemp(prefix="wg-forge-", dir="/tmp"))
    bin_dir = root / "bin"
    bin_dir.mkdir()
    forge_copy = bin_dir / "forge"
    shutil.copy2(_FORGE_BIN, forge_copy)
    home = root / "sandbox-home"
    solc_dir = home / ".svm" / "0.8.34"
    solc_dir.mkdir(parents=True)
    shutil.copy2(_SOLC_BIN, solc_dir / "solc-0.8.34")
    # world-traversable/readable: the dropped-privilege child is `nobody`
    os.chmod(root, 0o755)
    for dirpath, dirnames, filenames in os.walk(root):
        for d in dirnames:
            os.chmod(os.path.join(dirpath, d), 0o755)
        for f in filenames:
            os.chmod(os.path.join(dirpath, f), 0o755)
    yield {"forge": forge_copy, "home": home}
    shutil.rmtree(root, ignore_errors=True)


@pytest.fixture()
def forge_env(_forge_bundle: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    monkeypatch.setenv("WEB3GUARD_FORGE_BIN", str(_forge_bundle["forge"]))
    monkeypatch.setenv("WEB3GUARD_STRATEGY_STATE", str(tmp_path / "strategy_state.json"))
    monkeypatch.setattr("web3guard.invariants.fuzz.FOUNDRY_SANDBOX_HOME", _forge_bundle["home"])
    return _forge_bundle


def _run_campaign(
    source: str,
    contract_name: str,
    invariants: list[Invariant],
    *,
    attack: bool | None = None,
    runs: int = 32,
) -> tuple:
    # NOTE: the campaign project dir must live directly under /tmp
    # (world-traversable): the sandboxed forge child runs as `nobody` and
    # cannot traverse pytest's 0700 tmp_path.
    import tempfile

    project_dir = Path(tempfile.mkdtemp(prefix="wg-campaign-", dir="/tmp"))
    os.chmod(project_dir, 0o755)
    bounds = FuzzBounds(runs=runs, depth=16, timeout_seconds=240)
    files = render_solidity_project(source, contract_name, invariants, bounds, attack=attack)
    notes: list[str] = []
    try:
        campaign, findings = run_fuzz_campaign(
            project_dir,
            files,
            invariants,
            bounds,
            {},
            contract_path=f"{contract_name}.sol",
            contract_name=contract_name,
            target_label=contract_name,
            notes=notes,
        )
    finally:
        # /tmp is a small tmpfs: don't leak campaign dirs
        shutil.rmtree(project_dir, ignore_errors=True)
    assert not any("SKIPPED" in n for n in notes), notes
    assert campaign.compile_ok, campaign.raw_stdout[-2000:]
    return campaign, findings


@needs_forge
def test_e2e_reentrancy_missed_by_legacy_simulator(forge_env: dict, tmp_path: Path) -> None:
    """FAIL-BEFORE (a): moneyless direct calls cannot reenter; bug missed."""
    invs = [
        _inv(
            "reenter-solvency",
            "address(target).balance == target.totalDeposited() - target.totalWithdrawn()",
        )
    ]
    campaign, findings = _run_campaign(_REENTER_VAULT_SRC, "ReenterVault", invs, attack=False)
    assert findings == [], [f.description for f in findings]


@needs_forge
def test_e2e_reentrancy_caught_by_attack_simulator(forge_env: dict, tmp_path: Path) -> None:
    """PASS-AFTER (a): the deployed attacker contract drains the vault; the
    exact call sequence is captured as the PoC."""
    invs = [
        _inv(
            "reenter-solvency",
            "address(target).balance == target.totalDeposited() - target.totalWithdrawn()",
        )
    ]
    campaign, findings = _run_campaign(_REENTER_VAULT_SRC, "ReenterVault", invs)
    assert "0x539" in campaign.raw_stdout  # seed 1337 plumbed to forge
    assert set(campaign.strategies_used) == {s.name for s in strategies_mod.PORTFOLIO}
    profit = [f for f in findings if f.metadata.get("invariant_id") == "attacker_no_profit"]
    assert profit, (
        f"expected attacker_no_profit finding, got {[f.metadata.get('invariant_id') for f in findings]}"
    )
    f = profit[0]
    assert f.status == "POTENTIAL"
    assert f.dynamically_confirmed is True
    # the exploit ran THROUGH the deployed attacker contract, in one
    # fuzzed handler action:
    assert "act_attack_reenter(" in f.poc_code
    assert "sender=" in f.poc_code and "calldata=" in f.poc_code
    # the strategy bookkeeping learned from this campaign
    state = json.loads((tmp_path / "strategy_state.json").read_text())
    assert state["values"]["attacker-contract"] > 0


@needs_forge
def test_e2e_fee_bug_missed_by_legacy_simulator(forge_env: dict, tmp_path: Path) -> None:
    """FAIL-BEFORE (b): with msg.value always 0 the fee is always 0; missed."""
    invs = [
        _inv(
            "fee-coverage",
            "target.totalDeposits() <= address(target).balance + target.totalWithdrawn()",
        )
    ]
    campaign, findings = _run_campaign(_FEE_VAULT_SRC, "FeeVault", invs, attack=False)
    assert findings == [], [f.description for f in findings]


@needs_forge
def test_e2e_fee_bug_caught_by_attack_simulator(forge_env: dict, tmp_path: Path) -> None:
    """PASS-AFTER (b): value-carrying calls expose the fee mis-accounting."""
    invs = [
        _inv(
            "fee-coverage",
            "target.totalDeposits() <= address(target).balance + target.totalWithdrawn()",
        )
    ]
    campaign, findings = _run_campaign(_FEE_VAULT_SRC, "FeeVault", invs)
    fee = [f for f in findings if f.metadata.get("invariant_id") == "fee-coverage"]
    assert fee, (
        f"expected fee-coverage finding, got {[f.metadata.get('invariant_id') for f in findings]}"
    )
    poc = fee[0].poc_code
    # the breaking sequence carried real ETH through a value action --
    # something the old simulator could never do:
    assert any(
        a in poc
        for a in (
            "act_deposit(",
            "act_vaultCycle(",
            "act_attack_reenter(",
            "act_heist(",
            "act_adaptiveAssault(",
        )
    ), poc


@needs_forge
def test_e2e_campaign_is_reproducible_for_fixed_seed(forge_env: dict, tmp_path: Path) -> None:
    """The fixed default seed (1337) reproduces the same counterexample.

    The fuzzed CALLDATA (the attack itself) is bit-identical across runs.
    The rendered `sender=`/contract addresses can wobble: they come from a
    sender-index -> address map whose iteration order is randomized per
    OS process (Rust HashMap), outside the fuzz seed's reach. The
    machine-checkable part -- which function, which arguments -- is what
    we compare, with addresses normalized out.
    """
    import re

    invs = [
        _inv(
            "fee-coverage",
            "target.totalDeposits() <= address(target).balance + target.totalWithdrawn()",
        )
    ]
    _, findings1 = _run_campaign(_FEE_VAULT_SRC, "FeeVault", invs)
    _, findings2 = _run_campaign(_FEE_VAULT_SRC, "FeeVault", invs)
    fee1 = [f for f in findings1 if f.metadata.get("invariant_id") == "fee-coverage"]
    fee2 = [f for f in findings2 if f.metadata.get("invariant_id") == "fee-coverage"]
    assert fee1 and fee2

    def normalize(poc: str) -> str:
        return re.sub(r"0x[0-9a-fA-F]{40}", "0xADDR", poc)

    assert normalize(fee1[0].poc_code) == normalize(fee2[0].poc_code)

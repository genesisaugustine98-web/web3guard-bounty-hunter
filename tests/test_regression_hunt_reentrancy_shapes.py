"""Regression tests: ReentrancyAttacker supports no-arg withdraw() and
withdrawTo(address) shapes (weakness-hunt follow-up).

Background: the weakness-hunt round "caught" 8 batch_01 reentrancy-family
cases (r1-classic-eth, r3-withdraw-to, r4-wrong-mapping, r5-readonly-quote,
r6-readonly-price, r7-cross-function, r8-guard-gap, r10-stale-snapshot) —
but the donation-scoping review proved those catches were DONATION
ARTIFACTS (forced ETH breaking totalDeposits()==totalAssets()): none of
those contracts has a (deposit, withdraw(uint)) pair, so the
ReentrancyAttacker was never even deployed for them. These contracts ARE
genuinely vulnerable (CEI violations), but the attacker only supported the
(deposit, withdraw(uint)) shape.

This file pins the fix: the attacker now drives
  (a) bare withdraw()      — deposit, then reenter via a no-arg call;
  (b) withdrawTo(address)   — the reentrant call pays the attacker itself;
  (c) cross-function pairs  — every withdraw-like entry (e.g. an unguarded
      withdrawVested() next to a guarded withdraw()) becomes its own
      re-entry variant, funded by the deposit-like function that feeds the
      balance it reads.

$0 cost: pure unit + render tests, no forge, no network, no LLM. The
end-to-end proof (real forge campaigns with the donation attacker forcibly
disabled) is documented in the parent task's report, not here.
"""

from __future__ import annotations

from web3guard.invariants import attackers as atk
from web3guard.invariants import templates as tmpl
from web3guard.invariants.harness import (
    extract_target_functions,
    render_solidity_project,
)
from web3guard.invariants.models import CampaignResult, FunctionSig, FuzzBounds, Invariant
from web3guard.invariants.proof_gate import apply_proof_gate
from web3guard.scanner import Finding

_BOUNDS = FuzzBounds.from_config({})


def _inv() -> list[Invariant]:
    # A plain (non-ghost) invariant keeps the render on the attack harness.
    return [
        Invariant(
            id="solvency",
            statement="Recorded deposits always equal the ETH actually held",
            assertion="target.totalDeposits() == target.totalAssets()",
        )
    ]


# --- fixture contracts (the batch_01 r-case shapes, trimmed) ----------------

_R1_NOARG = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract ReVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "none");
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
        totalDeposits -= bal;
    }
    function totalAssets() external view returns (uint256) {
        return address(this).balance;
    }
}
"""

_R3_TO = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract PayVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
    function withdrawTo(address payable to) external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "none");
        (bool ok, ) = to.call{value: bal}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
        totalDeposits -= bal;
    }
    function totalAssets() external view returns (uint256) {
        return address(this).balance;
    }
}
"""

_R8_GUARD_GAP = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract GuardGapVault {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public vested;
    uint256 public totalDeposits;
    bool private locked;
    modifier nonReentrant {
        require(!locked, "locked");
        locked = true;
        _;
        locked = false;
    }
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
    function depositVested() external payable {
        vested[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
    function withdraw() external nonReentrant {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "none");
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
        totalDeposits -= bal;
    }
    function withdrawVested() external {
        uint256 bal = vested[msg.sender];
        require(bal > 0, "none");
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "send failed");
        vested[msg.sender] = 0;
        totalDeposits -= bal;
    }
    function totalAssets() external view returns (uint256) {
        return address(this).balance;
    }
}
"""


# --- detection ---------------------------------------------------------------


def test_noarg_withdraw_detected_as_variant() -> None:
    fns = extract_target_functions(_R1_NOARG)
    v = atk.detect_vault_interface(fns)
    assert v is not None
    assert v.withdraw_shape == "noarg"
    assert v.withdraw_sig == "withdraw()"
    assert [x.withdraw_fn for x in v.variants] == ["withdraw"]
    assert v.variants[0].deposit_fn == "deposit"


def test_withdraw_to_detected_as_variant() -> None:
    fns = extract_target_functions(_R3_TO)
    v = atk.detect_vault_interface(fns)
    assert v is not None
    assert v.withdraw_shape == "to"
    assert v.withdraw_sig == "withdrawTo(address)"
    assert v.variants[0].deposit_fn == "deposit"


def test_guard_gap_yields_two_paired_variants() -> None:
    fns = extract_target_functions(_R8_GUARD_GAP)
    v = atk.detect_vault_interface(fns)
    assert v is not None
    by_fn = {x.withdraw_fn: x for x in v.variants}
    assert set(by_fn) == {"withdraw", "withdrawVested"}
    # The unguarded sibling is funded by ITS deposit, not the primary one.
    assert by_fn["withdraw"].deposit_fn == "deposit"
    assert by_fn["withdrawVested"].deposit_fn == "depositVested"


def test_select_attackers_deploys_reentrancy_for_new_shapes() -> None:
    for src in (_R1_NOARG, _R3_TO, _R8_GUARD_GAP):
        fns = extract_target_functions(src)
        specs, _notes = atk.select_attackers("pragma solidity ^0.8.20;", fns)
        assert "ReentrancyAttacker" in [s.name for s in specs]


# --- attack-harness rendering ---------------------------------------------------


def _handler(src: str) -> str:
    files = render_solidity_project(src, "Victim", _inv(), _BOUNDS)
    return files["test/AttackHandler.sol"]


def test_attack_harness_reenters_noarg_withdraw() -> None:
    h = _handler(_R1_NOARG)
    assert "reenterAttacker = new ReentrancyAttacker();" in h
    # Armed with the bare signature, triggered with a bare call.
    assert 'abi.encodeWithSignature("withdraw()")' in h
    assert "target.withdraw();" in h
    # The old amount-shaped call must NOT appear for this target.
    assert 'abi.encodeWithSignature("withdraw(uint256)"' not in h


def test_attack_harness_reenters_withdraw_to_attacker() -> None:
    h = _handler(_R3_TO)
    assert 'abi.encodeWithSignature("withdrawTo(address)", address(a))' in h
    assert "target.withdrawTo(payable(address(a)));" in h


def test_attack_harness_drives_both_guard_gap_variants() -> None:
    h = _handler(_R8_GUARD_GAP)
    # The guarded entry is still driven (its reentry reverts harmlessly);
    # the unguarded sibling is driven with ITS funding deposit.
    assert 'abi.encodeWithSignature("withdraw()")' in h
    assert 'abi.encodeWithSignature("withdrawVested()")' in h
    assert "target.depositVested{value: v}();" in h
    assert "target.withdrawVested();" in h


def test_attack_harness_vault_cycle_matches_primary_shape() -> None:
    h = _handler(_R1_NOARG)
    assert "target.withdraw();" in h  # no amount arg on the no-arg shape
    h3 = _handler(_R3_TO)
    assert "target.withdrawTo(payable(u));" in h3  # recipient = the cycling user


def test_attack_harness_renders_balanced_for_new_shapes() -> None:
    for src in (_R1_NOARG, _R3_TO, _R8_GUARD_GAP):
        h = _handler(src)
        assert h.count("{") == h.count("}"), src[:40]


# --- ghost-harness rendering ----------------------------------------------------


def _ghost_handler(src: str) -> str:
    invs = [i for i in tmpl.template_invariants(src) if i.id in tmpl.GHOST_TEMPLATE_IDS]
    assert invs, "fixture must trigger ghost mode"
    files, _notes = tmpl.render_ghost_project(src, "Victim", invs, _BOUNDS)
    # Single-file project: handler source comes first in the test file.
    return files["test/Invariant.t.sol"]


def test_ghost_harness_reenters_through_passthrough_signatures() -> None:
    # Ghost passthroughs append a trailing sender seed, so the armed
    # calldata names the passthrough signature, not the raw target one.
    g = _ghost_handler(_R1_NOARG)
    assert "reenterAttacker = new ReentrancyAttacker();" in g
    assert 'abi.encodeWithSignature("withdraw(uint256)", WG_SENDER_REENTER)' in g
    assert "this.withdraw(WG_SENDER_REENTER);" in g


def test_ghost_harness_withdraw_to_passthrough() -> None:
    g = _ghost_handler(_R3_TO)
    assert (
        'abi.encodeWithSignature("withdrawTo(address,uint256)", '
        "address(reenterAttacker), WG_SENDER_REENTER)" in g
    )
    assert "this.withdrawTo(payable(address(reenterAttacker)), WG_SENDER_REENTER);" in g


def test_ghost_harness_drives_both_guard_gap_variants() -> None:
    g = _ghost_handler(_R8_GUARD_GAP)
    assert 'abi.encodeWithSignature("withdraw(uint256)", WG_SENDER_REENTER)' in g
    assert 'abi.encodeWithSignature("withdrawVested(uint256)", WG_SENDER_REENTER)' in g
    assert "this.depositVested{value: v}(WG_SENDER_REENTER);" in g


def test_ghost_harness_renders_balanced_for_new_shapes() -> None:
    for src in (_R1_NOARG, _R3_TO, _R8_GUARD_GAP):
        g = _ghost_handler(src)
        assert g.count("{") == g.count("}"), src[:40]


# --- proof-gate: the harness's own exploit invariant is attributable --------
def _exploit_finding(inv_id: str) -> Finding:
    return Finding(
        target="Victim",
        language="solidity",
        file="Victim.sol",
        function="invariant_attacker_no_profit",
        category="invariant-violation",
        confidence=0.9,
        description="harness exploit invariant broke",
        poc_code=(
            "# Forge invariant counterexample (machine-checked).\n"
            "1. act_attack_reenter(sender=0xabc, calldata=0x1234)\n"
        ),
        tool_consensus=["foundry-invariant"],
        metadata={"invariant_id": inv_id, "engine": "foundry-invariant"},
    )


def _ok_campaign() -> CampaignResult:
    return CampaignResult(compile_ok=True)


def test_proof_gate_admits_harness_rendered_exploit_invariant() -> None:
    """The harness's own exploit invariant (deterministic product code, not
    an LLM rule) is attributable by construction: a machine-proven break
    must surface as a finding even though no caller asked for that rule."""
    caller_invs = [Invariant(id="solvency", statement="s", assertion="target.a() == 1")]
    admitted = apply_proof_gate(
        [_exploit_finding("attacker_no_profit")],
        caller_invs,
        _ok_campaign(),
        notes=[],
        target_label="Victim",
    )
    assert [f.metadata["invariant_id"] for f in admitted] == ["attacker_no_profit"]


def test_proof_gate_still_rejects_hallucinated_rules() -> None:
    """The allowlist is narrow: an unknown rule id is still rejected."""
    caller_invs = [Invariant(id="solvency", statement="s", assertion="target.a() == 1")]
    notes: list[str] = []
    admitted = apply_proof_gate(
        [_exploit_finding("llm-hallucinated-rule")],
        caller_invs,
        _ok_campaign(),
        notes=notes,
        target_label="Victim",
    )
    assert admitted == []
    assert any("REJECTED" in n for n in notes)


_CLASSIC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract ClassicVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
    function withdraw(uint256 a) external {
        require(balances[msg.sender] >= a, "insufficient");
        balances[msg.sender] -= a;
        totalDeposits -= a;
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok, "send failed");
    }
    function totalAssets() external view returns (uint256) {
        return address(this).balance;
    }
}
"""


# --- no regressions on the classic shape ----------------------------------------


def test_classic_amount_shape_unchanged() -> None:
    fns = extract_target_functions(_CLASSIC)
    v = atk.detect_vault_interface(fns)
    assert v is not None
    assert (v.withdraw_fn, v.withdraw_sig, v.withdraw_shape) == (
        "withdraw",
        "withdraw(uint256)",
        "amount",
    )
    h = _handler(_CLASSIC)
    assert 'abi.encodeWithSignature("withdraw(uint256)", v)' in h
    assert "target.withdraw(v);" in h


def test_unrelated_contract_still_gets_no_reentrancy_attacker() -> None:
    fns = [
        FunctionSig("setX", [("uint256", "v")], ""),
        FunctionSig("getX", [], "view"),
    ]
    specs, notes = atk.select_attackers("pragma solidity ^0.8.20;", fns)
    assert "ReentrancyAttacker" not in [s.name for s in specs]
    assert any("reentrancy attacker not deployed" in n for n in notes)

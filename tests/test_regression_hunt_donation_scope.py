"""Fix B regression tests: donation-attacker scoping (weakness-hunt round).

Commit 4a911c7 deployed the donation attacker inside ghost mode in every
campaign; its forced ETH donations broke exact-equality accounting
invariants (``deposits == balance``) on clean contracts — 0.90-confidence
false positives (batch_01 ``n1-cei-clean``, ``n2-guarded-clean``,
``n9-no-template-clean``).

Donation attacks are a REAL bug class (the ERC-4626 inflation attack works
exactly this way), so the capability must stay fully active where share
mechanics exist. The scoping rule: when the campaign's invariants assert
exact accounting equality AND the target has no share-price/mint
mechanics that forced donations could legitimately break, the donation
attacker is stood down (deployment skipped; its actions become loud
no-ops). Everywhere else it stays fully active.

$0 cost: pure unit + render tests, no forge, no network, no LLM.
"""

from __future__ import annotations

import pytest

from web3guard.invariants import attackers as atk
from web3guard.invariants import templates as tmpl
from web3guard.invariants.harness import render_solidity_project
from web3guard.invariants.models import FuzzBounds, Invariant

# A clean 1:1 vault (the n1-cei-clean shape): exact deposits == balance
# accounting, no shares, no share price. A forced donation breaks the
# equality by construction — a false positive, never a bug.
_CLEAN_VAULT_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract CleanVault {
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

# A share-based vault (ERC-4626 shape): donations move the share price, so
# the donation attacker is a legitimate test here and must stay active.
_SHARE_VAULT_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract ShareVault {
    mapping(address => uint256) public balanceOf;
    uint256 public totalShares;
    uint256 public totalAssets;
    function getRate() public view returns (uint256) {
        return totalShares == 0 ? 1e18 : totalAssets * 1e18 / totalShares;
    }
    function deposit() external payable {
        uint256 shares = msg.value * 1e18 / getRate();
        balanceOf[msg.sender] += shares;
        totalShares += shares;
        totalAssets += msg.value;
    }
    function withdraw(uint256 s) external {
        uint256 assets = s * getRate() / 1e18;
        balanceOf[msg.sender] -= s;
        totalShares -= s;
        totalAssets -= assets;
        (bool ok, ) = msg.sender.call{value: assets}("");
        require(ok, "send failed");
    }
}
"""


def _inv(id: str, assertion: str, source: str = "llm") -> Invariant:
    return Invariant(id=id, statement=id, assertion=assertion, source=source)


def _ghost_invariants(src: str) -> list[Invariant]:
    invs = [i for i in tmpl.template_invariants(src) if i.id in tmpl.GHOST_TEMPLATE_IDS]
    assert invs, "fixture must trigger at least one ghost template"
    return invs


# ---------------------------------------------------------------------------
# Decision function
# ---------------------------------------------------------------------------


def test_decision_stands_down_for_exact_equality_without_share_mechanics() -> None:
    invs = [_inv("solvency", "target.totalDeposits() == target.totalAssets()")]
    deploy, reason = atk.should_deploy_donation_attacker(_CLEAN_VAULT_SRC, invs)
    assert deploy is False
    assert "STOOD DOWN" in reason
    assert "solvency" in reason


def test_decision_keeps_attacker_when_share_mechanics_present() -> None:
    invs = [_inv("solvency", "target.totalShares() == target.totalAssets()")]
    deploy, reason = atk.should_deploy_donation_attacker(_SHARE_VAULT_SRC, invs)
    assert deploy is True
    assert "share-price/mint mechanics" in reason


def test_decision_keeps_attacker_without_exact_equality_invariant() -> None:
    invs = [_inv("owner-ok", "target.owner() != address(0)")]
    deploy, _reason = atk.should_deploy_donation_attacker(_CLEAN_VAULT_SRC, invs)
    assert deploy is True


def test_decision_template_classified_exact_equality() -> None:
    # tmpl-solvency-1-1 (totalSupply == totalAssets) is classified by its
    # spec, not by the heuristic — and still stands down without shares.
    src = _CLEAN_VAULT_SRC.replace(
        "uint256 public totalDeposits;", "uint256 public totalSupply;"
    )
    spec_invs = [s.to_invariant() for s in tmpl.SOLIDITY_TEMPLATES
                 if s.id == "tmpl-solvency-1-1"]
    assert spec_invs and tmpl.template_accounting_class("tmpl-solvency-1-1") == "exact-equality"
    deploy, _reason = atk.should_deploy_donation_attacker(src, spec_invs)
    assert deploy is False


def test_decision_empty_invariants_keeps_attacker() -> None:
    deploy, _reason = atk.should_deploy_donation_attacker(_CLEAN_VAULT_SRC, [])
    assert deploy is True


# ---------------------------------------------------------------------------
# Heuristic + share-mechanics detectors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("assertion", "expected"),
    [
        ("target.totalDeposits() == target.totalAssets()", True),  # n1/n2
        ("target.reserves() == target.realBalance()", True),  # n9
        ("target.totalSupply() == target.totalAssets()", True),  # a3/a4/a5/a8
        ("target.totalAssets() == target.totalDeposits()", True),  # reversed
        ("target.totalSupply() + target.feeAccrued() == target.totalAssets()", False),
        ("target.owner() == target.deployer()", False),
        ("target.minter() != address(0)", False),
        ("target.ethBal() == target.totalAssets()", False),  # actual-vs-actual
        ("target.sharePrice() > 0", False),
        ("target.totalWithdrawn() <= target.totalDeposited()", False),
    ],
)
def test_is_exact_equality_accounting(assertion: str, expected: bool) -> None:
    assert tmpl.is_exact_equality_accounting(_inv("x", assertion)) is expected


@pytest.mark.parametrize(
    ("src_snippet", "expected"),
    [
        ("uint256 public totalShares;", True),
        ("function getRate() public view returns (uint256)", True),
        ("function convertToShares(uint256 a) external", True),
        ("contract MyToken is ERC4626", True),
        ("uint256 public sharePrice;", True),
        ("uint256 public totalDeposits;", False),
        ("mapping(address => uint256) public balances;", False),
        ("uint256 public totalSupply;", False),  # supply alone is not a price
    ],
)
def test_has_share_mechanics(src_snippet: str, expected: bool) -> None:
    assert atk.has_share_mechanics(src_snippet) is expected


# ---------------------------------------------------------------------------
# Ghost renderer: deployment actually gated
# ---------------------------------------------------------------------------


def test_ghost_render_skips_donation_deployment_when_scoped_out() -> None:
    invs = _ghost_invariants(_CLEAN_VAULT_SRC) + [
        _inv("solvency", "target.totalDeposits() == target.totalAssets()")
    ]
    files, notes = tmpl.render_ghost_project(
        _CLEAN_VAULT_SRC, "CleanVault", invs, FuzzBounds()
    )
    test_src = files["test/Invariant.t.sol"]
    # Not deployed...
    assert "donationAttacker = new DonationAttacker();" not in test_src
    # ...but the field stays (references must compile) and the action is a
    # loud no-op instead of a revert/footgun.
    assert "DonationAttacker public donationAttacker;" in test_src
    assert "if (address(donationAttacker) == address(0)) return;" in test_src
    # The scoping decision is loud in the notes.
    assert any("STOOD DOWN" in n for n in notes)
    # No address(0) in the sender pool (would break attacker-no-profit).
    assert "wgSenderPool.push(address(donationAttacker));" not in test_src


def test_ghost_render_keeps_donation_for_share_mechanics() -> None:
    invs = _ghost_invariants(_SHARE_VAULT_SRC) + [
        _inv("solvency", "target.totalShares() == target.totalAssets()")
    ]
    files, _notes = tmpl.render_ghost_project(
        _SHARE_VAULT_SRC, "ShareVault", invs, FuzzBounds()
    )
    test_src = files["test/Invariant.t.sol"]
    assert "donationAttacker = new DonationAttacker();" in test_src
    # Reentrancy attacker still deployed for the vault shape in both modes.
    assert "reenterAttacker = new ReentrancyAttacker();" in test_src


def test_ghost_render_scoped_out_keeps_reentrancy_attacker() -> None:
    invs = _ghost_invariants(_CLEAN_VAULT_SRC) + [
        _inv("solvency", "target.totalDeposits() == target.totalAssets()")
    ]
    files, _notes = tmpl.render_ghost_project(
        _CLEAN_VAULT_SRC, "CleanVault", invs, FuzzBounds()
    )
    test_src = files["test/Invariant.t.sol"]
    # CleanVault has deposit()/withdraw(uint256): the vault interface is
    # detected, so the reentrancy attacker must still deploy.
    assert "reenterAttacker = new ReentrancyAttacker();" in test_src


# ---------------------------------------------------------------------------
# Attack renderer: deployment actually gated
# ---------------------------------------------------------------------------


def test_attack_render_skips_donation_deployment_when_scoped_out() -> None:
    invs = [_inv("solvency", "target.totalDeposits() == target.totalAssets()")]
    files = render_solidity_project(_CLEAN_VAULT_SRC, "CleanVault", invs, FuzzBounds())
    handler = files["test/AttackHandler.sol"]
    assert "donationAttacker = new DonationAttacker();" not in handler
    assert "DonationAttacker public donationAttacker;" in handler
    assert "if (address(donationAttacker) == address(0)) return;" in handler
    # The attacker source file is still written (the import must resolve).
    assert "test/attackers/DonationAttacker.sol" in files


def test_attack_render_keeps_donation_for_share_mechanics() -> None:
    invs = [_inv("solvency", "target.totalShares() == target.totalAssets()")]
    files = render_solidity_project(_SHARE_VAULT_SRC, "ShareVault", invs, FuzzBounds())
    handler = files["test/AttackHandler.sol"]
    assert "donationAttacker = new DonationAttacker();" in handler

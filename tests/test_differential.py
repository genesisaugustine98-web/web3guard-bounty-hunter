"""Unit tests for vulnerability-patching mutators."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from web3guard.sandbox.differential import mutate_source

_VULN = """\
function withdraw(uint256 _amount) external {
    require(balances[msg.sender] >= _amount, "insufficient");
    (bool ok,) = msg.sender.call{value: _amount}("");
    require(ok, "send fail");
    balances[msg.sender] -= _amount;
}
"""


def test_reentrancy_mutator_reorders_state_update() -> None:
    out = mutate_source("reentrancy", _VULN)
    assert out is not None
    assert out.index("balances[msg.sender] -= _amount;") < out.index('call{value: _amount}("")')


_VULN_WITHDRAW_ALL = """\
function withdraw() external {
    uint256 amount = balances[msg.sender];
    require(amount > 0, "no balance");
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok, "send fail");
    balances[msg.sender] = 0;
}
"""


def test_reentrancy_mutator_handles_withdraw_all() -> None:
    out = mutate_source("reentrancy", _VULN_WITHDRAW_ALL)
    assert out is not None
    assert out.index("balances[msg.sender] = 0;") < out.index('call{value: amount}("")')


def test_access_control_mutator_inserts_guard() -> None:
    src = "function setOwner(address n) external { owner = n; }"
    out = mutate_source("access-control", src)
    assert out is not None and "require(msg.sender == owner" in out


def test_unknown_category_returns_none() -> None:
    assert mutate_source("arithmetic", _VULN) is None


def test_no_mutator_reports_unverified(tmp_path: Path) -> None:
    from web3guard.languages.solidity import SolidityAdapter
    from web3guard.sandbox.differential import run_differential

    target = tmp_path / "t"
    target.mkdir()
    (target / "X.sol").write_text("contract X {}")
    work = tmp_path / "w"
    work.mkdir()
    out = run_differential(SolidityAdapter(), target, work, "// noop", "fp", "arithmetic")
    assert out.status == "no-mutator"

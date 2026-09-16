"""Tests for custom Solidity reachability verdicts."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.reachability.solidity import resolve_solidity  # noqa: E402
from web3guard.reachability.solidity_index import FunctionIndex  # noqa: E402
from web3guard.reachability.types import ReachabilityVerdict  # noqa: E402


SOURCE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

abstract contract Base {
    mapping(address => uint256) public balances;

    function _helper() internal virtual {
        balances[msg.sender] = 0;
    }
}

contract Vault is Base {
    function withdraw() external {
        _helper();
    }

    function _dead() internal {
        balances[msg.sender] = 1;
    }

    function _mid() internal {
        _leaf();
    }

    function _leaf() internal {
        balances[msg.sender] = 2;
    }

    function lockedWithdraw() external onlyOwner {
        balances[msg.sender] = 0;
    }
}
"""


def _index(tmp_path: Path) -> FunctionIndex:
    (tmp_path / "Vault.sol").write_text(SOURCE, encoding="utf-8")
    return FunctionIndex.build(tmp_path)


def _verdict(tmp_path: Path, name: str) -> object:
    idx = _index(tmp_path)
    return resolve_solidity(idx, idx.by_name(name)[0])


def test_public_function_is_reachable(tmp_path: Path) -> None:
    ev = _verdict(tmp_path, "withdraw")
    assert ev.verdict == ReachabilityVerdict.REACHABLE
    assert ev.entrypoint == "withdraw"


def test_inherited_internal_helper_is_reachable(tmp_path: Path) -> None:
    ev = _verdict(tmp_path, "_helper")
    assert ev.verdict == ReachabilityVerdict.REACHABLE
    assert ev.entrypoint == "withdraw"
    assert "_helper" in ev.path


def test_dead_internal_is_not_reachable(tmp_path: Path) -> None:
    assert _verdict(tmp_path, "_dead").verdict == ReachabilityVerdict.NOT_REACHABLE


def test_internal_called_only_by_uncalled_internal_is_not_reachable(tmp_path: Path) -> None:
    assert _verdict(tmp_path, "_leaf").verdict == ReachabilityVerdict.NOT_REACHABLE


def test_abstract_virtual_member_is_unknown(tmp_path: Path) -> None:
    src = """\
pragma solidity ^0.8.0;

abstract contract A {
    function _hook() internal virtual {
        uint x = 1;
    }

    function _unreferenced() internal virtual {
        uint y = 2;
    }
}
"""
    tmp = tmp_path / "A.sol"
    tmp.write_text(src, encoding="utf-8")
    idx = FunctionIndex.build(tmp_path)
    ev = resolve_solidity(idx, idx.by_name("_unreferenced")[0])
    assert ev.verdict == ReachabilityVerdict.UNKNOWN


def test_unknown_function_is_unknown(tmp_path: Path) -> None:
    idx = _index(tmp_path)
    assert resolve_solidity(idx, None).verdict == ReachabilityVerdict.UNKNOWN


def test_gated_public_is_reachable_and_marked_gated(tmp_path: Path) -> None:
    idx = _index(tmp_path)
    fn = idx.by_name("lockedWithdraw")[0]
    ev = resolve_solidity(idx, fn)
    assert ev.verdict == ReachabilityVerdict.REACHABLE
    assert ev.gated is True

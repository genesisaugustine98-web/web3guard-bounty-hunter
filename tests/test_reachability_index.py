"""Tests for the Solidity reachability function index."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.reachability.solidity_index import FunctionIndex  # noqa: E402


SOURCE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

abstract contract Base {
    mapping(address => uint256) public balances;

    function _helper() internal virtual {
        balances[msg.sender] = 0;
    }
}

contract Derived is Base {
    function withdraw() external {
        _helper();
    }

    function _dead() internal {
        balances[msg.sender] = 1;
    }
}
"""


def _index(tmp_path: Path) -> FunctionIndex:
    (tmp_path / "Vault.sol").write_text(SOURCE, encoding="utf-8")
    return FunctionIndex.build(tmp_path)


def test_indexes_visibility_and_inheritance(tmp_path: Path) -> None:
    idx = _index(tmp_path)
    withdraw = idx.by_name("withdraw")[0]
    assert withdraw.visibility == "external"
    assert withdraw.contract == "Derived"
    assert withdraw.parents == ("Base",)


def test_helper_is_abstract_member(tmp_path: Path) -> None:
    helper = _index(tmp_path).by_name("_helper")[0]
    assert helper.visibility == "internal"
    assert helper.virtual is True
    assert helper.abstract is True


def test_references_finds_caller(tmp_path: Path) -> None:
    callers = [fn.name for fn in _index(tmp_path).references("_helper")]
    assert "withdraw" in callers


def test_references_empty_for_dead_code(tmp_path: Path) -> None:
    assert _index(tmp_path).references("_dead") == []


def test_enclosing_by_function_name(tmp_path: Path) -> None:
    fn = _index(tmp_path).enclosing("Vault.sol", "withdraw", 0)
    assert fn is not None and fn.name == "withdraw"


def test_enclosing_by_line(tmp_path: Path) -> None:
    fn = _index(tmp_path).enclosing("Vault.sol", "", 17)
    assert fn is not None and fn.name == "_dead"


def test_build_skips_vendored_and_tests(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "Dep.sol").write_text(
        "contract Dep { function f() public {} }", encoding="utf-8")
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "T.sol").write_text(
        "contract T { function g() public {} }", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "A.sol").write_text(
        "contract A { function h() public {} }", encoding="utf-8")
    names = {fn.name for fn in FunctionIndex.build(tmp_path).functions}
    assert "h" in names
    assert "f" not in names
    assert "g" not in names


def test_to_metadata_roundtrip() -> None:
    from web3guard.reachability.types import ReachabilityEvidence, ReachabilityVerdict

    ev = ReachabilityEvidence(
        ReachabilityVerdict.NOT_REACHABLE, "solidity-parser",
        function="_dead", detail="no path",
    )
    assert ev.to_metadata() == {
        "verdict": "not_reachable",
        "backend": "solidity-parser",
        "function": "_dead",
        "detail": "no path",
    }

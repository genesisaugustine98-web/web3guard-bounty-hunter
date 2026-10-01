"""Regression tests for the SWC detector expansion (Phase 1).

Each detector gets a positive case (must fire) and a negative case
(must stay silent) so future refactors cannot silently widen or
narrow the rules.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from web3guard.discovery.static_analyzer import StaticAnalyzerEngine  # noqa: E402


def _cats(code: str) -> set[str]:
    engine = StaticAnalyzerEngine()
    return {r.category for r in engine.run_text(code, "t.sol")}


def test_floating_pragma() -> None:
    assert "floating-pragma" in _cats(
        "pragma solidity ^0.8.0;\ncontract A { function f() public {} }")
    assert "floating-pragma" not in _cats(
        "pragma solidity 0.8.20;\ncontract A { function f() public {} }")


def test_deprecated_idioms() -> None:
    assert "deprecated" in _cats(
        "pragma solidity 0.4.24;\ncontract A {"
        " function f() public { if (true) throw; } }")
    assert "deprecated" in _cats(
        "pragma solidity 0.4.24;\ncontract A {"
        " function f(bytes x) public { sha3(x); } }")
    assert "deprecated" not in _cats(
        "pragma solidity 0.8.0;\ncontract A {"
        " function f() public { revert(); } }")


def test_uninitialized_storage_pointer() -> None:
    vuln = ("pragma solidity 0.4.24;\ncontract A { struct T { uint a; }\n"
            " function f() public { T t; t.a = 1; } }")
    assert "uninitialized-storage" in _cats(vuln)
    safe = ("pragma solidity 0.4.24;\ncontract A { struct T { uint a; }\n"
            " function f() public { T memory t; t.a = 1; } }")
    assert "uninitialized-storage" not in _cats(safe)
    modern = ("pragma solidity 0.8.0;\ncontract A { struct T { uint a; }\n"
              " function f() public { T t; t.a = 1; } }")
    assert "uninitialized-storage" not in _cats(modern)


def test_arbitrary_storage_write() -> None:
    assert "arbitrary-storage-write" in _cats(
        "pragma solidity 0.8.0;\ncontract A {"
        " function f(uint s) public { assembly { sstore(s, 1) } } }")
    # keccak-derived or literal slots are the safe pattern
    assert "arbitrary-storage-write" not in _cats(
        "pragma solidity 0.8.0;\ncontract A {"
        " function f() public { assembly { sstore(keccak256(0, 64), 1) } } }")


def test_hash_collision() -> None:
    assert "hash-collision" in _cats(
        "pragma solidity 0.8.0;\ncontract A {"
        " function f(string a, string b) public pure returns (bytes32) {"
        " return keccak256(abi.encodePacked(a, b)); } }")
    # fixed-size args cannot collide
    assert "hash-collision" not in _cats(
        "pragma solidity 0.8.0;\ncontract A {"
        " function f() public pure returns (bytes32) {"
        " return keccak256(abi.encodePacked(msg.sender, block.number)); } }")


def test_hardcoded_gas() -> None:
    assert "hardcoded-gas" in _cats(
        "pragma solidity 0.8.0;\ncontract A {"
        " function f(address x) public { x.call.gas(2300)(\"\"); } }")
    assert "hardcoded-gas" not in _cats(
        "pragma solidity 0.8.0;\ncontract A {"
        " function f(address x) public { x.call(\"\"); } }")


def test_typographical_error() -> None:
    assert "typographical-error" in _cats(
        "pragma solidity 0.8.0;\ncontract A {"
        " uint n; function f() public { n =+ 1; } }")
    assert "typographical-error" not in _cats(
        "pragma solidity 0.8.0;\ncontract A {"
        " int n; function f() public { n = -1; } }")


def test_signature_malleability() -> None:
    assert "signature-malleability" in _cats(
        "pragma solidity 0.8.0;\ncontract A {"
        " function f(bytes32 h, uint8 v, bytes32 r, bytes32 s)"
        " public pure returns (address) { return ecrecover(h, v, r, s); } }")
    guarded = ("pragma solidity 0.8.0;\ncontract A {"
               " function f(bytes32 h, uint8 v, bytes32 r, bytes32 s)"
               " public pure returns (address) {"
               " require(uint256(s) <="
               " 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A450ABB"
               "DABB9EDD4968B47); return ecrecover(h, v, r, s); } }")
    assert "signature-malleability" not in _cats(guarded)


def test_default_visibility() -> None:
    assert "default-visibility" in _cats(
        "pragma solidity 0.4.24;\ncontract A { function f() { } }")
    assert "default-visibility" not in _cats(
        "pragma solidity 0.4.24;\ncontract A { function f() public { } }")
    # modern compilers require explicit visibility: no finding expected
    assert "default-visibility" not in _cats(
        "pragma solidity 0.8.0;\ncontract A { function f() public { } }")


def test_shadowing_true_and_false() -> None:
    assert "shadowing" in _cats(
        "pragma solidity 0.8.0;\ncontract A { uint public price;\n"
        " function f(uint price) public { price = 1; } }")
    # reading a state var inside an expression is not shadowing
    assert "shadowing" not in _cats(
        "pragma solidity 0.8.0;\ncontract A { uint public total;\n"
        " function f(uint x) public { uint y = x * total / 2; y; } }")


def test_private_data_exposure() -> None:
    assert "private-data" in _cats(
        "pragma solidity 0.8.0;\ncontract A {"
        " bytes32 private password; }")
    assert "private-data" not in _cats(
        "pragma solidity 0.8.0;\ncontract A {"
        " uint private counter; }")


def test_strict_balance_equality() -> None:
    assert "strict-balance-equality" in _cats(
        "pragma solidity 0.8.0;\ncontract A {"
        " function f() public { require(address(this).balance == 0); } }")
    assert "strict-balance-equality" not in _cats(
        "pragma solidity 0.8.0;\ncontract A {"
        " function f() public { require(address(this).balance > 0); } }")


def test_timestamp_dependence() -> None:
    assert "timestamp-dependence" in _cats(
        "pragma solidity 0.8.0;\ncontract A {"
        " function f() public { require(block.timestamp == 123); } }")
    assert "timestamp-dependence" not in _cats(
        "pragma solidity 0.8.0;\ncontract A {"
        " function f() public { require(block.timestamp > 123); } }")


def test_rtl_override() -> None:
    rtl = "\u202e"
    assert "rtl-override" in _cats(
        f"pragma solidity 0.8.0;\ncontract A {{\n //{rtl} hidden\n"
        " function f() public {} }")
    assert "rtl-override" not in _cats(
        "pragma solidity 0.8.0;\ncontract A { function f() public {} }")

"""Regression tests for cross-function taint tracking (Solidity).

Covers: assignment-chain taint, multi-hop internal-call flows, and the
suppression paths (ledger bounds, state-derived amounts, msg.value
forwarding, owner guards, signer-authorized meta-tx values, clamps).
"""
from __future__ import annotations

from web3guard.discovery.static_analyzer import StaticAnalyzerEngine


def _taint_hits(src: str) -> set[tuple[str, str]]:
    engine = StaticAnalyzerEngine()
    return {
        (r.category, r.function)
        for r in engine.run_text(src, "T.sol")
        if r.category == "uncontrolled-payout"
        and ("aint" in r.title or "flows" in r.title)
    }


def test_taint_assignment_chain_fires() -> None:
    src = """pragma solidity 0.8.0; contract A {
        function w(uint x) public {
            uint y = x * 2;
            (bool ok,) = msg.sender.call{value: y}("");
        }
    }"""
    assert ("uncontrolled-payout", "w") in _taint_hits(src)


def test_taint_multihop_flow_fires() -> None:
    src = """pragma solidity 0.8.0; contract A {
        function w(uint x) public { _mid(x); }
        function _mid(uint a) internal { _sink(a); }
        function _sink(uint v) internal {
            (bool ok,) = msg.sender.call{value: v}("");
        }
    }"""
    hits = _taint_hits(src)
    # entry-point flow on w (the internal sink itself is not directly
    # reported: its params are only attacker-controlled via the flow)
    assert ("uncontrolled-payout", "w") in hits
    assert ("uncontrolled-payout", "_sink") not in hits
    assert ("uncontrolled-payout", "_mid") not in hits


def test_taint_transfer_sink_fires() -> None:
    src = """pragma solidity 0.8.0; contract A {
        function w(uint x) public {
            uint y = x + 1;
            payable(msg.sender).transfer(y);
        }
    }"""
    assert ("uncontrolled-payout", "w") in _taint_hits(src)


def test_taint_ledger_bound_is_silent() -> None:
    src = """pragma solidity 0.8.0; contract A {
        mapping(address => uint) _bals;
        function withdraw(uint amount) external {
            uint bal = _bals[msg.sender];
            if (amount > bal) revert();
            (bool ok,) = msg.sender.call{value: amount}("");
        }
    }"""
    assert _taint_hits(src) == set()


def test_taint_direct_ledger_compare_is_silent() -> None:
    src = """pragma solidity 0.8.0; contract A {
        mapping(address => uint) deposits;
        function withdraw(uint _amount) external {
            require(deposits[msg.sender] >= _amount, "insufficient");
            (bool ok,) = msg.sender.call{value: _amount}("");
        }
    }"""
    assert _taint_hits(src) == set()


def test_taint_state_derived_amount_is_silent() -> None:
    # amount computed with protocol state (exchange rate) is not purely
    # attacker-controlled.
    src = """pragma solidity 0.8.0; contract A {
        uint totalAssets; uint totalShares;
        function withdraw(uint share) external {
            uint amount = share * totalAssets / totalShares;
            (bool ok,) = msg.sender.call{value: amount}("");
        }
    }"""
    assert _taint_hits(src) == set()


def test_taint_ledger_derived_local_is_silent() -> None:
    src = """pragma solidity 0.8.0; contract A {
        mapping(address => uint) balances;
        function withdraw() external {
            uint amount = balances[msg.sender];
            (bool ok,) = msg.sender.call{value: amount}("");
        }
    }"""
    assert _taint_hits(src) == set()


def test_taint_msg_value_forwarding_is_silent() -> None:
    src = """pragma solidity 0.8.0; contract A {
        function fwd(address t) public payable {
            (bool ok,) = t.call{value: msg.value}("");
        }
    }"""
    assert _taint_hits(src) == set()


def test_taint_owner_guarded_is_silent() -> None:
    src = """pragma solidity 0.8.0; contract A {
        function sweep(address to, uint amount) external onlyOwner {
            (bool ok,) = to.call{value: amount}("");
        }
    }"""
    assert _taint_hits(src) == set()


def test_taint_signer_authorized_meta_tx_is_silent() -> None:
    # value is inside the signed payload verified by ecrecover: the
    # signer chose it, not the caller.
    src = """pragma solidity 0.8.0; contract A {
        function executeMetaTx(address from, address to, uint256 value,
                bytes calldata data, bytes calldata signature) external payable {
            bytes32 hash = keccak256(abi.encodePacked(from, to, value, keccak256(data)));
            require(ecrecover(hash, _v(signature), _r(signature), _s(signature)) == from, "bad sig");
            (bool ok,) = to.call{value: value}(data);
        }
        function _v(bytes calldata s) internal pure returns (uint8) { return uint8(s[64]); }
        function _r(bytes calldata s) internal pure returns (bytes32) { return bytes32(s[0:32]); }
        function _s(bytes calldata s) internal pure returns (bytes32) { return bytes32(s[32:64]); }
    }"""
    assert _taint_hits(src) == set()


def test_taint_clamped_amount_is_silent() -> None:
    src = """pragma solidity 0.8.0; contract A {
        function w(uint x) public {
            uint y = x * 2;
            y = y < 100 ? y : 100;
            (bool ok,) = msg.sender.call{value: y}("");
        }
    }"""
    assert _taint_hits(src) == set()


def test_taint_unguarded_drain_fires() -> None:
    # textbook arbitrary-payout sink: anyone picks to + amount
    src = """pragma solidity 0.8.0; contract A {
        function drain(address to, uint256 amount) external {
            (bool s,) = to.call{value: amount}("");
            require(s);
        }
    }"""
    assert ("uncontrolled-payout", "drain") in _taint_hits(src)

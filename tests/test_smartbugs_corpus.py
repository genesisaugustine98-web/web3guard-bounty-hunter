"""External-corpus regression tests (SmartBugs sample contracts).

These lock in detector improvements driven by the SmartBugs benchmark:
known-recall gaps must stay closed without introducing false positives.
"""

from __future__ import annotations

from pathlib import Path

from web3guard.discovery.static_analyzer import StaticAnalyzerEngine

REPO = Path(__file__).resolve().parents[1]
SMARTBUGS = REPO / "bench" / "smartbugs" / "samples"


def _run(file_name: str):
    engine = StaticAnalyzerEngine()
    return [
        r for r in engine.run(SMARTBUGS)
        if r.file.endswith(file_name)
    ]


def test_unchecked_low_level_call_return_is_detected() -> None:
    findings = _run("ReturnValue.sol")
    unchecked = [r for r in findings if r.category == "unchecked-external-call"]
    assert any(r.function == "callnotchecked" for r in unchecked)


def test_checked_low_level_call_is_not_flagged() -> None:
    findings = _run("ReturnValue.sol")
    unchecked = [r for r in findings if r.category == "unchecked-external-call"]
    assert not any(r.function == "callchecked" for r in unchecked)


def test_blockhash_only_randomness_is_detected() -> None:
    findings = _run("SmartBillions.sol")
    randomness = [r for r in findings if r.category == "randomness"]
    assert any(r.function == "betOf" for r in randomness)


def test_wrong_constructor_name_init_is_detected() -> None:
    findings = _run("Rubixi.sol")
    assert any(
        r.category == "access-control" and r.function == "DynamicPyramid"
        for r in findings
    )


def test_unchecked_send_dos_is_detected() -> None:
    findings = _run("Government.sol")
    assert any(r.category == "denial-of-service" for r in findings)


def test_approve_transferfrom_race_is_detected() -> None:
    findings = _run("ERC20.sol")
    assert any(
        r.category == "front-running" and r.function == "approve"
        for r in findings
    )


def test_mitigated_approve_is_not_flagged() -> None:
    findings = _run("SmartBillions.sol")
    assert not any(r.category == "front-running" for r in findings)


def test_owner_guarded_send_is_not_dos() -> None:
    findings = _run("Rubixi.sol")
    assert not any(
        r.category == "denial-of-service"
        and r.function in ("collectAllFees", "collectFeesInEther",
                           "collectPercentOfFees")
        for r in findings
    )


def test_clean_fixtures_stay_false_positive_free() -> None:
    engine = StaticAnalyzerEngine()
    assert engine.run(REPO / "test_contracts" / "clean") == []


def test_race_condition_mutable_price_is_detected() -> None:
    findings = _run("RaceCondition.sol")
    assert any(
        r.category == "front-running" and r.function == "buy"
        and "changePrice" in r.description
        for r in findings
    )


def test_plaintext_game_move_is_detected() -> None:
    findings = _run("odds_and_evens.sol")
    assert any(
        r.category == "front-running" and r.function == "play"
        for r in findings
    )


def test_commit_reveal_game_is_not_flagged_as_plaintext() -> None:
    # A game WITH a hash commitment scheme must not trip the
    # plaintext-move detector.
    from web3guard.discovery import static_analyzer as sa

    code = """
    pragma solidity ^0.8.0;
    contract CommitReveal {
        mapping(address => bytes32) public commits;
        mapping(address => uint) public moves;
        function commit(bytes32 h) external { commits[msg.sender] = h; }
        function reveal(uint move, bytes32 salt) external payable {
            require(keccak256(abi.encodePacked(move, salt)) == commits[msg.sender]);
            moves[msg.sender] = move;
        }
        function payout(address winner) external {
            payable(winner).transfer(address(this).balance);
        }
    }
    """
    issues = sa._detect_solidity(code, "CommitReveal.sol")
    assert not any(
        i.category == "front-running" and "Plaintext game move" in i.title
        for i in issues
    )


def test_bound_only_price_is_not_tod() -> None:
    # An owner-settable cap compared against msg.value is fail-safe
    # (moving it reverts); only a mutable *payment amount* is TOD.
    from web3guard.discovery import static_analyzer as sa

    code = """
    pragma solidity ^0.8.0;
    contract CappedSale {
        uint public maxBuy = 1 ether;
        address public owner;
        constructor() { owner = msg.sender; }
        function setMax(uint m) external {
            require(msg.sender == owner);
            maxBuy = m;
        }
        function buy() external payable {
            require(msg.value <= maxBuy);
        }
    }
    """
    issues = sa._detect_solidity(code, "CappedSale.sol")
    assert not any(i.category == "front-running" for i in issues)


def test_var_writes_distinguishes_assignment_from_comparison() -> None:
    from web3guard.discovery.static_analyzer import _var_writes

    assert _var_writes("price = new_price;", "function f(uint new_price)", "price")
    assert _var_writes("price += 1;", "function f()", "price")
    assert _var_writes("price++;", "function f()", "price")
    assert not _var_writes("require(price == new_price);", "function f(uint new_price)", "price")
    assert not _var_writes("if (price != 0) {}", "function f()", "price")
    assert not _var_writes("if (a <= price) {}", "function f()", "price")
    # shadowed by a parameter: not a state write
    assert not _var_writes("price = price + 1;", "function f(uint price)", "price")
    # shadowed by a local declaration: not a state write
    assert not _var_writes("uint price = 5; price += 1;", "function f()", "price")

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


def test_clean_fixtures_stay_false_positive_free() -> None:
    engine = StaticAnalyzerEngine()
    assert engine.run(REPO / "test_contracts" / "clean") == []

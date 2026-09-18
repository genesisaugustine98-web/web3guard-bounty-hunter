"""End-to-end reachability: present vs externally reachable."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.discovery.static_analyzer import _detect_solidity  # noqa: E402
from web3guard.reachability.analyzer import ReachabilityAnalyzer  # noqa: E402
from web3guard.reachability.types import ReachabilityVerdict  # noqa: E402
from web3guard.scanner import Finding  # noqa: E402

_FIXTURES = PROJECT_ROOT / "test_contracts" / "reachability"


def test_static_analyzer_flags_both_patterns() -> None:
    for name in ("UnreachableReentrancy.sol", "InheritedReentrancy.sol"):
        text = (_FIXTURES / name).read_text(encoding="utf-8")
        issues = _detect_solidity(text, name)
        assert any(i.category == "reentrancy" for i in issues), name


def test_unreachable_fixture_is_not_reachable() -> None:
    analyzer = ReachabilityAnalyzer(_FIXTURES)
    finding = Finding(target="x", language="solidity",
                      file="UnreachableReentrancy.sol",
                      function="_withdrawInternal", line_hint="6-11")
    assert analyzer.classify(finding).verdict == ReachabilityVerdict.NOT_REACHABLE


def test_inherited_fixture_is_reachable() -> None:
    analyzer = ReachabilityAnalyzer(_FIXTURES)
    finding = Finding(target="x", language="solidity",
                      file="InheritedReentrancy.sol",
                      function="_withdraw", line_hint="5-10")
    ev = analyzer.classify(finding)
    assert ev.verdict == ReachabilityVerdict.REACHABLE
    assert ev.entrypoint == "withdraw"

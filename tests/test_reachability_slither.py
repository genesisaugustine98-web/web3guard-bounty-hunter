"""Tests for the optional Slither reachability backend."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.reachability.analyzer import ReachabilityAnalyzer  # noqa: E402
from web3guard.reachability.slither_backend import SlitherBackend  # noqa: E402
from web3guard.reachability.solidity_index import FunctionInfo  # noqa: E402


def test_backend_returns_none_without_slither(tmp_path: Path) -> None:
    backend = SlitherBackend(tmp_path)
    fn = FunctionInfo(name="f", contract="C", file="C.sol", visibility="internal")
    assert backend.verdict(fn) in (None,)


def test_analyzer_does_not_construct_backend_when_disabled(tmp_path: Path) -> None:
    analyzer = ReachabilityAnalyzer(tmp_path, use_slither=False)
    assert analyzer._get_slither() is None


def test_analyzer_constructs_backend_when_enabled(tmp_path: Path) -> None:
    analyzer = ReachabilityAnalyzer(tmp_path, use_slither=True)
    backend = analyzer._get_slither()
    assert isinstance(backend, SlitherBackend)
    assert analyzer._get_slither() is backend

"""Tests for the reachability analyzer router and visibility checks."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.reachability.analyzer import ReachabilityAnalyzer  # noqa: E402
from web3guard.reachability.types import ReachabilityVerdict  # noqa: E402
from web3guard.reachability.visibility import resolve_visibility  # noqa: E402
from web3guard.scanner import Finding  # noqa: E402


def test_vyper_external_is_reachable() -> None:
    src = "@external\ndef withdraw():\n    pass\n"
    ev = resolve_visibility("vyper", src, "withdraw")
    assert ev.verdict == ReachabilityVerdict.REACHABLE


def test_vyper_internal_without_caller_is_unknown() -> None:
    src = "@internal\ndef helper():\n    pass\n"
    ev = resolve_visibility("vyper", src, "helper")
    assert ev.verdict == ReachabilityVerdict.UNKNOWN


def test_vyper_internal_with_self_call_is_reachable() -> None:
    src = "@external\ndef withdraw():\n    self.helper()\n\n@internal\ndef helper():\n    pass\n"
    ev = resolve_visibility("vyper", src, "helper")
    assert ev.verdict == ReachabilityVerdict.REACHABLE


def test_move_entry_is_reachable() -> None:
    src = "module m { entry fun withdraw() { } }"
    ev = resolve_visibility("move", src, "withdraw")
    assert ev.verdict == ReachabilityVerdict.REACHABLE


def test_move_private_is_unknown() -> None:
    src = "module m { fun helper() { } }"
    ev = resolve_visibility("move", src, "helper")
    assert ev.verdict == ReachabilityVerdict.UNKNOWN


def test_cairo_external_is_reachable() -> None:
    src = "#[external]\nfn withdraw() {\n}\n"
    ev = resolve_visibility("cairo", src, "withdraw")
    assert ev.verdict == ReachabilityVerdict.REACHABLE


def test_cairo_plain_fn_is_unknown() -> None:
    src = "fn helper() {\n}\n"
    ev = resolve_visibility("cairo", src, "helper")
    assert ev.verdict == ReachabilityVerdict.UNKNOWN


def test_clarity_public_is_reachable() -> None:
    src = "(define-public (withdraw) (ok true))"
    ev = resolve_visibility("clarity", src, "withdraw")
    assert ev.verdict == ReachabilityVerdict.REACHABLE


def test_non_solidity_never_rejects() -> None:
    for lang, src, name in (
        ("vyper", "@internal\ndef helper():\n    pass\n", "helper"),
        ("move", "module m { fun helper() { } }", "helper"),
        ("cairo", "fn helper() {\n}\n", "helper"),
        ("clarity", "(define-private (helper) (ok true))", "helper"),
    ):
        assert resolve_visibility(lang, src, name).verdict != ReachabilityVerdict.NOT_REACHABLE


def test_analyzer_routes_solidity(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Vault {\n"
        "    mapping(address => uint) public balances;\n"
        "    function _dead() internal { balances[msg.sender] = 1; }\n"
        "    function deposit() external payable { balances[msg.sender] += msg.value; }\n"
        "}\n",
        encoding="utf-8",
    )
    analyzer = ReachabilityAnalyzer(tmp_path)
    finding = Finding(target="x", language="solidity", file="Vault.sol",
                      function="_dead", line_hint="4")
    assert analyzer.classify(finding).verdict == ReachabilityVerdict.NOT_REACHABLE


def test_analyzer_unknown_language_is_unknown(tmp_path: Path) -> None:
    analyzer = ReachabilityAnalyzer(tmp_path)
    finding = Finding(target="x", language="func", file="vault.fc", function="f")
    assert analyzer.classify(finding).verdict == ReachabilityVerdict.UNKNOWN


def test_analyzer_never_raises_on_bad_file(tmp_path: Path) -> None:
    analyzer = ReachabilityAnalyzer(tmp_path)
    finding = Finding(target="x", language="solidity", file="missing.sol",
                      function="whatever")
    assert analyzer.classify(finding).verdict == ReachabilityVerdict.UNKNOWN


class _FakeSlither:
    def __init__(self, verdict) -> None:
        self._verdict = verdict

    def verdict(self, fn):  # noqa: ANN001
        return self._verdict


def test_corroboration_rescues_not_reachable(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Vault {\n"
        "    function _dead() internal { uint x = 1; }\n"
        "}\n",
        encoding="utf-8",
    )
    analyzer = ReachabilityAnalyzer(
        tmp_path, use_slither=False, slither_backend=_FakeSlither(ReachabilityVerdict.REACHABLE)
    )
    finding = Finding(target="x", language="solidity", file="Vault.sol",
                      function="_dead", line_hint="3")
    ev = analyzer.classify(finding)
    assert ev.verdict == ReachabilityVerdict.REACHABLE
    assert ev.backend == "slither"


def test_corroboration_strengthens_not_reachable(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Vault {\n"
        "    function _dead() internal { uint x = 1; }\n"
        "}\n",
        encoding="utf-8",
    )
    analyzer = ReachabilityAnalyzer(
        tmp_path, use_slither=False,
        slither_backend=_FakeSlither(ReachabilityVerdict.NOT_REACHABLE),
    )
    finding = Finding(target="x", language="solidity", file="Vault.sol",
                      function="_dead", line_hint="3")
    ev = analyzer.classify(finding)
    assert ev.verdict == ReachabilityVerdict.NOT_REACHABLE
    assert ev.backend == "slither"

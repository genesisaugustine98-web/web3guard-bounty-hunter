"""Impact evidence is parsed from Foundry log output."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from web3guard.languages.solidity import extract_impact_solidity


def test_no_logs_returns_none() -> None:
    assert extract_impact_solidity("1 passed; 0 failed") is None


def test_gain_confirms() -> None:
    out = "Ran 1 test ...\nimpact_gain: 2000000000000000000\n[PASS]"
    ev = extract_impact_solidity(out)
    assert ev is not None and ev.gain == 2 * 10**18 and ev.confirmed


def test_zero_gain_is_not_confirmed() -> None:
    ev = extract_impact_solidity("impact_gain: 0")
    assert ev is not None and not ev.confirmed


def test_loss_confirms() -> None:
    ev = extract_impact_solidity("impact_loss: 42")
    assert ev is not None and ev.loss == 42 and ev.confirmed


from web3guard.languages.solidity import _has_impact_assertion_solidity  # noqa: E402


def test_rejects_bare_assert_true() -> None:
    assert not _has_impact_assertion_solidity("assert(true);")


def test_rejects_assert_without_impact_log() -> None:
    code = "function test_autonomous_exploit() public { assertEq(address(a).balance, 2 ether); }"
    assert not _has_impact_assertion_solidity(code)


def test_accepts_comparison_plus_impact_log() -> None:
    code = (
        "function test_autonomous_exploit() public {\n"
        "    assertGt(address(a).balance, 1 ether);\n"
        '    emit log_named_uint("impact_gain", 2 ether);\n'
        "}"
    )
    assert _has_impact_assertion_solidity(code)


from web3guard.languages.base import parse_impact_marker  # noqa: E402


def test_marker_parser_handles_underscores() -> None:
    ev = parse_impact_marker("impact_gain: 1_000_000")
    assert ev is not None and ev.gain == 1_000_000 and ev.confirmed


def test_marker_parser_sums_repeated_markers() -> None:
    ev = parse_impact_marker("impact_gain: 10\nimpact_gain: 5\nimpact_loss: 3")
    assert ev is not None and ev.gain == 15 and ev.loss == 3


def test_marker_parser_missing_returns_none() -> None:
    assert parse_impact_marker("all good, nothing emitted") is None


from web3guard.languages.cairo_lang import (  # noqa: E402
    _has_impact_assertion_cairo,
    extract_impact_cairo,
)


def test_cairo_extract_marker() -> None:
    ev = extract_impact_cairo("running 1 test\nimpact_gain: 100\ntest ... ok")
    assert ev is not None and ev.gain == 100 and ev.confirmed


def test_cairo_prefilter_rejects_without_marker() -> None:
    code = "#[cfg(test)] mod lib { #[test] fn t() { assert!(1 > 0, \"x\"); } }"
    assert not _has_impact_assertion_cairo(code)


def test_cairo_prefilter_accepts_assert_plus_marker() -> None:
    code = (
        "#[test] fn t() { assert!(after > before, \"no impact\"); "
        'println!("impact_gain: {}", gain); }'
    )
    assert _has_impact_assertion_cairo(code)


def test_vyper_template_requires_impact_log() -> None:
    from web3guard.languages.vyper import _VYPER_EXPLOIT_TEMPLATE

    assert "impact_gain" in _VYPER_EXPLOIT_TEMPLATE
    assert "impact_loss" in _VYPER_EXPLOIT_TEMPLATE

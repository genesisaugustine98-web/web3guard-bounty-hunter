"""Tests for the chat-facing scan report digest (web3guard.reports.digest)."""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.reports.digest import (  # noqa: E402
    load_scan_report,
    render_digest,
)

SAMPLE = {
    "started_at": "2026-09-07T00:00:00",
    "finished_at": "2026-09-07T00:01:00",
    "targets": [
        {
            "target": "https://github.com/acme/contracts.git",
            "language": "solidity",
            "findings": [
                {
                    "target": "https://github.com/acme/contracts.git",
                    "language": "solidity",
                    "file": "src/Vault.sol",
                    "function": "withdraw",
                    "category": "reentrancy",
                    "severity": "HIGH",
                    "confidence": 0.95,
                    "swc_id": "SWC-107",
                    "description": "External call before state update enables reentrancy.",
                    "reasoning": "eth.send is issued after balance transfer is not recorded.",
                    "status": "CONFIRMED EXPLOIT",
                    "poc_code": "contract PoC { function run() external { } }",
                    "exploit_log": "line 1\nline 2\nVictory! balance drained.",
                    "line_hint": "42",
                    "fingerprint": "abcd1234",
                },
                {
                    "target": "https://github.com/acme/contracts.git",
                    "language": "solidity",
                    "file": "src/Owner.sol",
                    "function": "setOwner",
                    "category": "access-control",
                    "severity": "CRITICAL",
                    "confidence": 0.99,
                    "description": "setOwner has no access check.",
                    "reasoning": "Anyone may call setOwner.",
                    "status": "POTENTIAL",
                    "poc_code": "",
                    "exploit_log": "",
                    "line_hint": "5",
                },
            ],
        }
    ],
}


def test_load_scan_report_missing(tmp_path: Path) -> None:
    assert load_scan_report(tmp_path) is None


def test_load_scan_report_present(tmp_path: Path) -> None:
    (tmp_path / "WEB3GUARD_FINDINGS.json").write_text('{"targets": []}', encoding="utf-8")
    assert load_scan_report(tmp_path) == {"targets": []}


def test_render_contains_finding_text() -> None:
    text = render_digest(SAMPLE, include_poc=True)
    assert "Findings: 2" in text
    assert "Confirmed exploits: 1" in text
    assert "[CRITICAL] access-control" in text
    assert "[HIGH] reentrancy" in text
    assert "src/Vault.sol:42 (withdraw)" in text
    assert "External call before state update enables reentrancy." in text
    assert "eth.send is issued after balance transfer is not recorded." in text
    assert "contract PoC { function run() external { } }" in text
    assert "balance drained." in text


def test_render_sorts_severity_and_caps() -> None:
    text = render_digest(SAMPLE, include_poc=False, max_findings=1)
    assert "showing first 1" in text
    # CRITICAL sorts before HIGH, so the capped digest leads with CRITICAL.
    assert "[CRITICAL] access-control" in text
    assert "[HIGH] reentrancy" not in text
    assert "contract PoC" not in text
    assert "balance drained." not in text


def test_render_no_poc_omits_code() -> None:
    text = render_digest(SAMPLE, include_poc=False)
    assert "contract PoC" not in text
    assert "balance drained." not in text
    assert "External call before state update enables reentrancy." in text

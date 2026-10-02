"""Tests for web3guard.history (Phase 4: audit history + version comparison)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from web3guard.history import (
    RediveQueue,
    diff_refs,
    parse_report,
    render_text,
    summarize_verdicts,
    walk_versions,
)
from web3guard.history.ingest import PdfSupportError
from web3guard.history.redive import suggest_adjacent

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

REPORT_MD = """\
# Vault Protocol Security Audit

Auditor: TrailGuard Security
Date: 2026-03-15

## [H-01] Reentrancy in `withdraw` allows draining the vault (High)

The `withdraw(uint256 amount)` function in `contracts/Vault.sol` sends
Ether with `msg.sender.call{value: amount}("")` before it updates
`balances[msg.sender]`. A malicious contract can re-enter `withdraw`
during the external call and drain the vault.

Recommendation: follow checks-effects-interactions or add a reentrancy
guard to every function that sends Ether.

## [M-01] Missing access control on `setFee` (Medium)

The `setFee(uint256 newFee)` function in `contracts/Vault.sol` is
reachable by anyone and changes the protocol fee. Restrict it to the
owner.
"""

_VAULT_V1 = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;
    uint256 public fee;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send fail");
        balances[msg.sender] -= amount;
    }

    function withdrawAll() external {
        uint256 amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send fail");
        balances[msg.sender] = 0;
    }

    function setFee(uint256 newFee) external {
        fee = newFee;
    }
}
"""

# v2.0: band-aid — withdraw gets a guard, withdrawAll keeps the same bug.
_VAULT_V2 = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Vault is ReentrancyGuard {
    mapping(address => uint256) public balances;
    uint256 public fee;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send fail");
    }

    function withdrawAll() external {
        uint256 amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send fail");
        balances[msg.sender] = 0;
    }

    function setFee(uint256 newFee) external {
        fee = newFee;
    }
}
"""

# v3.0: proper fix — both Ether-sending functions guarded + CEI.
_VAULT_V3 = _VAULT_V2.replace(
    "function withdrawAll() external {",
    "function withdrawAll() external nonReentrant {",
).replace(
    """        uint256 amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send fail");
        balances[msg.sender] = 0;""",
    """        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send fail");""",
)

# v3.1: regression — withdrawAll loses its guard AND the state update moves
# back after the external call, genuinely reintroducing the hole. (Under
# the hardened property semantics, merely dropping the nonReentrant marker
# from CEI-ordered code is not a regression — the textbook fix without a
# marker reads FIXED — so the fixture reintroduces the actual vulnerable
# shape.)
_VAULT_V31 = (
    _VAULT_V3.replace(
        "function withdrawAll() external nonReentrant {",
        "function withdrawAll() external {",
    ).replace(
        """        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send fail");""",
        """        uint256 amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send fail");
        balances[msg.sender] = 0;""",
    )
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        env={
            "PATH": "/usr/bin:/bin",
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@t",
            "HOME": str(repo),
        },
    )


@pytest.fixture()
def vuln_repo(tmp_path: Path) -> Path:
    """Git repo with tags v1.0 (vuln) -> v2.0 (band-aid) -> v3.0 (fixed) -> v3.1 (regressed)."""
    repo = tmp_path / "vault"
    repo.mkdir()
    (repo / "contracts").mkdir()
    _git(repo, "init", "-q")
    versions = [("v1.0", _VAULT_V1), ("v2.0", _VAULT_V2), ("v3.0", _VAULT_V3), ("v3.1", _VAULT_V31)]
    for tag, source in versions:
        (repo / "contracts" / "Vault.sol").write_text(source)
        _git(repo, "add", ".")
        _git(repo, "commit", "-qm", tag)
        _git(repo, "tag", tag)
    return repo


@pytest.fixture()
def report_file(tmp_path: Path) -> Path:
    path = tmp_path / "audit.md"
    path.write_text(REPORT_MD)
    return path


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------


def test_ingest_extracts_findings(report_file: Path) -> None:
    report = parse_report(report_file)
    assert report.auditor == "TrailGuard Security"
    assert report.report_date == "2026-03-15"
    assert len(report.findings) == 2

    h1 = next(f for f in report.findings if f.id == "H-01")
    assert h1.severity == "high"
    assert "withdraw" in h1.title.lower() or "reentrancy" in h1.title.lower()
    assert "contracts/Vault.sol" in h1.files
    assert "withdraw" in h1.functions
    assert h1.confidence >= 0.7
    assert h1.raw_excerpt  # raw evidence preserved

    m1 = next(f for f in report.findings if f.id == "M-01")
    assert m1.severity == "medium"
    assert "setFee" in m1.functions


def test_ingest_txt_format(tmp_path: Path) -> None:
    path = tmp_path / "audit.txt"
    path.write_text(
        "H-02: Reentrancy in `drain()`\n\n"
        "The `drain()` function in contracts/Vault.sol calls "
        "msg.sender.call{value: x} before updating state.\n"
    )
    report = parse_report(path)
    assert len(report.findings) == 1
    assert report.findings[0].id == "H-02"


def test_ingest_pdf_without_pypdf(tmp_path: Path) -> None:
    pytest.importorskip("pytest")  # keep linters quiet about conditional import
    try:
        import pypdf  # noqa: F401  # type: ignore[import-not-found]
    except ImportError:
        path = tmp_path / "audit.pdf"
        path.write_bytes(b"%PDF-1.4 fake")
        with pytest.raises(PdfSupportError, match="pypdf"):
            parse_report(path)
    else:
        pytest.skip("pypdf is installed; graceful-degradation path not exercised")


def test_ingest_unsupported_format(tmp_path: Path) -> None:
    path = tmp_path / "audit.docx"
    path.write_text("nope")
    with pytest.raises(ValueError, match="Unsupported report format"):
        parse_report(path)


# ---------------------------------------------------------------------------
# Diffing
# ---------------------------------------------------------------------------


def test_diff_detects_changed_functions(vuln_repo: Path) -> None:
    diff = diff_refs(vuln_repo, "v1.0", "v2.0")
    assert any(f.path == "contracts/Vault.sol" for f in diff.files)
    changed = diff.changed_functions.get("contracts/Vault.sol", [])
    assert "withdraw" in changed  # gained nonReentrant + reordered
    # withdrawAll untouched between v1 and v2
    assert "withdrawAll" not in changed


def test_diff_detects_fix_version(vuln_repo: Path) -> None:
    diff = diff_refs(vuln_repo, "v2.0", "v3.0")
    changed = diff.changed_functions.get("contracts/Vault.sol", [])
    assert "withdrawAll" in changed
    assert "withdraw" not in changed


def test_diff_line_ranges(vuln_repo: Path) -> None:
    diff = diff_refs(vuln_repo, "v1.0", "v2.0")
    ranges = diff.changed_line_ranges.get("contracts/Vault.sol", [])
    assert ranges, "expected changed line ranges"
    assert all(start <= end for start, end in ranges)


def test_diff_bad_ref_raises(vuln_repo: Path) -> None:
    from web3guard.history.diff import GitError

    with pytest.raises(GitError):
        diff_refs(vuln_repo, "v1.0", "no-such-tag")


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------


def test_verdicts_full_lifecycle(vuln_repo: Path, report_file: Path) -> None:
    report = parse_report(report_file)
    finding = next(f for f in report.findings if f.id == "H-01")
    verdicts = walk_versions(
        finding, vuln_repo, ["v1.0", "v2.0", "v3.0", "v3.1"]
    )
    got = [(v.version, v.verdict) for v in verdicts]
    assert got == [
        ("v1.0", "STILL OPEN"),
        ("v2.0", "BAND-AID"),
        ("v3.0", "FIXED"),
        ("v3.1", "REGRESSED"),
    ]
    for v in verdicts:
        assert v.confidence in ("high", "medium", "low")
        assert v.evidence, f"verdict at {v.version} must carry evidence"
    # The money verdict must name the spot the fix missed.
    bandaid = verdicts[1]
    assert any("withdrawAll" in e for e in bandaid.evidence)


def test_verdicts_are_heuristic_not_certain(vuln_repo: Path) -> None:
    from web3guard.history.ingest import AuditFinding

    vague = AuditFinding(
        id="X-01",
        title="Something might be off somewhere",
        severity="unknown",
        description="No pattern keywords here at all.",
        functions=["nonexistentFunction"],
    )
    verdicts = walk_versions(vague, vuln_repo, ["v1.0", "v2.0"])
    # Heuristic can't locate anything -> STILL OPEN with low confidence,
    # never a confident FIXED out of thin air.
    assert verdicts[0].verdict == "STILL OPEN"
    assert verdicts[0].confidence == "low"


def test_walk_versions_needs_a_version(vuln_repo: Path, report_file: Path) -> None:
    report = parse_report(report_file)
    with pytest.raises(ValueError):
        walk_versions(report.findings[0], vuln_repo, [])


# ---------------------------------------------------------------------------
# Re-dive queue
# ---------------------------------------------------------------------------


def test_redive_queue_roundtrip(
    tmp_path: Path, vuln_repo: Path, report_file: Path
) -> None:
    report = parse_report(report_file)
    finding = next(f for f in report.findings if f.id == "H-01")
    verdicts = walk_versions(finding, vuln_repo, ["v1.0", "v2.0", "v3.0", "v3.1"])

    queue = RediveQueue(tmp_path / "q.json")
    added = queue.add_from_verdicts(verdicts, {finding.id: finding})
    # BAND-AID (v2.0) + REGRESSED (v3.1) land in the queue; FIXED does not.
    assert len(added) == 2
    assert {i.finding_id for i in added} == {"H-01"}

    open_items = queue.list(status="open")
    assert len(open_items) == 2

    item = queue.claim(open_items[0].id, by="AG BABY", note="looking now")
    assert item.status == "claimed"
    assert item.claimed_by == "AG BABY"

    queue.resolve(open_items[0].id, resolution="confirmed still exploitable", by="AG BABY")
    assert queue.get(open_items[0].id).status == "resolved"  # type: ignore[union-attr]

    # Persistence: a fresh handle sees the same state.
    queue2 = RediveQueue(tmp_path / "q.json")
    assert len(queue2.list()) == 2
    assert queue2.get(open_items[0].id).status == "resolved"  # type: ignore[union-attr]
    assert len(queue2.list(status="open")) == 1

    # Re-adding the same verdicts does not duplicate open items.
    queue2.add_from_verdicts(verdicts, {finding.id: finding})
    assert len(queue2.list(status="open")) == 1


def test_redive_queue_errors(tmp_path: Path) -> None:
    queue = RediveQueue(tmp_path / "q.json")
    with pytest.raises(KeyError):
        queue.claim("nope", by="x")
    item = queue.add("H-01", "t", "r")
    queue.resolve(item.id, "done")
    with pytest.raises(ValueError, match="already resolved"):
        queue.claim(item.id, by="x")


def test_suggest_adjacent(report_file: Path) -> None:
    report = parse_report(report_file)
    suggestions = suggest_adjacent(
        report.findings, {"contracts/Vault.sol": ["withdrawAll", "setFee"]}
    )
    # withdrawAll changed in a file implicated by past high finding H-01.
    assert any(
        s["finding_id"] == "H-01" and "withdrawAll" in s["target"]
        for s in suggestions
    )


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def test_report_summary_and_plain_text(
    vuln_repo: Path, report_file: Path
) -> None:
    report = parse_report(report_file)
    finding = next(f for f in report.findings if f.id == "H-01")
    verdicts = walk_versions(finding, vuln_repo, ["v1.0", "v2.0", "v3.0", "v3.1"])

    summary = summarize_verdicts(verdicts, ["v1.0", "v2.0", "v3.0", "v3.1"])
    assert summary["per_version"]["v1.0"]["still_open"] == 1
    assert summary["per_version"]["v2.0"]["band_aid"] == 1
    assert summary["per_version"]["v3.0"]["fixed"] == 1
    assert summary["per_version"]["v3.1"]["regressed"] == 1
    assert summary["per_finding"]["H-01"]["v2.0"] == "BAND-AID"

    text = render_text(summary)
    assert "Version v2.0" in text
    assert "patched only on the surface" in text
    assert "Bottom line" in text
    # Jargon-light: no git/hunk/heuristic internals leak into the text.
    for banned in ("hunk", "ref ", "regex", "heuristic"):
        assert banned not in text.lower()


def test_queue_default_path_follows_repo_convention(tmp_path: Path) -> None:
    from web3guard.history.redive import default_queue_path

    assert default_queue_path(tmp_path) == tmp_path / ".web3guard" / "redive_queue.json"

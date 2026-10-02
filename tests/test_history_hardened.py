"""Hardened history-engine tests (Phase 2: cross-file tracking, refactor-
resistant verdicts, exhaustive re-dive queue).

Covers the adversarial findings from docs/ADVERSARIAL_LIMITS.md (Batch 05):

- moved-but-buggy code declared FIXED (cross-file blindness);
- renamed/reshuffled-but-vulnerable code reading FIXED or BAND-AID
  instead of STILL OPEN;
- textbook checks-effects-interactions fix (no marker) reading STILL OPEN;
- access-control findings stuck at BAND-AID forever by by-design-public
  functions;
- generic-class findings stuck at STILL OPEN forever (no REGRESSED);
- reversed version order fabricating REGRESSED;
- re-dive queue missing mid-history verdicts / silently dropping items.

No network, no API keys. Everything runs against throwaway git repos in
tmp_path.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from web3guard.history import (
    RESOLVED_ACCEPTED_RISK,
    RESOLVED_FIXED,
    RESOLVED_STILL_OPEN,
    RediveQueue,
    build_xref,
    canonicalize_function,
    parse_report,
    suggest_adjacent,
    walk_versions,
)
from web3guard.history.diff import GitError  # noqa: F401  (re-export check)
from web3guard.history.ingest import AuditFinding
from web3guard.history.normalize import (
    is_pure_reshuffle,
    is_rename,
    similarity,
    statement_multiset,
)
from web3guard.history.verdicts import (
    BAND_AID,
    FIXED,
    REGRESSED,
    STILL_OPEN,
    VersionVerdict,
    analyze_version,
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


def _make_repo(tmp_path: Path, name: str, versions: list[tuple[str, dict[str, str]]]) -> Path:
    """Build a git repo; each version is (tag, {path: source})."""
    repo = tmp_path / name
    repo.mkdir()
    _git(repo, "init", "-q")
    for tag, files in versions:
        for rel, source in files.items():
            target = repo / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source)
        # Remove files deleted in this version.
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", tag)
        _git(repo, "tag", tag)
        # Ensure distinct commit timestamps for version ordering.
        time.sleep(1.05)
    return repo


def _finding(**kwargs) -> AuditFinding:
    base = dict(
        id="H-01",
        title="Reentrancy in withdraw drains the vault",
        severity="high",
        description="The withdraw function sends Ether via call before "
        "updating balances: classic reentrancy.",
        files=["contracts/Vault.sol"],
        functions=["withdraw"],
    )
    base.update(kwargs)
    return AuditFinding(**base)


# ---------------------------------------------------------------------------
# Fixture A: rename + reshuffle (hole intact) -> genuine CEI fix (no marker)
# ---------------------------------------------------------------------------

_A_VAULT_V1 = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send fail");
        balances[msg.sender] -= amount;
    }
}
"""

# v2: renamed to cashOut AND reshuffled (call hoisted above the require),
# but the hole is intact: the external call still precedes the state update.
_A_VAULT_V2 = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function cashOut(uint256 amt) external {
        (bool ok,) = msg.sender.call{value: amt}("");
        require(balances[msg.sender] >= amt, "insufficient");
        require(ok, "send fail");
        balances[msg.sender] -= amt;
    }
}
"""

# v3: genuine fix — state updated BEFORE the external call. No
# nonReentrant marker: the textbook checks-effects-interactions fix.
_A_VAULT_V3 = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function cashOut(uint256 amt) external {
        require(balances[msg.sender] >= amt, "insufficient");
        balances[msg.sender] -= amt;
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok, "send fail");
    }
}
"""


@pytest.fixture()
def repo_reshuffle(tmp_path: Path) -> Path:
    return _make_repo(
        tmp_path,
        "reshuffle",
        [
            ("v1", {"contracts/Vault.sol": _A_VAULT_V1}),
            ("v2", {"contracts/Vault.sol": _A_VAULT_V2}),
            ("v3", {"contracts/Vault.sol": _A_VAULT_V3}),
        ],
    )


def test_rename_reshuffle_is_not_fixed(repo_reshuffle: Path) -> None:
    """v2 merely renames + reshuffles the vulnerable function (hole intact).

    The verdict must NOT be FIXED. The tracker must follow the rename via
    the rename-resistant fingerprint, and the reshuffle must not read as
    a fix because the vulnerable property (call-before-update) holds.
    """
    verdicts = walk_versions(_finding(), repo_reshuffle, ["v1", "v2", "v3"])
    by_version = {v.version: v for v in verdicts}
    assert by_version["v1"].verdict == STILL_OPEN
    v2 = by_version["v2"]
    assert v2.verdict != FIXED, (
        f"renamed/reshuffled-but-vulnerable must not read FIXED; evidence: {v2.evidence}"
    )
    # The evidence must show the tracker followed the code, not the name.
    blob = " ".join(v2.evidence).lower()
    assert "cashout" in blob or "reshuffl" in blob or "renam" in blob
    # v3 is the genuine checks-effects-interactions fix (no marker).
    v3 = by_version["v3"]
    assert v3.verdict == FIXED, f"genuine CEI fix must read FIXED; evidence: {v3.evidence}"


def test_pure_rename_is_still_open_not_bandaid(tmp_path: Path) -> None:
    """A pure rename of still-buggy code is STILL OPEN — a rename is not a
    fix attempt, so BAND-AID would be dishonest."""
    v1 = _A_VAULT_V1
    v2 = _A_VAULT_V1.replace(
        "function withdraw(uint256 amount) external {",
        "function withdrawFunds(uint256 amount) external {",
    )
    repo = _make_repo(
        tmp_path, "purerename", [("v1", {"contracts/Vault.sol": v1}), ("v2", {"contracts/Vault.sol": v2})]
    )
    verdicts = walk_versions(_finding(), repo, ["v1", "v2"])
    assert verdicts[1].verdict == STILL_OPEN
    blob = " ".join(verdicts[1].evidence).lower()
    assert "rename" in blob


# ---------------------------------------------------------------------------
# Fixture B: the fix moves the function to a different file
# ---------------------------------------------------------------------------

_B_VAULT_V1 = _A_VAULT_V1
_B_VAULT_V2 = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
"""
_B_TREASURY_V2 = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Vault.sol";

contract Treasury {
    mapping(address => uint256) public balances;

    function payout(uint256 amt) external {
        require(balances[msg.sender] >= amt, "insufficient");
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok, "send fail");
        balances[msg.sender] -= amt;
    }
}
"""
# v3: the moved function is genuinely fixed (CEI) in its new home.
_B_TREASURY_V3 = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Vault.sol";

contract Treasury {
    mapping(address => uint256) public balances;

    function payout(uint256 amt) external {
        require(balances[msg.sender] >= amt, "insufficient");
        balances[msg.sender] -= amt;
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok, "send fail");
    }
}
"""


@pytest.fixture()
def repo_moved(tmp_path: Path) -> Path:
    return _make_repo(
        tmp_path,
        "moved",
        [
            ("v1", {"contracts/Vault.sol": _B_VAULT_V1}),
            (
                "v2",
                {
                    "contracts/Vault.sol": _B_VAULT_V2,
                    "contracts/Treasury.sol": _B_TREASURY_V2,
                },
            ),
            (
                "v3",
                {
                    "contracts/Vault.sol": _B_VAULT_V2,
                    "contracts/Treasury.sol": _B_TREASURY_V3,
                },
            ),
        ],
    )


def test_moved_code_is_followed_not_declared_fixed(repo_moved: Path) -> None:
    """v2 moves the vulnerable function to Treasury.sol (renamed to payout).

    The old engine scanned only the report-named file and declared FIXED
    without ever looking at the new file. The tracker must follow the
    code: v2 is STILL OPEN with the new location named; v3 (genuinely
    fixed in the new file) is FIXED with the new location named.
    """
    verdicts = walk_versions(_finding(), repo_moved, ["v1", "v2", "v3"])
    by_version = {v.version: v for v in verdicts}
    assert by_version["v1"].verdict == STILL_OPEN

    v2 = by_version["v2"]
    assert v2.verdict != FIXED, (
        f"moved-but-buggy code must not read FIXED; evidence: {v2.evidence}"
    )
    assert any("Treasury.sol" in e for e in v2.evidence), (
        f"v2 evidence must name the new location; got: {v2.evidence}"
    )

    v3 = by_version["v3"]
    assert v3.verdict == FIXED, f"fixed-in-new-file must read FIXED; evidence: {v3.evidence}"
    assert any("Treasury.sol" in e for e in v3.evidence), (
        f"v3 FIXED evidence must name where the fix lives; got: {v3.evidence}"
    )


def test_xref_locate_follows_cross_file_move(repo_moved: Path) -> None:
    """The reference map finds the function in its new file by fingerprint."""
    xref = build_xref(str(repo_moved), "v2")
    assert "contracts/Treasury.sol" in xref.files
    assert xref.files["contracts/Treasury.sol"].imports == ["contracts/Vault.sol"]
    assert xref.neighbors("contracts/Vault.sol")["importers"] == [
        "contracts/Treasury.sol"
    ]
    from web3guard.history.diff import extract_solidity_functions, file_content_at

    src_v1 = file_content_at(repo_moved, "v1", "contracts/Vault.sol")
    assert src_v1 is not None
    v1_body = extract_solidity_functions(src_v1)["withdraw"]
    path, name, how = xref.locate_function(
        "withdraw", ["contracts/Vault.sol"], v1_body, "withdraw"
    )
    assert path == "contracts/Treasury.sol"
    assert name == "payout"
    assert how == "fingerprint"


# ---------------------------------------------------------------------------
# Fixture C: access control — guarding the implicated fn must reach FIXED
# ---------------------------------------------------------------------------

_C_VAULT_V1 = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;
    uint256 public fee;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function setFee(uint256 newFee) external {
        fee = newFee;
    }
}
"""
_C_VAULT_V2 = _C_VAULT_V1.replace(
    "function setFee(uint256 newFee) external {",
    "function setFee(uint256 newFee) external onlyOwner {",
)


@pytest.fixture()
def repo_acl(tmp_path: Path) -> Path:
    return _make_repo(
        tmp_path,
        "acl",
        [
            ("v1", {"contracts/Vault.sol": _C_VAULT_V1}),
            ("v2", {"contracts/Vault.sol": _C_VAULT_V2}),
        ],
    )


def _acl_finding() -> AuditFinding:
    return _finding(
        id="M-01",
        title="Missing access control on setFee",
        severity="high",
        description="setFee is reachable by anyone and changes the protocol "
        "fee. Missing access control.",
        files=["contracts/Vault.sol"],
        functions=["setFee"],
    )


def test_access_control_fix_reaches_fixed(repo_acl: Path) -> None:
    """Guarding setFee with onlyOwner must read FIXED — the still-public
    deposit() must not hold the verdict at BAND-AID forever."""
    verdicts = walk_versions(_acl_finding(), repo_acl, ["v1", "v2"])
    assert verdicts[0].verdict == STILL_OPEN
    assert verdicts[1].verdict == FIXED, (
        f"guarded setFee must read FIXED; evidence: {verdicts[1].evidence}"
    )


def test_access_control_elsewhere_becomes_lead_not_verdict(repo_acl: Path) -> None:
    """deposit() stays public and writes state: it becomes an adjacent-code
    lead for human review, not a verdict-blocking band-aid."""
    analysis = analyze_version(repo_acl, "v2", _acl_finding())
    assert not analysis.pattern_elsewhere, (
        f"by-design-public functions must not block FIXED: {analysis.pattern_elsewhere}"
    )
    assert any("deposit" in lead for lead in analysis.adjacent_leads)


def test_access_control_shared_privileged_state_is_bandaid(tmp_path: Path) -> None:
    """A second unguarded function writing the SAME privileged state the
    finding was about is a genuine cross-file band-aid and blocks FIXED."""
    v2 = _C_VAULT_V2.replace(
        """    function setFee(uint256 newFee) external onlyOwner {
        fee = newFee;
    }""",
        """    function setFee(uint256 newFee) external onlyOwner {
        fee = newFee;
    }

    function setFeeEmergency(uint256 newFee) external {
        fee = newFee;
    }""",
    )
    repo = _make_repo(
        tmp_path,
        "aclband",
        [
            ("v1", {"contracts/Vault.sol": _C_VAULT_V1}),
            ("v2", {"contracts/Vault.sol": v2}),
        ],
    )
    verdicts = walk_versions(_acl_finding(), repo, ["v1", "v2"])
    assert verdicts[1].verdict == BAND_AID
    assert any("setFeeEmergency" in e for e in verdicts[1].evidence)


# ---------------------------------------------------------------------------
# Fixture D: generic class — rename must not fix, real change must
# ---------------------------------------------------------------------------

_D_V1 = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FeeMath {
    function calcFee(uint256 amount) external pure returns (uint256) {
        uint256 fee = amount * 3 / 1000;
        return fee;
    }
}
"""
_D_V2 = _D_V1.replace("function calcFee(", "function computeFee(")
_D_V3 = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FeeMath {
    function computeFee(uint256 amount) external pure returns (uint256) {
        require(amount > 0, "zero amount");
        uint256 fee = amount * 5 / 1000;
        require(fee <= amount, "fee exceeds amount");
        return fee;
    }
}
"""
# v4: the old vulnerable shape comes back under the new name.
_D_V4 = _D_V1.replace("function calcFee(", "function computeFee(")


@pytest.fixture()
def repo_generic(tmp_path: Path) -> Path:
    return _make_repo(
        tmp_path,
        "generic",
        [
            ("v1", {"contracts/FeeMath.sol": _D_V1}),
            ("v2", {"contracts/FeeMath.sol": _D_V2}),
            ("v3", {"contracts/FeeMath.sol": _D_V3}),
            ("v4", {"contracts/FeeMath.sol": _D_V4}),
        ],
    )


def _rounding_finding() -> AuditFinding:
    return _finding(
        id="M-02",
        title="Rounding error in calcFee",
        severity="medium",
        description="The fee computation loses precision for small amounts.",
        files=["contracts/FeeMath.sol"],
        functions=["calcFee"],
    )


def test_generic_class_full_lifecycle(repo_generic: Path) -> None:
    """Generic findings: rename -> STILL OPEN (not FIXED); genuine change ->
    FIXED (not STILL OPEN); reintroduced shape -> REGRESSED."""
    verdicts = walk_versions(_rounding_finding(), repo_generic, ["v1", "v2", "v3", "v4"])
    got = [(v.version, v.verdict) for v in verdicts]
    assert got == [
        ("v1", STILL_OPEN),
        ("v2", STILL_OPEN),  # pure rename: not FIXED
        ("v3", FIXED),  # genuine fix: not STILL OPEN
        ("v4", REGRESSED),  # old shape back: regression detected
    ], f"unexpected timeline: {got}"


# ---------------------------------------------------------------------------
# Version ordering: reversed input must not fabricate REGRESSED
# ---------------------------------------------------------------------------


def test_reversed_version_order_is_safe(repo_reshuffle: Path) -> None:
    ordered = walk_versions(_finding(), repo_reshuffle, ["v1", "v2", "v3"])
    reversed_in = walk_versions(_finding(), repo_reshuffle, ["v3", "v2", "v1"])
    assert [v.version for v in reversed_in] == ["v1", "v2", "v3"]
    assert [v.verdict for v in reversed_in] == [v.verdict for v in ordered]


# ---------------------------------------------------------------------------
# normalize.py unit tests
# ---------------------------------------------------------------------------


def test_canonicalize_is_rename_resistant() -> None:
    a = "function withdraw(uint256 amount) external { balances[msg.sender] -= amount; }"
    b = "function cashOut(uint256 amt) external { balances[msg.sender] -= amt; }"
    assert canonicalize_function("withdraw", a) == canonicalize_function("cashOut", b)
    assert is_rename("withdraw", a, "cashOut", b)


def test_canonicalize_preserves_statement_order() -> None:
    a = "function f() public { x = 1; y = 2; }"
    b = "function f() public { y = 2; x = 1; }"
    assert canonicalize_function("f", a) != canonicalize_function("f", b)
    assert statement_multiset(a, "f") == statement_multiset(b, "f")
    assert is_pure_reshuffle("f", a, "f", b)


def test_similarity_extremes() -> None:
    assert similarity("abc", "abc") == 1.0
    assert similarity("", "abc") == 0.0
    assert 0.0 < similarity("aaa bbb", "aaa ccc") < 1.0


# ---------------------------------------------------------------------------
# Ingest: hedged audit language is kept, not dropped
# ---------------------------------------------------------------------------


def test_hedged_language_becomes_low_confidence_finding(tmp_path: Path) -> None:
    path = tmp_path / "audit.md"
    path.write_text(
        "# Audit\n\n"
        "## Note on withdraw\n\n"
        "The `withdraw()` function in `contracts/Vault.sol` may be at risk "
        "under certain conditions.\n\n"
        "## Summary\n\n"
        "No potential vulnerabilities were found elsewhere.\n"
    )
    report = parse_report(path)
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.severity == "low"
    assert finding.confidence <= 0.3
    assert "withdraw" in finding.functions


# ---------------------------------------------------------------------------
# Re-dive queue: explicit resolved states, persistence, exhaustiveness
# ---------------------------------------------------------------------------


def test_resolve_outcome_taxonomy(tmp_path: Path) -> None:
    queue = RediveQueue(tmp_path / "q.json")
    item = queue.add("H-01", "t", "r")
    assert item.outcome == ""
    assert not item.is_terminal

    queue.resolve(item.id, "looked, risk accepted", by="AG BABY", outcome=RESOLVED_ACCEPTED_RISK)
    got = queue.get(item.id)
    assert got is not None
    assert got.status == "resolved"
    assert got.outcome == RESOLVED_ACCEPTED_RISK
    assert got.is_terminal
    assert queue.unresolved() == []

    with pytest.raises(ValueError, match="outcome must be one of"):
        queue.resolve(item.id, "x", outcome="bogus")

    # Default outcome keeps the old two-argument call working.
    item2 = queue.add("H-02", "t", "r2")
    queue.resolve(item2.id, "done")
    assert queue.get(item2.id).outcome == RESOLVED_FIXED  # type: ignore[union-attr]


def test_still_open_is_an_explicit_resolved_state(tmp_path: Path) -> None:
    queue = RediveQueue(tmp_path / "q.json")
    item = queue.add("H-01", "t", "r")
    queue.resolve(item.id, "confirmed still exploitable", outcome=RESOLVED_STILL_OPEN)
    got = queue.get(item.id)
    assert got is not None and got.is_terminal
    assert got.outcome == RESOLVED_STILL_OPEN
    # A terminal STILL_OPEN item is a recorded decision, not a todo:
    # re-adding the same reason must not resurrect it.
    again = queue.add("H-01", "t", "r")
    assert again.id == item.id
    assert queue.unresolved() == []


def test_legacy_resolved_items_migrate_explicitly(tmp_path: Path) -> None:
    path = tmp_path / "q.json"
    path.write_text(
        json.dumps(
            [
                {
                    "id": "rd-old",
                    "finding_id": "H-01",
                    "title": "t",
                    "reason": "r",
                    "status": "resolved",
                    "claimed_by": "",
                    "created_at": 1.0,
                    "events": [],
                }
            ]
        )
    )
    queue = RediveQueue(path)
    item = queue.get("rd-old")
    assert item is not None
    assert item.outcome == RESOLVED_FIXED
    assert item.is_terminal
    assert any(e["event"] == "outcome-migrated" for e in item.events)


def test_corrupt_queue_is_quarantined_not_truncated(tmp_path: Path) -> None:
    path = tmp_path / "q.json"
    path.write_text("{not valid json!!!")
    queue = RediveQueue(path)
    assert queue.list() == []
    backups = list(tmp_path.glob("q.corrupt-*.bak"))
    assert len(backups) == 1
    assert "not valid json" in backups[0].read_text()
    # The queue is usable again after quarantine.
    queue.add("H-01", "t", "r")
    assert len(RediveQueue(path).list()) == 1


def test_sync_from_history_covers_mid_history_verdicts(tmp_path: Path) -> None:
    """Every BAND-AID / REGRESSED at every version gets a tracked item —
    not just the latest version (the old pipeline's hand-rolled gap)."""
    queue = RediveQueue(tmp_path / "q.json")
    finding = _finding()
    verdicts = [
        VersionVerdict("H-01", "v1", STILL_OPEN, "high", ["e1"]),
        VersionVerdict("H-01", "v2", BAND_AID, "high", ["e2"]),
        VersionVerdict("H-01", "v3", FIXED, "high", ["e3"]),
        VersionVerdict("H-01", "v4", REGRESSED, "high", ["e4"]),
    ]
    added = queue.sync_from_history("H-01", verdicts, finding)
    assert len(added) == 2  # BAND-AID@v2 + REGRESSED@v4
    assert {i.status for i in queue.unresolved()} == {"open"}

    # Idempotent: re-running neither duplicates nor drops.
    queue.sync_from_history("H-01", verdicts, finding)
    assert len(queue.list()) == 2

    # The finding later read FIXED at v3: open items get a note, but are
    # NOT auto-resolved — a human must decide explicitly.
    band_aid_item = next(i for i in queue.list() if "BAND-AID" in i.reason)
    assert not band_aid_item.is_terminal
    assert any(e["event"] == "superseded-noted" for e in band_aid_item.events)
    # No duplicate note on re-sync.
    queue.sync_from_history("H-01", verdicts, finding)
    notes = [
        e for e in queue.get(band_aid_item.id).events  # type: ignore[union-attr]
        if e["event"] == "superseded-noted"
    ]
    assert len(notes) == 1


def test_sync_queues_still_open_high_at_latest(tmp_path: Path) -> None:
    queue = RediveQueue(tmp_path / "q.json")
    finding = _finding(severity="high")
    verdicts = [VersionVerdict("H-01", "v3", STILL_OPEN, "high", ["still bad"])]
    added = queue.sync_from_history("H-01", verdicts, finding)
    assert len(added) == 1
    assert "STILL OPEN" in added[0].reason


def test_stale_claims_watchdog(tmp_path: Path) -> None:
    queue = RediveQueue(tmp_path / "q.json")
    item = queue.add("H-01", "t", "r")
    queue.claim(item.id, by="AG BABY")
    assert queue.stale_claims(max_age_days=14) == []
    # Backdate the claim: the watchdog must flag it.
    item.created_at = time.time() - 20 * 86400
    queue._save()
    queue2 = RediveQueue(tmp_path / "q.json")
    stale = queue2.stale_claims(max_age_days=14)
    assert [i.id for i in stale] == [item.id]
    # Claimed items are unresolved until an explicit outcome is recorded.
    assert [i.id for i in queue2.unresolved()] == [item.id]


def test_queue_survives_roundtrip_with_outcomes(tmp_path: Path) -> None:
    queue = RediveQueue(tmp_path / "q.json")
    item = queue.add("H-01", "t", "r")
    queue.resolve(item.id, "accepted", outcome=RESOLVED_ACCEPTED_RISK)
    queue2 = RediveQueue(tmp_path / "q.json")
    got = queue2.get(item.id)
    assert got is not None
    assert got.outcome == RESOLVED_ACCEPTED_RISK
    assert got.is_terminal


# ---------------------------------------------------------------------------
# suggest_adjacent: cross-file neighbours from the xref map
# ---------------------------------------------------------------------------


def test_suggest_adjacent_cross_file(repo_moved: Path) -> None:
    xref = build_xref(str(repo_moved), "v2")
    suggestions = suggest_adjacent([_finding(severity="high")], xref=xref)
    relations = {(s["target"], s["relation"]) for s in suggestions}
    # contracts/Treasury.sol imports contracts/Vault.sol (implicated file).
    assert any(
        target == "contracts/Treasury.sol" and "importing" in relation
        for target, relation in relations
    ), f"expected a cross-file suggestion; got {relations}"


def test_adjacent_leads_are_queued_until_resolved(tmp_path: Path) -> None:
    queue = RediveQueue(tmp_path / "q.json")
    suggestions = [
        {
            "finding_id": "H-01",
            "title": "t",
            "severity": "high",
            "target": "contracts/Treasury.sol",
            "relation": "importing code implicated by",
            "detail": "imports the implicated file",
        }
    ]
    added = queue.add_adjacent_suggestions(suggestions)
    assert len(added) == 1
    assert len(queue.unresolved()) == 1
    queue.resolve(added[0].id, "checked, clean", outcome=RESOLVED_FIXED)
    assert queue.unresolved() == []

"""Tests for the findings database lifecycle, especially that the
dashboard's short fingerprint can be used with `mark`."""

import pytest

from web3guard.findings_db import FindingsDB, FindingRecord


@pytest.fixture()
def db(tmp_path):
    return FindingsDB(tmp_path / "findings.db")


def _add(db, fingerprint):
    db.upsert(FindingRecord(
        fingerprint=fingerprint,
        target="t",
        language="solidity",
        file="f.sol",
        category="reentrancy",
        severity="HIGH",
        confidence=1.0,
        status="new",
    ))


def test_update_status_full_fingerprint(db):
    _add(db, "abcdef0123456789abcdef0123456789")
    db.update_status("abcdef0123456789abcdef0123456789", "submitted")
    assert db.list_findings()[0].status == "submitted"


def test_update_status_short_prefix(db):
    _add(db, "abcdef0123456789abcdef0123456789")
    db.update_status("abcdef01234567", "submitted")
    assert db.list_findings()[0].status == "submitted"


def test_update_status_prefix_ambiguous_raises(db):
    _add(db, "abc11111111111111111111111111111")
    _add(db, "abc22222222222222222222222222222")
    with pytest.raises(KeyError):
        db.update_status("abc", "submitted")


def test_update_status_unknown_raises(db):
    with pytest.raises(KeyError):
        db.update_status("deadbeef", "submitted")

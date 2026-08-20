"""
SQLite-backed findings database.

Tracks the lifecycle of each finding across runs:

- "new" — first time the scanner saw this finding
- "submitted" — the user submitted it to a bounty program
- "accepted" — the program accepted it as a valid finding
- "paid" — the program paid out; record the amount
- "rejected" — the program rejected it; record the reason
- "duplicate" — someone else submitted first

Persists to a local SQLite file so you can come back later and
update statuses. Also gives you a CLI command to do so.

The DB is intentionally simple — one table per finding plus a
status history table. A `dashboard` subcommand renders a TUI
summary of your hunt history.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger("web3guard.findings_db")


@dataclass
class FindingRecord:
    """A finding as stored in the DB."""
    fingerprint: str
    target: str
    language: str
    file: str
    function: str = ""
    category: str = ""
    severity: str = "LOW"
    confidence: float = 0.5
    swc_id: str = ""
    description: str = ""
    status: str = "new"           # new | submitted | accepted | paid | rejected | duplicate
    submission_program: str = ""  # "Immunefi" | "Sherlock" | ...
    submission_id: str = ""
    paid_amount_usd: float = 0.0
    rejection_reason: str = ""
    poc_code: str = ""
    exploit_log: str = ""
    first_seen_ts: float = 0.0
    last_seen_ts: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_finding(cls, f: Any) -> FindingRecord:
        """Build a record from a :class:`web3guard.scanner.Finding`."""
        fp = f.fingerprint
        if not fp:
            import hashlib
            h = hashlib.sha256()
            h.update((f.target or "").encode())
            h.update((f.file or "").encode())
            h.update((f.function or "").encode())
            h.update((f.category or "").encode())
            fp = h.hexdigest()[:32]
        ts = time.time()
        return cls(
            fingerprint=fp,
            target=f.target,
            language=f.language,
            file=f.file,
            function=f.function,
            category=f.category,
            severity=f.severity,
            confidence=f.confidence,
            swc_id=f.swc_id,
            description=f.description,
            status="new",
            poc_code=f.poc_code,
            exploit_log=f.exploit_log,
            first_seen_ts=ts,
            last_seen_ts=ts,
            metadata={
                "reasoning": f.reasoning,
                "line_hint": f.line_hint,
                "tool_consensus": f.tool_consensus,
                "dynamically_confirmed": f.dynamically_confirmed,
                **f.metadata,
            },
        )


class FindingsDB:
    """SQLite-backed store for findings and their submission status."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with closing(sqlite3.connect(str(self.db_path))) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS findings (
                    fingerprint TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    language TEXT,
                    file TEXT,
                    function TEXT,
                    category TEXT,
                    severity TEXT,
                    confidence REAL,
                    swc_id TEXT,
                    description TEXT,
                    status TEXT NOT NULL DEFAULT 'new',
                    submission_program TEXT,
                    submission_id TEXT,
                    paid_amount_usd REAL DEFAULT 0,
                    rejection_reason TEXT,
                    poc_code TEXT,
                    exploit_log TEXT,
                    first_seen_ts REAL,
                    last_seen_ts REAL,
                    metadata TEXT
                );
                CREATE TABLE IF NOT EXISTS status_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT NOT NULL,
                    ts REAL NOT NULL,
                    old_status TEXT,
                    new_status TEXT,
                    note TEXT,
                    FOREIGN KEY (fingerprint) REFERENCES findings(fingerprint)
                );
                CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
                CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            """)
            conn.commit()

    def upsert(self, rec: FindingRecord) -> None:
        with closing(sqlite3.connect(str(self.db_path))) as conn:
            existing = conn.execute(
                "SELECT first_seen_ts, status FROM findings WHERE fingerprint = ?",
                (rec.fingerprint,),
            ).fetchone()
            if existing:
                first_seen = existing[0]
                conn.execute("""
                    UPDATE findings SET
                        last_seen_ts = ?, target = ?, language = ?, file = ?,
                        function = ?, category = ?, severity = ?, confidence = ?,
                        swc_id = ?, description = ?, poc_code = ?, exploit_log = ?,
                        metadata = ?
                    WHERE fingerprint = ?
                """, (
                    rec.last_seen_ts, rec.target, rec.language, rec.file,
                    rec.function, rec.category, rec.severity, rec.confidence,
                    rec.swc_id, rec.description, rec.poc_code, rec.exploit_log,
                    json.dumps(rec.metadata, default=str),
                    rec.fingerprint,
                ))
            else:
                first_seen = rec.first_seen_ts or rec.last_seen_ts
                conn.execute("""
                    INSERT INTO findings (
                        fingerprint, target, language, file, function, category,
                        severity, confidence, swc_id, description, status,
                        poc_code, exploit_log, first_seen_ts, last_seen_ts, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    rec.fingerprint, rec.target, rec.language, rec.file, rec.function,
                    rec.category, rec.severity, rec.confidence, rec.swc_id,
                    rec.description, rec.status, rec.poc_code, rec.exploit_log,
                    first_seen, rec.last_seen_ts,
                    json.dumps(rec.metadata, default=str),
                ))
            conn.commit()

    def _resolve_fingerprint(self, fingerprint: str) -> str:
        """Resolve a full fingerprint or a unique prefix to a stored one."""
        with closing(sqlite3.connect(str(self.db_path))) as conn:
            rows = conn.execute(
                "SELECT fingerprint FROM findings WHERE fingerprint LIKE ?",
                (f"{fingerprint}%",),
            ).fetchall()
        matches = [r[0] for r in rows]
        if not matches:
            raise KeyError(f"fingerprint {fingerprint!r} not found")
        if len(matches) > 1:
            raise KeyError(
                f"fingerprint {fingerprint!r} is ambiguous "
                f"({len(matches)} matches); use the full fingerprint"
            )
        return matches[0]

    def update_status(
        self,
        fingerprint: str,
        new_status: str,
        *,
        note: str = "",
        submission_program: str = "",
        submission_id: str = "",
        paid_amount_usd: float = 0.0,
        rejection_reason: str = "",
    ) -> None:
        fingerprint = self._resolve_fingerprint(fingerprint)
        with closing(sqlite3.connect(str(self.db_path))) as conn:
            old = conn.execute(
                "SELECT status FROM findings WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if not old:
                raise KeyError(f"fingerprint {fingerprint!r} not found")
            old_status = old[0]
            conn.execute("""
                UPDATE findings SET
                    status = ?,
                    submission_program = COALESCE(NULLIF(?, ''), submission_program),
                    submission_id = COALESCE(NULLIF(?, ''), submission_id),
                    paid_amount_usd = ?,
                    rejection_reason = COALESCE(NULLIF(?, ''), rejection_reason),
                    last_seen_ts = ?
                WHERE fingerprint = ?
            """, (
                new_status, submission_program, submission_id,
                paid_amount_usd, rejection_reason, time.time(), fingerprint,
            ))
            conn.execute("""
                INSERT INTO status_history (fingerprint, ts, old_status, new_status, note)
                VALUES (?, ?, ?, ?, ?)
            """, (fingerprint, time.time(), old_status, new_status, note))
            conn.commit()

    def list_findings(
        self,
        *,
        status: str | None = None,
        target: str | None = None,
        severity: str | None = None,
        limit: int = 1000,
    ) -> list[FindingRecord]:
        clauses, args = [], []
        if status:
            clauses.append("status = ?")
            args.append(status)
        if target:
            clauses.append("target LIKE ?")
            args.append(f"%{target}%")
        if severity:
            clauses.append("severity = ?")
            args.append(severity)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        with closing(sqlite3.connect(str(self.db_path))) as conn:
            rows = conn.execute(
                f"SELECT * FROM findings {where} ORDER BY last_seen_ts DESC LIMIT ?",
                (*args, limit),
            ).fetchall()
        return [_row_to_record(r) for r in rows]

    def summary(self) -> dict[str, Any]:
        with closing(sqlite3.connect(str(self.db_path))) as conn:
            total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            by_status = {row[0]: row[1] for row in conn.execute(
                "SELECT status, COUNT(*) FROM findings GROUP BY status"
            ).fetchall()}
            paid_total = conn.execute(
                "SELECT COALESCE(SUM(paid_amount_usd), 0) FROM findings"
            ).fetchone()[0]
            by_severity = {row[0]: row[1] for row in conn.execute(
                "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
            ).fetchall()}
        return {
            "total": total,
            "by_status": by_status,
            "by_severity": by_severity,
            "paid_total_usd": paid_total,
        }


def _row_to_record(row: tuple) -> FindingRecord:
    cols = (
        "fingerprint", "target", "language", "file", "function", "category",
        "severity", "confidence", "swc_id", "description", "status",
        "submission_program", "submission_id", "paid_amount_usd",
        "rejection_reason", "poc_code", "exploit_log", "first_seen_ts",
        "last_seen_ts", "metadata",
    )
    d = dict(zip(cols, row, strict=True))
    try:
        d["metadata"] = json.loads(d.get("metadata") or "{}")
    except (ValueError, TypeError):
        d["metadata"] = {}
    return FindingRecord(**d)

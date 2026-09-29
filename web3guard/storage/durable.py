"""DurableStore — the facade all Web3Guard persistence goes through.

v3.5 architecture ("write local, replicate remote, sync later"):

1. **Local SQLite is the source of truth.** Every write lands locally
   first (WAL mode, so crashes lose nothing committed).
2. **Remote is best-effort immediate.** When a Postgres/Supabase backend
   is configured, the same statement is attempted remotely right away.
3. **Missed remote writes go to an outbox.** Failed remote writes are
   recorded locally (operation + SQL + params) and replayed by
   :meth:`DurableStore.sync` — from the CLI, a cron entry, or the bot's
   periodic tick. Replay is idempotent (upserts keyed by primary key).

Beyond findings, the store owns the v3.5 schemas: cost records (global
budget control), LLM cache, state KV (Telegram/GitHub persistence),
evidence memory, and scan runs. Retention is enforced by
:meth:`DurableStore.enforce_retention` so "durable" never becomes
"unbounded disk growth" (see docs/STORAGE_POLICY.md).

Backends are chosen, not built, by this class: callers hand in a
:class:`SqliteBackend` (local, required) and optionally a
:class:`PostgresBackend` (remote). Constructing the remote backend via
:func:`web3guard.storage.make_backend_from_env` keeps DSN handling in
one place.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from web3guard.storage.base import StorageBackend, StorageError
from web3guard.storage.sqlite_backend import SqliteBackend
from web3guard.storage.routing import StorageRouter

LOGGER = logging.getLogger("web3guard.storage")

from web3guard.state import StateStore  # noqa: E402  (low-level, no cycle)

# Outbox row older than this is dropped with a warning (it would mean
# the remote has been down for days; replaying weeks of writes in one
# burst is more risk than value).
OUTBOX_MAX_AGE_SECONDS = 14 * 24 * 3600
OUTBOX_MAX_ROWS = 50_000

# Default retention (overridable via config `storage:` block).
DEFAULT_RETENTION = {
    "cost_records_days": 180,
    "llm_cache_days": 30,
    "state_events_days": 90,
    "evidence_days": 365,
    "scan_runs_days": 180,
}


@dataclass
class StorageStatus:
    """Health/status snapshot for dashboards and /healthz."""
    local_ok: bool
    local_detail: str = ""
    remote_configured: bool = False
    remote_ok: bool = False
    remote_detail: str = ""
    outbox_pending: int = 0
    table_sizes: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "local": {"ok": self.local_ok, "detail": self.local_detail},
            "remote": {
                "configured": self.remote_configured,
                "ok": self.remote_ok,
                "detail": self.remote_detail,
            },
            "outbox_pending": self.outbox_pending,
            "table_sizes": self.table_sizes,
        }


class DurableStore:
    """Local-first durable persistence with optional remote replication."""

    def __init__(
        self,
        *,
        local: SqliteBackend,
        remote: StorageBackend | None = None,
        retention: dict[str, int] | None = None,
    ) -> None:
        if local is None:
            raise StorageError("DurableStore requires a local backend")
        self.local = local
        self.remote = remote
        self.retention = {**DEFAULT_RETENTION, **(retention or {})}
        self._init_local()
        if self.remote is not None:
            self._init_remote_quiet()
        self._state = StateStore(self, namespace="core")

    @property
    def state(self) -> StateStore:
        """Durable KV/event state (Telegram offsets, graph caches, cursors)."""
        return self._state

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_config(cls, workdir: Path, config: dict[str, Any]) -> DurableStore:
        """Build the store from scanner config + environment.

        Config keys (all optional, under ``storage:``)::

            storage:
              durable_db_path: .web3guard/durable.db
              remote: auto            # auto | off
              retention:
                cost_records_days: 180
        """
        router = StorageRouter.from_config(Path(workdir), config)
        local = SqliteBackend(router.durable_db_path)
        remote = None
        if router.remote_configured and router.remote_mode != "off":
            import os
            dsn = (os.environ.get(router.remote_dsn_env or "") or "").strip()
            if dsn:
                from web3guard.storage.postgres_backend import PostgresBackend
                try:
                    remote = PostgresBackend(dsn)
                except StorageError as e:
                    if router.remote_required:
                        raise
                    LOGGER.warning("remote storage unavailable, local-only: %s", e)
        retention_cfg = (
            (config.get("storage") or {}).get("retention")
            if isinstance(config.get("storage"), dict) else {}
        ) or {}
        store = cls(local=local, remote=remote, retention=dict(retention_cfg))
        if router.remote_required:
            if store.remote is None:
                raise StorageError(
                    "storage.remote=required but the remote backend could not be initialized"
                )
            remote_health = store.remote.health()
            if not remote_health.ok:
                raise StorageError(
                    "storage.remote=required but the remote backend is unhealthy: "
                    + remote_health.detail
                )
            try:
                store.remote.query_all("SELECT 1 FROM scan_runs LIMIT 1")
            except Exception as e:  # noqa: BLE001
                raise StorageError(
                    "storage.remote=required but the remote schema is unavailable: "
                    + str(e)[:300]
                ) from e
        return store

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    _SCHEMA_TABLES: tuple[str, ...] = (
        # Findings mirror (FindingsDB keeps its own file; this table is
        # the durable replica that syncs to Postgres).
        """
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
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS cost_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            provider TEXT NOT NULL,
            model TEXT NOT NULL,
            prompt_tokens INTEGER NOT NULL,
            completion_tokens INTEGER NOT NULL,
            cost_usd REAL NOT NULL,
            role TEXT NOT NULL,
            scan_id TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS llm_cache (
            key TEXT PRIMARY KEY,
            content TEXT NOT NULL,
            tokens_in INTEGER NOT NULL,
            tokens_out INTEGER NOT NULL,
            cost_usd REAL NOT NULL,
            ts REAL NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS state_kv (
            k TEXT PRIMARY KEY,
            v TEXT NOT NULL,
            updated_ts REAL NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS state_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            kind TEXT NOT NULL,
            key TEXT,
            payload TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS evidence_memory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT,
            target TEXT,
            category TEXT,
            severity TEXT,
            verdict TEXT,
            evidence TEXT,
            embedding_ref TEXT,
            ts REAL NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT,
            finished_at TEXT,
            targets INTEGER,
            findings INTEGER,
            confirmed INTEGER,
            cost_usd REAL,
            status TEXT,
            metadata TEXT
        )
        """,
        # Outbox: local journal of writes that must reach the remote.
        """
        CREATE TABLE IF NOT EXISTS outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            table_name TEXT NOT NULL,
            op TEXT NOT NULL,
            row_key TEXT NOT NULL,
            payload TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT
        )
        """,
    )

    _INDEXES: tuple[str, ...] = (
        "CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target)",
        "CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)",
        "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)",
        "CREATE INDEX IF NOT EXISTS idx_cost_ts ON cost_records(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_cost_scan ON cost_records(scan_id)",
        "CREATE INDEX IF NOT EXISTS idx_state_events_kind ON state_events(kind)",
        "CREATE INDEX IF NOT EXISTS idx_evidence_target ON evidence_memory(target)",
        "CREATE INDEX IF NOT EXISTS idx_outbox_pending ON outbox(attempts)",
        "CREATE INDEX IF NOT EXISTS idx_runs_started ON scan_runs(started_at)",
    )

    def _init_local(self) -> None:
        for ddl in self._SCHEMA_TABLES:
            self.local.execute(ddl)
        for idx in self._INDEXES:
            self.local.execute(idx)

    def _init_remote_quiet(self) -> None:
        """Best-effort remote schema init; failure is non-fatal."""
        assert self.remote is not None
        try:
            for ddl in self._SCHEMA_TABLES:
                self.remote.execute(ddl)
            for idx in self._INDEXES:
                self.remote.execute(idx)
        except Exception as e:  # noqa: BLE001
            LOGGER.warning("remote schema init failed (will retry via sync): %s", e)

    # ------------------------------------------------------------------
    # Write path: local first, remote best-effort, outbox on miss
    # ------------------------------------------------------------------

    def write(self, table: str, row_key: str, payload: dict[str, Any],
              *, upsert: bool = True) -> None:
        """Upsert one row into ``table`` locally, then replicate.

        ``payload`` values must be SQL scalars or JSON-serializable
        objects (dicts/lists are serialized to JSON strings).
        """
        cols = sorted(payload.keys())
        json_cols = {
            c for c, v in payload.items() if isinstance(v, (dict, list))
        }
        values = []
        for c in cols:
            v = payload[c]
            values.append(json.dumps(v) if c in json_cols else v)
        placeholders = ", ".join("?" for _ in cols)
        col_list = ", ".join(cols)
        if upsert:
            updates = ", ".join(f"{c} = excluded.{c}" for c in cols if c != row_key)
            sql = (
                f"INSERT INTO {table} ({col_list}) VALUES ({placeholders}) "
                f"ON CONFLICT({row_key}) DO UPDATE SET {updates}"
                if updates else
                f"INSERT INTO {table} ({col_list}) VALUES ({placeholders}) "
                f"ON CONFLICT({row_key}) DO NOTHING"
            )
        else:
            sql = f"INSERT INTO {table} ({col_list}) VALUES ({placeholders})"
        self.local.execute(sql, values)
        self._replicate(table, row_key, dict(zip(cols, values, strict=True)))

    def delete(self, table: str, row_key: str, row_value: Any) -> None:
        """Delete a local row and replicate the deletion when configured."""
        self.local.execute(
            f"DELETE FROM {table} WHERE {row_key} = ?",
            (row_value,),
        )
        if self.remote is None:
            return
        try:
            self.remote.execute(
                f"DELETE FROM {table} WHERE {row_key} = ?",
                (row_value,),
            )
        except Exception as e:  # noqa: BLE001
            self._enqueue_outbox(
                table,
                row_key,
                {row_key: row_value},
                str(e),
                op="delete",
            )

    def _replicate(self, table: str, row_key: str, values: dict[str, Any]) -> None:
        if self.remote is None:
            return
        cols = sorted(values.keys())
        placeholders = ", ".join("?" for _ in cols)
        updates = ", ".join(f"{c} = excluded.{c}" for c in cols if c != row_key)
        sql = (
            f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders}) "
            f"ON CONFLICT({row_key}) DO UPDATE SET {updates}"
        )
        try:
            self.remote.execute(sql, [values[c] for c in cols])
        except Exception as e:  # noqa: BLE001
            LOGGER.warning("remote write failed, queuing in outbox: %s", e)
            self._enqueue_outbox(table, row_key, values, str(e))

    def _enqueue_outbox(self, table: str, row_key: str,
                        values: dict[str, Any], error: str,
                        *, op: str = "upsert") -> None:
        try:
            self.local.execute(
                "INSERT INTO outbox (ts, table_name, op, row_key, payload, attempts, last_error)"
                " VALUES (?, ?, ?, ?, ?, 0, ?)",
                (time.time(), table, op, row_key,
                 json.dumps({k: v for k, v in values.items()}, default=str),
                 error[:500]),
            )
            self._trim_outbox()
        except Exception:  # noqa: BLE001
            LOGGER.exception("outbox enqueue failed; remote write is lost")

    def _trim_outbox(self) -> None:
        n = self.local.query_all("SELECT COUNT(*) AS n FROM outbox")[0]["n"]
        if n > OUTBOX_MAX_ROWS:
            self.local.execute(
                "DELETE FROM outbox WHERE id IN ("
                "SELECT id FROM outbox ORDER BY id ASC LIMIT ?)",
                (n - OUTBOX_MAX_ROWS,),
            )

    # ------------------------------------------------------------------
    # Sync (outbox replay)
    # ------------------------------------------------------------------

    def sync(self, *, limit: int = 500) -> dict[str, int]:
        """Replay outboxed writes to the remote backend.

        Returns ``{"replayed": n, "failed": m, "dropped": k}``. Safe to
        call repeatedly (idempotent upserts); safe with no remote
        configured (no-op).
        """
        if self.remote is None:
            return {"replayed": 0, "failed": 0, "dropped": 0}
        rows = self.local.query_all(
            "SELECT id, table_name, op, row_key, payload, attempts, ts FROM outbox"
            " ORDER BY id ASC LIMIT ?", (limit,))
        replayed = failed = dropped = 0
        for row in rows:
            age = time.time() - float(row["ts"])
            if age > OUTBOX_MAX_AGE_SECONDS:
                self.local.execute("DELETE FROM outbox WHERE id = ?", (row["id"],))
                dropped += 1
                continue
            try:
                payload = json.loads(row["payload"])
                values = {k: payload[k] for k in sorted(payload.keys())}
                self.remote.execute(
                    f"INSERT INTO {row['table_name']} "
                    f"({', '.join(values)}) VALUES "
                    f"({', '.join('?' for _ in values)}) "
                    f"ON CONFLICT({row['row_key']}) DO UPDATE SET "
                    + ", ".join(f"{c} = excluded.{c}" for c in values if c != row["row_key"]),
                    [values[c] for c in values],
                )
            except Exception as e:  # noqa: BLE001
                self.local.execute(
                    "UPDATE outbox SET attempts = attempts + 1, last_error = ?"
                    " WHERE id = ?", (str(e)[:500], row["id"]))
                failed += 1
                continue
            self.local.execute("DELETE FROM outbox WHERE id = ?", (row["id"],))
            replayed += 1
        return {"replayed": replayed, "failed": failed, "dropped": dropped}

    # ------------------------------------------------------------------
    # Read helpers (used by dashboard / serve / bot)
    # ------------------------------------------------------------------

    def status(self) -> StorageStatus:
        local_health = self.local.health()
        outbox = self.local.query_all("SELECT COUNT(*) AS n FROM outbox")
        sizes: dict[str, int] = {}
        for table in ("findings", "cost_records", "llm_cache", "state_kv",
                      "state_events", "evidence_memory", "scan_runs", "outbox"):
            try:
                sizes[table] = int(self.local.query_all(
                    f"SELECT COUNT(*) AS n FROM {table}")[0]["n"])  # noqa: S608
            except Exception:  # noqa: BLE001
                sizes[table] = -1
        st = StorageStatus(
            local_ok=local_health.ok,
            local_detail=local_health.detail,
            outbox_pending=int(outbox[0]["n"]) if outbox else 0,
            table_sizes=sizes,
        )
        if self.remote is not None:
            st.remote_configured = True
            remote_health = self.remote.health()
            st.remote_ok = remote_health.ok
            st.remote_detail = remote_health.detail
        return st

    # ------------------------------------------------------------------
    # Retention / cleanup / recovery
    # ------------------------------------------------------------------

    def enforce_retention(self, *, vacuum: bool = False) -> dict[str, int]:
        """Delete rows older than the configured retention windows.

        Returns deleted-row counts per table. This is the "safe cleanup"
        half of durable storage: bounded growth, checkpointed WAL, and
        no unbounded evidence hoarding.
        """
        now = time.time()
        deleted: dict[str, int] = {}
        windows = {
            "cost_records": ("timestamp", self.retention.get("cost_records_days", 180)),
            "llm_cache": ("ts", self.retention.get("llm_cache_days", 30)),
            "state_events": ("ts", self.retention.get("state_events_days", 90)),
            "evidence_memory": ("ts", self.retention.get("evidence_days", 365)),
        }
        for table, (col, days) in windows.items():
            cutoff = now - days * 86_400
            deleted[table] = max(0, self.local.execute(
                f"DELETE FROM {table} WHERE {col} < ?", (cutoff,)))  # noqa: S608
        # Orphan outbox rows for tables that no longer exist remotely are
        # handled by sync()'s age drop; here we only clear succeeded ones.
        if vacuum and isinstance(self.local, SqliteBackend):
            self.local.checkpoint()
            self.local.vacuum()
        return deleted

    def recover(self) -> dict[str, Any]:
        """Post-crash recovery pass: checkpoint WAL, sync outbox.

        Call at startup (CLI/bot) after an unclean shutdown.
        """
        result: dict[str, Any] = {}
        if isinstance(self.local, SqliteBackend):
            result["checkpointed_pages"] = self.local.checkpoint()
        result.update(self.sync())
        return result

    def backup(self, dest_dir: Path) -> Path:
        """Consistent local backup (uses sqlite3 backup API, WAL-safe)."""
        import sqlite3
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / f"web3guard-backup-{time.strftime('%Y%m%d-%H%M%S')}.db"
        if not isinstance(self.local, SqliteBackend) or str(self.local.path) == ":memory:":
            raise StorageError("backup requires a file-backed SQLite backend")
        src = sqlite3.connect(str(self.local.path))
        try:
            dst = sqlite3.connect(str(dest))
            try:
                src.backup(dst)
            finally:
                dst.close()
        finally:
            src.close()
        return dest

    def write_cost_record(
        self, *, timestamp: float, provider: str, model: str,
        prompt_tokens: int, completion_tokens: int, cost_usd: float,
        role: str = "analysis", scan_id: str = "",
    ) -> None:
        """Record cost in local durable ledger and remote replica."""
        self.write("cost_records", "id", {
            "id": int(time.time_ns()),
            "timestamp": timestamp,
            "provider": provider,
            "model": model,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "cost_usd": cost_usd,
            "role": role,
            "scan_id": scan_id,
        })

    def write_scan_run(
        self, *, started_at: str, finished_at: str, targets: int,
        findings: int, confirmed: int, cost_usd: float,
        status: str = "ok", metadata: dict[str, Any] | None = None,
    ) -> None:
        """Record scan history in local durable ledger and remote replica."""
        self.write("scan_runs", "id", {
            "id": int(time.time_ns()),
            "started_at": started_at,
            "finished_at": finished_at,
            "targets": targets,
            "findings": findings,
            "confirmed": confirmed,
            "cost_usd": cost_usd,
            "status": status,
            "metadata": metadata or {},
        })

    def record_state_event(
        self, *, kind: str, key: str = "",
        payload: dict[str, Any] | None = None,
    ) -> None:
        """Append a namespaced state event through the durable write router."""
        self.write("state_events", "id", {
            "id": int(time.time_ns()),
            "ts": time.time(),
            "kind": kind,
            "key": key,
            "payload": payload or {},
        })

    def record_finding(self, record: Any) -> None:
        """Mirror a :class:`~web3guard.findings_db.FindingRecord` durably.

        The findings DB remains the lifecycle store; this replica is what
        replicates to Supabase/Postgres and feeds cross-run evidence.
        """
        meta = record.metadata if isinstance(record.metadata, dict) else {}
        self.write("findings", "fingerprint", {
            "fingerprint": record.fingerprint,
            "target": record.target,
            "language": getattr(record, "language", ""),
            "file": getattr(record, "file", ""),
            "function": getattr(record, "function", ""),
            "category": getattr(record, "category", ""),
            "severity": getattr(record, "severity", "LOW"),
            "confidence": float(getattr(record, "confidence", 0.5) or 0.0),
            "swc_id": getattr(record, "swc_id", ""),
            "description": getattr(record, "description", ""),
            "status": record.status,
            "submission_program": getattr(record, "submission_program", ""),
            "submission_id": getattr(record, "submission_id", ""),
            "paid_amount_usd": float(getattr(record, "paid_amount_usd", 0.0) or 0.0),
            "rejection_reason": getattr(record, "rejection_reason", ""),
            "poc_code": (getattr(record, "poc_code", "") or "")[:20_000],
            "exploit_log": (getattr(record, "exploit_log", "") or "")[:20_000],
            "first_seen_ts": float(getattr(record, "first_seen_ts", 0.0) or 0.0),
            "last_seen_ts": float(getattr(record, "last_seen_ts", 0.0) or 0.0),
            "metadata": meta,
        })

    def describe(self) -> dict[str, Any]:
        """Redacted description for reports/logs (no DSNs, ever)."""
        return {
            "local": {"kind": self.local.kind, "path": str(getattr(self.local, "path", ""))},
            "remote": {"configured": self.remote is not None,
                       "kind": self.remote.kind if self.remote else None},
            "retention_days": dict(self.retention),
        }

"""SQLite backend — the always-available local backend.

Hardening over raw ``sqlite3.connect`` usage elsewhere in the codebase:

- WAL journal mode so concurrent readers (dashboard, serve, Telegram
  bot) never block the scanner's writer.
- ``busy_timeout`` so parallel batch chunks retry instead of erroring
  with "database is locked".
- Checkpoint support for the retention/recovery pass.
- A process-wide per-path lock map: parallel :class:`Scanner` instances
  (CLI ``--parallel``) each build their own backend, and SQLite
  connections are per-thread, so writes serialize through this lock.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any, Iterator

from web3guard.storage.base import BackendInfo, StorageBackend

LOGGER = logging.getLogger("web3guard.storage.sqlite")

# One lock per DB file path, shared process-wide.
_PATH_LOCKS: dict[str, threading.RLock] = {}
_LOCKS_GUARD = threading.Lock()


def _lock_for(path: str) -> threading.RLock:
    with _LOCKS_GUARD:
        if path not in _PATH_LOCKS:
            _PATH_LOCKS[path] = threading.RLock()
        return _PATH_LOCKS[path]


class SqliteBackend(StorageBackend):
    """Durable local backend. Path ``:memory:`` is reserved for tests."""

    kind = "sqlite"

    def __init__(self, path: Path | str) -> None:
        if str(path) == ":memory:":
            self.path = Path(":memory:")
        else:
            self.path = Path(path)
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = _lock_for(str(self.path))

    # -- connection ---------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        if str(self.path) == ":memory:":
            conn = sqlite3.connect(":memory:", check_same_thread=False)
        else:
            conn = sqlite3.connect(str(self.path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        if str(self.path) != ":memory:":
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=10000")
            conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            with closing(self._connect()) as conn:
                yield conn

    # -- StorageBackend API --------------------------------------------------

    def execute(self, sql: str, params: tuple | list = ()) -> int:
        with self._conn() as conn:
            cur = conn.execute(sql, params)
            conn.commit()
            return cur.rowcount

    def query_all(self, sql: str, params: tuple | list = ()) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def transaction(self, statements: list[tuple[str, tuple | list]]) -> list[int]:
        with self._conn() as conn:
            counts: list[int] = []
            try:
                for sql, params in statements:
                    counts.append(conn.execute(sql, params).rowcount)
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            return counts

    # -- sqlite extras -------------------------------------------------------

    def checkpoint(self) -> int:
        """WAL checkpoint (TRUNCATE); returns the number of checkpointed pages."""
        if str(self.path) == ":memory:":
            return 0
        with self._conn() as conn:
            try:
                row = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                return int(row[0]) if row else 0
            except sqlite3.Error as e:
                LOGGER.debug("checkpoint failed: %s", e)
                return 0

    def vacuum(self) -> None:
        if str(self.path) != ":memory:":
            with self._conn() as conn:
                conn.execute("VACUUM")

    def file_size_bytes(self) -> int:
        if str(self.path) == ":memory:":
            return 0
        try:
            return self.path.stat().st_size
        except OSError:
            return 0

    def health(self) -> BackendInfo:
        info = super().health()
        if info.ok and str(self.path) != ":memory:":
            info.detail = f"file={self.path} size={self.file_size_bytes()}"
        elif info.ok:
            info.detail = "in-memory"
        return info

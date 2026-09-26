"""Supabase / Postgres backend (optional remote durable storage).

Selected automatically when ``SUPABASE_DB_URL`` or ``POSTGRES_DSN`` is
set. Uses ``psycopg`` (psycopg3, install ``psycopg[binary]``) when
available; anything else raises :class:`UnavailableBackendError` at
construction so the caller can degrade to local-only instead of
crashing mid-scan.

Failure posture (matches the project's degrade-gracefully policy):

- Construction failure (driver missing, bad DSN, unreachable host) is
  reported, never fatal: :class:`DurableStore` keeps local SQLite as
  the source of truth and queues remote writes in the outbox.
- Supabase poolers (port 6543, transaction mode) work as-is; the
  backend appends the standard Supabase TLS requirement when the host
  is ``*.supabase.co`` and no sslmode is present in the DSN.

SQL translation: the storage layer writes SQLite-style ``?``
placeholders; Postgres uses ``%(p0)s``-style or ``%s`` — ``%s`` with
positional params is the simplest correct translation and is what
psycopg expects for tuples.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from web3guard.storage.base import (
    BackendInfo,
    StorageBackend,
    UnavailableBackendError,
)

LOGGER = logging.getLogger("web3guard.storage.postgres")

_DSN_PASSWORD_RE = re.compile(r"(?:://[^:/@]+:)[^@]+@")


def redact_dsn(dsn: str) -> str:
    """Redact the password in a Postgres DSN for safe logging."""
    return _DSN_PASSWORD_RE.sub("://<user>:<redacted>@", dsn)


class PostgresBackend(StorageBackend):
    """Remote durable backend backed by Supabase Postgres (or any PG)."""

    kind = "postgres"

    def __init__(self, dsn: str) -> None:
        self.dsn = dsn.strip()
        self._redacted = redact_dsn(self.dsn)
        try:
            import psycopg  # noqa: F401
        except ImportError as e:
            raise UnavailableBackendError(
                "Postgres backend selected (SUPABASE_DB_URL/POSTGRES_DSN set) "
                "but the psycopg driver is not installed. Install with "
                "`pip install 'psycopg[binary]'` or unset the DSN to run "
                "local-only."
            ) from e
        self._dsn = self._with_ssl(self.dsn)

    @staticmethod
    def _with_ssl(dsn: str) -> str:
        """Supabase requires TLS; add sslmode=require when absent."""
        if "supabase.co" not in dsn and "supabase.com" not in dsn:
            return dsn
        if "sslmode=" in dsn:
            return dsn
        sep = "&" if "?" in dsn else "?"
        return f"{dsn}{sep}sslmode=require"

    def _connect(self) -> Any:
        import psycopg
        return psycopg.connect(self._dsn, autocommit=True)

    def execute(self, sql: str, params: tuple | list = ()) -> int:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(self.normalize_sql(sql), tuple(params))
                return cur.rowcount if cur.rowcount is not None else 0

    def query_all(self, sql: str, params: tuple | list = ()) -> list[dict[str, Any]]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(self.normalize_sql(sql), tuple(params))
                if cur.description is None:
                    return []
                cols = [d.name for d in cur.description]
                return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]

    def transaction(self, statements: list[tuple[str, tuple | list]]) -> list[int]:
        import psycopg
        counts: list[int] = []
        with self._connect() as conn:
            try:
                with conn.transaction():
                    with conn.cursor() as cur:
                        for sql, params in statements:
                            cur.execute(self.normalize_sql(sql), tuple(params))
                            counts.append(cur.rowcount if cur.rowcount is not None else 0)
            except psycopg.Error:
                raise
            return counts

    def normalize_sql(self, sql: str) -> str:
        # SQLite '?' -> psycopg '%s'. '?' never appears legally in our
        # generated SQL outside placeholders.
        return sql.replace("?", "%s")

    def health(self) -> BackendInfo:
        try:
            row = self.query_all("SELECT 1 AS ok")
            return BackendInfo(kind=self.kind, ok=bool(row),
                               detail=self._redacted)
        except Exception as e:  # noqa: BLE001
            return BackendInfo(kind=self.kind, ok=False,
                               detail=f"{type(e).__name__}: {e}"[:300])

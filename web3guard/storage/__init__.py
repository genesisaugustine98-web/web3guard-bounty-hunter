"""Durable storage for Web3Guard.

v3.5: findings, costs, LLM cache, and run state no longer live only in
process-local SQLite files. The storage layer is the single integration
point:

- :class:`DurableStore` — the facade the rest of the codebase talks to.
- :class:`SqliteBackend` — the local backend (zero-dependency default).
- :class:`PostgresBackend` — remote Supabase/Postgres (optional).

Design rules:

- **Local always works.** SQLite is the source of truth until a row is
  confirmed replicated; a Supabase outage degrades to local-only with a
  warning, never a crashed scan.
- **Backend interface is intentionally narrow.** ``execute`` /
  ``query_all`` / ``transaction`` are all a backend must implement;
  higher-level tables are plain SQL so no ORM is needed.
- **Credentials come from the environment.** ``SUPABASE_DB_URL`` (or
  ``POSTGRES_DSN``) is read at construction; it is never logged and is
  redacted from reports (see :meth:`DurableStore.describe`).
"""

from __future__ import annotations

from web3guard.storage.base import (
    BackendInfo,
    StorageBackend,
    StorageError,
    UnavailableBackendError,
)
from web3guard.storage.durable import DurableStore
from web3guard.storage.sqlite_backend import SqliteBackend

__all__ = [
    "BackendInfo",
    "DurableStore",
    "SqliteBackend",
    "StorageBackend",
    "StorageError",
    "UnavailableBackendError",
]


def make_backend_from_env() -> SqliteBackend | Any:  # noqa: ANN401
    """Build the remote backend when remote env vars are present.

    Returns a :class:`SqliteBackend` marker when no remote backend is
    configured (the caller passes that straight to :class:`DurableStore`
    as the local backend either way). Remote selection:

    - ``SUPABASE_DB_URL`` or ``POSTGRES_DSN`` -> PostgresBackend.
    - Neither set -> local-only mode.
    """
    import os

    from web3guard.storage.postgres_backend import PostgresBackend

    dsn = (
        os.environ.get("SUPABASE_DB_URL")
        or os.environ.get("POSTGRES_DSN")
        or ""
    ).strip()
    if dsn:
        return PostgresBackend(dsn)
    return SqliteBackend(":memory:")  # sentinel; never used as local

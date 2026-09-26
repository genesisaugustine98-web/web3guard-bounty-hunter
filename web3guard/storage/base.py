"""Storage backend interface — deliberately narrow.

A backend must be able to execute DDL/DML, run queries, and optionally
group statements into a transaction. Everything else (schemas, sync
logic, retention) is implemented once at the :class:`DurableStore` level
so SQLite and Postgres stay behaviorally identical.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

LOGGER = logging.getLogger("web3guard.storage")


class StorageError(RuntimeError):
    """Base class for storage-layer failures."""


class UnavailableBackendError(StorageError):
    """The remote backend could not be reached or authenticated."""


@dataclass
class BackendInfo:
    """Diagnostic info about a backend (never includes credentials)."""
    kind: str                      # "sqlite" | "postgres"
    ok: bool
    detail: str = ""
    tables: tuple[str, ...] = field(default_factory=tuple)


class StorageBackend(ABC):
    """Minimal contract for a durable storage backend."""

    #: Short backend kind tag used in health/diagnostic output.
    kind: str = "abstract"

    @abstractmethod
    def execute(self, sql: str, params: tuple | list = ()) -> int:
        """Run a DDL/DML statement; return the affected row count."""

    @abstractmethod
    def query_all(self, sql: str, params: tuple | list = ()) -> list[dict[str, Any]]:
        """Run a SELECT and return rows as dicts."""

    def transaction(self, statements: list[tuple[str, tuple | list]]) -> list[int]:
        """Run statements atomically. Default: sequential non-atomic."""
        return [self.execute(sql, params) for sql, params in statements]

    def health(self) -> BackendInfo:
        """Cheap liveness probe; must never raise."""
        try:
            self.query_all("SELECT 1 AS ok")
            return BackendInfo(kind=self.kind, ok=True)
        except Exception as e:  # noqa: BLE001
            return BackendInfo(kind=self.kind, ok=False, detail=str(e)[:300])

    def close(self) -> None:  # noqa: B027  # optional hook; backends may rely on the no-op
        """Release connections. Default: nothing to release."""

    # ---- dialect helpers -------------------------------------------------
    # SQLite and Postgres differ in placeholder styles and DDL details.
    # Backends normalize SQL through these hooks; DurableStore writes
    # SQLite-style '?' placeholders and lets backends translate.

    def normalize_sql(self, sql: str) -> str:
        """Translate SQLite-style placeholders to the backend dialect."""
        return sql

    @staticmethod
    def placeholder(count: int, start: int = 1) -> str:
        """Comma-separated placeholders for an IN clause."""
        return ", ".join("?" for _ in range(count))

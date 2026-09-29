"""Central storage routing policy for Web3Guard.

The scanner has several persistence workloads with different lifetimes and
concurrency profiles.  This module gives each workload an explicit local path
and prevents accidental database overlap.

Routing contract:
- findings: FindingsDB (hot operational lifecycle)
- cost: CostTracker/BudgetController (durable spend ledger)
- cache: AIClient response cache (rebuildable)
- durable: DurableStore state/evidence/outbox (cross-process durable state)
- reports: filesystem artifacts; optional remote archive is outside the hot path

Remote Postgres/Supabase is replication only.  It is never the scanner's
write-time source of truth, so a remote outage cannot make a local scan fail.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from web3guard.storage.base import StorageError

_DEFAULT_PATHS = {
    "findings_db_path": ".web3guard/findings.db",
    "cost_db_path": ".web3guard/cost.db",
    "cache_path": ".web3guard/llm_cache.db",
    "durable_db_path": ".web3guard/durable.db",
    "reports_dir": "reports",
}


def _path(workdir: Path, value: str) -> Path:
    p = Path(value)
    return p if p.is_absolute() else workdir / p


@dataclass(frozen=True)
class StorageRouter:
    """Resolved storage ownership for one scanner work directory."""

    workdir: Path
    findings_db_path: Path
    cost_db_path: Path
    cache_path: Path
    durable_db_path: Path
    reports_dir: Path
    remote_mode: str
    remote_dsn_env: str | None
    remote_configured: bool
    remote_required: bool

    @classmethod
    def from_config(cls, workdir: Path, config: dict[str, Any]) -> StorageRouter:
        st = config.get("storage")
        storage = st if isinstance(st, dict) else {}

        paths = dict(_DEFAULT_PATHS)
        configured_paths = storage.get("paths")
        if isinstance(configured_paths, dict):
            for key in paths:
                value = configured_paths.get(key)
                if isinstance(value, str) and value.strip():
                    paths[key] = value.strip()

        # Keep the established top-level keys authoritative for backwards
        # compatibility; the new storage.paths block is the single routing
        # namespace for all other workloads.
        for key in ("findings_db_path", "cost_db_path", "cache_path"):
            value = config.get(key)
            if isinstance(value, str) and value.strip():
                paths[key] = value.strip()

        resolved = {
            key: _path(workdir, value)
            for key, value in paths.items()
        }

        # A database file may not be shared by two independent persistence
        # owners.  That was previously possible because DurableStore
        # defaulted to findings.db.
        db_owners = {
            str(resolved["findings_db_path"].resolve()): "findings",
            str(resolved["cost_db_path"].resolve()): "cost",
            str(resolved["cache_path"].resolve()): "cache",
            str(resolved["durable_db_path"].resolve()): "durable",
        }
        collisions: dict[str, set[str]] = {}
        for path, owner in db_owners.items():
            collisions.setdefault(path, set()).add(owner)
        duplicates = {path: owners for path, owners in collisions.items() if len(owners) > 1}
        if duplicates:
            details = "; ".join(
                f"{', '.join(sorted(owners))} -> {path}"
                for path, owners in sorted(duplicates.items())
            )
            raise StorageError(
                "storage routing collision: independent stores share one SQLite "
                f"file; configure distinct paths. {details}"
            )

        mode = str(storage.get("remote", "auto")).lower().strip()
        if mode not in {"auto", "off", "required"}:
            raise StorageError(
                "storage.remote must be one of: auto, off, required"
            )

        dsn_env = None
        if os.environ.get("SUPABASE_DB_URL", "").strip():
            dsn_env = "SUPABASE_DB_URL"
        elif os.environ.get("POSTGRES_DSN", "").strip():
            dsn_env = "POSTGRES_DSN"

        remote_configured = dsn_env is not None
        remote_required = mode == "required"
        if remote_required and not remote_configured:
            raise StorageError(
                "storage.remote=required but SUPABASE_DB_URL/POSTGRES_DSN is not set"
            )

        return cls(
            workdir=workdir,
            findings_db_path=resolved["findings_db_path"],
            cost_db_path=resolved["cost_db_path"],
            cache_path=resolved["cache_path"],
            durable_db_path=resolved["durable_db_path"],
            reports_dir=resolved["reports_dir"],
            remote_mode=mode,
            remote_dsn_env=dsn_env,
            remote_configured=remote_configured,
            remote_required=remote_required,
        )

    def describe(self) -> dict[str, Any]:
        """Return non-secret routing diagnostics safe for logs/reports."""
        return {
            "workdir": str(self.workdir),
            "paths": {
                "findings": str(self.findings_db_path),
                "cost": str(self.cost_db_path),
                "cache": str(self.cache_path),
                "durable": str(self.durable_db_path),
                "reports": str(self.reports_dir),
            },
            "remote": {
                "mode": self.remote_mode,
                "configured": self.remote_configured,
                "dsn_env": self.remote_dsn_env,
            },
        }

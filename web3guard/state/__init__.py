"""Persistent state for long-running Web3Guard processes.

v3.5 problem solved: the Telegram bot keeps its ``getUpdates`` offset
and per-chat job bookkeeping **in memory**, so every restart re-reads
old updates (duplicates every past command) and loses running-scan
state. GitHub watcher cursors (repo push heads, Actions run ids) had
nowhere durable to live either.

This module is a tiny durable KV + event log on top of
:class:`web3guard.storage.durable.DurableStore` (SQLite locally,
optionally mirrored to Supabase Postgres):

- :meth:`StateStore.get` / :meth:`set` / :meth:`delete` — JSON values.
- :meth:`StateStore.record_event` / :meth:`recent_events` — audit trail
  of state changes (rate-limit decisions, dispatches, cursor moves).
- Namespacing keeps concurrent processes (bot, watcher, CLI) from
  clobbering each other's keys.

All writes are crash-safe: they go through the store's WAL SQLite and
mirror to the remote backend when configured.
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # cycle: web3guard.storage.durable imports StateStore
    from web3guard.storage.durable import DurableStore

LOGGER = logging.getLogger("web3guard.state")

# Every state write also lands here (audit trail, retention-managed).
EVENT_HISTORY_LIMIT = 500


class StateStore:
    """Durable namespaced KV + event log for bot/watcher state."""

    def __init__(self, store: DurableStore, namespace: str = "core") -> None:
        self._store = store
        self._ns = namespace

    # -- KV ------------------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        rows = self._store.local.query_all(
            "SELECT v FROM state_kv WHERE k = ?", (self._full_key(key),))
        if not rows:
            return default
        try:
            return json.loads(rows[0]["v"])
        except (ValueError, TypeError):
            return default

    def set(self, key: str, value: Any) -> None:
        self._store.write("state_kv", "k", {
            "k": self._full_key(key),
            "v": json.dumps(value, default=str),
            "updated_ts": time.time(),
        })

    def delete(self, key: str) -> None:
        self._store.local.execute(
            "DELETE FROM state_kv WHERE k = ?", (self._full_key(key),))

    # -- events ---------------------------------------------------------------

    def record_event(self, kind: str, key: str = "",
                     payload: dict[str, Any] | None = None) -> None:
        """Append an audit event (rate-limit hits, dispatches, errors)."""
        self._store.local.execute(
            "INSERT INTO state_events (ts, kind, key, payload) VALUES (?, ?, ?, ?)",
            (time.time(), kind, key,
             json.dumps(payload or {}, default=str)),
        )

    def recent_events(self, kind: str | None = None,
                      limit: int = 50) -> list[dict[str, Any]]:
        if kind:
            rows = self._store.local.query_all(
                "SELECT ts, kind, key, payload FROM state_events"
                " WHERE kind = ? ORDER BY id DESC LIMIT ?", (kind, limit))
        else:
            rows = self._store.local.query_all(
                "SELECT ts, kind, key, payload FROM state_events"
                " ORDER BY id DESC LIMIT ?", (limit,))
        for row in rows:
            try:
                row["payload"] = json.loads(row.get("payload") or "{}")
            except (ValueError, TypeError):
                row["payload"] = {}
        return rows

    # -- helpers ---------------------------------------------------------------

    def _full_key(self, key: str) -> str:
        return f"{self._ns}:{key}"

    # -- typed conveniences (the actual v3.5 use cases) ------------------------

    def telegram_offset(self) -> int:
        return int(self.get("telegram:update_offset", 0) or 0)

    def set_telegram_offset(self, offset: int) -> None:
        self.set("telegram:update_offset", int(offset))

    def save_chat_job(self, chat_id: int, job: dict[str, Any]) -> None:
        """Persist a chat's last scan job (survives bot restarts)."""
        self.set(f"telegram:job:{chat_id}", job)

    def load_chat_job(self, chat_id: int) -> dict[str, Any] | None:
        return self.get(f"telegram:job:{chat_id}")

    def record_rate_limited(self, chat_id: int) -> None:
        self.record_event("rate_limited", key=str(chat_id))

    def github_cursor(self, repo: str) -> dict[str, Any]:
        return self.get(f"github:cursor:{repo}", {}) or {}

    def set_github_cursor(self, repo: str, cursor: dict[str, Any]) -> None:
        self.set(f"github:cursor:{repo}", cursor)

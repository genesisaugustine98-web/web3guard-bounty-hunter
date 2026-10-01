"""Shared persistent-state helper for the phase-5 targeting modules.

The deployer watcher, upgrade watcher, and sweep runner all need the
same thing: a small durable KV store for cursors ("last seen block",
"last seen tag", per-target progress) that survives restarts. This
module builds one on the project's standard stack — a
:class:`web3guard.state.StateStore` over a local-only
:class:`web3guard.storage.durable.DurableStore` (SQLite, no remote
replication). It never touches the network.
"""

from __future__ import annotations

import logging
from pathlib import Path

from web3guard.state import StateStore
from web3guard.storage.durable import DurableStore
from web3guard.storage.sqlite_backend import SqliteBackend

LOGGER = logging.getLogger("web3guard.discovery.targeting_state")

# Relative to the user's workdir (same ".web3guard" home the recon
# module uses for its audit trail).
STATE_DB_REL = Path(".web3guard") / "targeting.db"


def open_targeting_state(
    workdir: Path, namespace: str = "targeting"
) -> StateStore:
    """Open the durable KV store the targeting modules share.

    ``workdir`` is the user's working directory; state lives at
    ``<workdir>/.web3guard/targeting.db``. The store is local-only —
    no remote backend is configured, so nothing leaves the machine.
    """
    db_path = workdir / STATE_DB_REL
    db_path.parent.mkdir(parents=True, exist_ok=True)
    store = DurableStore(local=SqliteBackend(db_path), remote=None)
    return StateStore(store, namespace=namespace)

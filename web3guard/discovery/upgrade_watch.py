"""New-version / upgrade detection.

Two independent signals that a watched project shipped new code:

1. **Git tags/releases** — :class:`GitTagWatcher` shells out to the
   local ``git`` CLI on an already-cloned repo. No network is needed
   (and none is used); it only reads tags the user has fetched.
2. **On-chain proxy upgrades** — :class:`ProxyUpgradeWatcher` watches
   the ``Upgraded(address)`` event (emitted by both UUPS and
   TransparentProxy proxies) through the opt-in
   :class:`~web3guard.discovery.deployer_watch.ChainClient`.

A detected upgrade becomes an :class:`UpgradeTrigger`, pushed onto a
persistent :class:`TriggerQueue` that the scanner loop (phase 7)
consumes as "scan-on-upgrade" work items.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from web3guard.discovery.base import safe_run_subprocess
from web3guard.discovery.deployer_watch import (
    ChainClient,
    DeployerWatchConfig,
    NoopChainClient,
)
from web3guard.discovery.targeting_state import open_targeting_state
from web3guard.state import StateStore

LOGGER = logging.getLogger("web3guard.discovery.upgrade_watch")

# keccak256("Upgraded(address)") — emitted by UUPS (ERC-1822) and
# TransparentUpgradeableProxy implementations on every upgrade.
UPGRADED_EVENT_TOPIC = (
    "0xbc7cd75a20ee27fd9adebab32041f755214d8526f10b3346175b4e63df70571f"
)

DEFAULT_POLL_INTERVAL_SECONDS = 600


# ---------------------------------------------------------------------------
# Trigger + queue
# ---------------------------------------------------------------------------

@dataclass
class UpgradeTrigger:
    """A "scan-on-upgrade" work item for the scanner loop.

    Phase 7 wires the consumption loop; this module only defines the
    shape and the persistent queue.
    """
    kind: str                    # "git_tag" | "proxy_upgrade"
    project: str
    repo_path: str = ""          # local clone, for git_tag
    proxy_address: str = ""      # for proxy_upgrade
    old_version: str = ""
    new_version: str = ""
    old_implementation: str = ""
    new_implementation: str = ""
    block_number: int = 0
    tx_hash: str = ""
    detected_ts: float = field(default_factory=time.time)
    payload: dict[str, Any] = field(default_factory=dict)

    @property
    def trigger_id(self) -> str:
        h = hashlib.sha256()
        for part in (self.kind, self.project, self.new_version,
                     self.new_implementation, self.tx_hash):
            h.update(str(part).encode())
        return h.hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "trigger_id": self.trigger_id,
            "kind": self.kind,
            "project": self.project,
            "repo_path": self.repo_path,
            "proxy_address": self.proxy_address,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "old_implementation": self.old_implementation,
            "new_implementation": self.new_implementation,
            "block_number": self.block_number,
            "tx_hash": self.tx_hash,
            "detected_ts": self.detected_ts,
            "payload": self.payload,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UpgradeTrigger:
        data = dict(data)
        data.pop("trigger_id", None)  # derived, not stored
        known = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in known})


class TriggerQueue:
    """Persistent FIFO queue of :class:`UpgradeTrigger`.

    Backed by the project's standard StateStore, so triggers survive
    restarts and are never lost or double-delivered by a crash
    between poll and scan.
    """

    def __init__(self, state: StateStore, key: str = "upgrade_watch:queue") -> None:
        self._state = state
        self._key = key

    def push(self, trigger: UpgradeTrigger) -> None:
        items = self._load()
        if any(t.get("trigger_id") == trigger.trigger_id for t in items):
            return  # already queued — never double-enqueue
        items.append(trigger.to_dict())
        self._save(items)
        self._state.record_event(
            "upgrade_trigger_queued", key=trigger.project,
            payload={"trigger_id": trigger.trigger_id, "kind": trigger.kind},
        )

    def pop(self) -> UpgradeTrigger | None:
        items = self._load()
        if not items:
            return None
        first, rest = items[0], items[1:]
        self._save(rest)
        return UpgradeTrigger.from_dict(first)

    def peek_all(self) -> list[UpgradeTrigger]:
        return [UpgradeTrigger.from_dict(d) for d in self._load()]

    def __len__(self) -> int:
        return len(self._load())

    def _load(self) -> list[dict[str, Any]]:
        return list(self._state.get(self._key, []) or [])

    def _save(self, items: list[dict[str, Any]]) -> None:
        self._state.set(self._key, items)


# ---------------------------------------------------------------------------
# Git tag watcher (local git CLI, no network)
# ---------------------------------------------------------------------------

def _git_tags(repo: Path) -> list[str]:
    """Tags in creation order, oldest first. Empty list on any failure."""
    rc, out, err = safe_run_subprocess(
        ["git", "for-each-ref", "--sort=creatordate",
         "--format=%(refname:short)", "refs/tags"],
        cwd=repo, timeout=30,
    )
    if rc != 0:
        LOGGER.warning("git tag listing failed for %s: %s", repo, err.strip()[:200])
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


class GitTagWatcher:
    """Detect new git tags on a locally cloned repo.

    Uses only the local ``git`` CLI — it reads tags already present in
    the clone and never touches the network. (Fetch new tags yourself
    with ``git fetch --tags`` when you want fresh data.)
    """

    def __init__(self, repo_path: Path | str, project: str,
                 state: StateStore) -> None:
        self.repo_path = Path(repo_path)
        self.project = project
        self._state = state

    @property
    def _cursor_key(self) -> str:
        return f"upgrade_watch:git_cursor:{self.project}"

    def known_tags(self) -> list[str]:
        return _git_tags(self.repo_path)

    def poll_once(self) -> list[UpgradeTrigger]:
        """Return triggers for tags newer than the stored cursor."""
        tags = self.known_tags()
        cursor = self._state.get(self._cursor_key)
        if cursor is None:
            # First run: baseline at the newest tag so we don't
            # re-report the project's entire release history.
            if tags:
                self._state.set(self._cursor_key, tags[-1])
            return []
        if cursor not in tags:
            # History was rewritten / tags deleted: re-baseline.
            LOGGER.warning("git cursor tag %r gone from %s; re-baselining",
                           cursor, self.repo_path)
            if tags:
                self._state.set(self._cursor_key, tags[-1])
            return []
        new_tags = tags[tags.index(cursor) + 1:]
        triggers: list[UpgradeTrigger] = []
        for tag in new_tags:
            triggers.append(UpgradeTrigger(
                kind="git_tag",
                project=self.project,
                repo_path=str(self.repo_path),
                old_version=str(cursor),
                new_version=tag,
            ))
            cursor = tag
        if new_tags:
            self._state.set(self._cursor_key, cursor)
            self._state.record_event(
                "upgrade_watch_git_tags", key=self.project,
                payload={"new_tags": new_tags},
            )
        return triggers


# ---------------------------------------------------------------------------
# On-chain proxy upgrade watcher
# ---------------------------------------------------------------------------

def _topic_to_address(topic: str) -> str:
    """Decode an indexed address topic (left-padded 32 bytes) to 0x-address."""
    t = topic[2:] if topic.startswith("0x") else topic
    return "0x" + t[-40:]


class ProxyUpgradeWatcher:
    """Detect UUPS / TransparentProxy upgrades via the Upgraded event.

    Only runs against the opt-in
    :class:`~web3guard.discovery.deployer_watch.ChainClient`; with the
    default :class:`NoopChainClient` it simply reports nothing.
    """

    def __init__(self, proxy_address: str, project: str,
                 client: ChainClient, state: StateStore) -> None:
        self.proxy_address = proxy_address
        self.project = project
        self.client = client
        self._state = state

    @property
    def _block_key(self) -> str:
        return f"upgrade_watch:proxy_block:{self.proxy_address.lower()}"

    @property
    def _impl_key(self) -> str:
        return f"upgrade_watch:proxy_impl:{self.proxy_address.lower()}"

    def poll_once(self) -> list[UpgradeTrigger]:
        try:
            head = self.client.latest_block_number()
        except Exception as e:  # ChainClientError or transport failure
            LOGGER.warning("proxy watch: chain head unavailable: %s", e)
            return []
        last = self._state.get(self._block_key)
        if last is None:
            self._state.set(self._block_key, head)
            return []  # baseline: don't replay history on first run
        from_block = int(last) + 1
        if from_block > head:
            return []
        try:
            logs = self.client.get_logs(
                self.proxy_address, [UPGRADED_EVENT_TOPIC], from_block, head)
        except Exception as e:
            LOGGER.warning("proxy watch: get_logs failed: %s", e)
            return []
        triggers: list[UpgradeTrigger] = []
        known_impl = self._state.get(self._impl_key, "")
        for log in logs:
            if len(log.topics) < 2:
                continue
            new_impl = _topic_to_address(log.topics[1])
            if known_impl and new_impl.lower() != str(known_impl).lower():
                triggers.append(UpgradeTrigger(
                    kind="proxy_upgrade",
                    project=self.project,
                    proxy_address=self.proxy_address,
                    old_implementation=str(known_impl),
                    new_implementation=new_impl,
                    block_number=log.block_number,
                    tx_hash=log.tx_hash,
                ))
            known_impl = new_impl
        self._state.set(self._block_key, head)
        if known_impl:
            self._state.set(self._impl_key, known_impl)
        if triggers:
            self._state.record_event(
                "upgrade_watch_proxy", key=self.proxy_address,
                payload={"upgrades": len(triggers)},
            )
        return triggers


# ---------------------------------------------------------------------------
# Combined watcher + config
# ---------------------------------------------------------------------------

@dataclass
class WatchedProject:
    name: str
    repo_path: str = ""          # local clone dir; "" = no git watching
    proxies: list[str] = field(default_factory=list)


@dataclass
class UpgradeWatchConfig:
    projects: list[WatchedProject] = field(default_factory=list)
    poll_interval_seconds: int = DEFAULT_POLL_INTERVAL_SECONDS

    @classmethod
    def from_yaml(cls, path: Path) -> UpgradeWatchConfig:
        import yaml

        if not path.exists():
            LOGGER.info("no upgrade-watch config at %s; disabled", path)
            return cls()
        data = yaml.safe_load(path.read_text()) or {}
        projects = [
            WatchedProject(
                name=str(p.get("name", "")),
                repo_path=str(p.get("repo_path", "") or ""),
                proxies=[str(a) for a in (p.get("proxies") or [])],
            )
            for p in (data.get("projects") or [])
        ]
        return cls(
            projects=projects,
            poll_interval_seconds=int(
                data.get("poll_interval_seconds",
                         DEFAULT_POLL_INTERVAL_SECONDS)),
        )

    @classmethod
    def example_yaml(cls) -> str:
        return (
            "# Web3Guard upgrade-watch config (TEMPLATE — edit me).\n"
            "# repo_path must be a LOCAL clone; the watcher only runs the\n"
            "# local git CLI and never touches the network itself.\n"
            "projects:\n"
            "  # - name: \"example-protocol\"\n"
            "  #   repo_path: \"/path/to/local/clone\"\n"
            "  #   proxies:\n"
            "  #     - \"0xProxyAddressHere\"\n"
            "poll_interval_seconds: 600\n"
        )


class UpgradeWatcher:
    """Runs git-tag and proxy-upgrade watchers; pushes to a TriggerQueue."""

    def __init__(
        self,
        config: UpgradeWatchConfig,
        client: ChainClient | None = None,
        *,
        state: StateStore | None = None,
        workdir: Path = Path("."),
        queue: TriggerQueue | None = None,
    ) -> None:
        self.config = config
        self.client = client or NoopChainClient()
        self.state = state or open_targeting_state(workdir)
        self.queue = queue or TriggerQueue(self.state)

    def poll_once(self) -> list[UpgradeTrigger]:
        """One poll cycle across all projects; new triggers are queued."""
        found: list[UpgradeTrigger] = []
        for project in self.config.projects:
            if project.repo_path:
                git_watcher = GitTagWatcher(
                    project.repo_path, project.name, self.state)
                found.extend(git_watcher.poll_once())
            for proxy in project.proxies:
                proxy_watcher = ProxyUpgradeWatcher(
                    proxy, project.name, self.client, self.state)
                found.extend(proxy_watcher.poll_once())
        for trigger in found:
            self.queue.push(trigger)
        return found


# Re-exported for convenience: the deployer config loader is shared
# by callers that manage one config file for both watchers.
__all__ = [
    "UPGRADED_EVENT_TOPIC",
    "UpgradeTrigger",
    "TriggerQueue",
    "GitTagWatcher",
    "ProxyUpgradeWatcher",
    "WatchedProject",
    "UpgradeWatchConfig",
    "UpgradeWatcher",
    "DeployerWatchConfig",
]

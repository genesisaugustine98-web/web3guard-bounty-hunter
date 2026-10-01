"""Deployer watching — detect new contract deployments from watched addresses.

A "fresh-code targeting" primitive: the user lists deployer addresses
they care about (a protocol's deployer multisig, a factory owner, ...)
in a YAML config file, and :class:`DeployerWatcher` polls for new
contract-creation transactions from those addresses.

Chain access goes through the :class:`ChainClient` interface:

- :class:`NoopChainClient` — offline stub, the default. Does nothing,
  returns nothing, needs zero configuration.
- :class:`RpcChainClient` — JSON-RPC over HTTPS, strictly opt-in via
  the ``WEB3GUARD_RPC_URL`` environment variable. No hardcoded
  endpoints, no API keys in files.

Poll state ("last seen block" per deployer) is persisted through the
project's standard :class:`web3guard.state.StateStore` so restarts
don't re-report old deployments.
"""

from __future__ import annotations

import abc
import json
import logging
import os
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from web3guard.discovery.targeting_state import open_targeting_state
from web3guard.state import StateStore

LOGGER = logging.getLogger("web3guard.discovery.deployer_watch")

# Env var that opts in to live chain data. Unset => NoopChainClient.
RPC_URL_ENV = "WEB3GUARD_RPC_URL"

DEFAULT_POLL_INTERVAL_SECONDS = 300
DEFAULT_MAX_BLOCKS_PER_POLL = 2000
# Safety valve: never scan more than this many blocks in one poll,
# even if asked (a huge range against a public RPC is abusive).
HARD_MAX_BLOCKS_PER_POLL = 50_000


class ChainClientError(RuntimeError):
    """Raised when a chain client is misconfigured or unreachable."""


@dataclass
class LogRecord:
    """One EVM event log, normalized from eth_getLogs."""
    address: str
    topics: list[str]
    data: str
    block_number: int
    tx_hash: str


@dataclass
class ContractDeployment:
    """A new contract deployment attributed to a watched deployer."""
    deployer: str
    contract_address: str
    block_number: int
    tx_hash: str
    chain: str = ""
    detected_ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "deployer": self.deployer,
            "contract_address": self.contract_address,
            "block_number": self.block_number,
            "tx_hash": self.tx_hash,
            "chain": self.chain,
            "detected_ts": self.detected_ts,
        }


class ChainClient(abc.ABC):
    """Minimal chain-access interface used by the targeting modules.

    Implementations must be side-effect free apart from read-only RPC
    calls; they never sign or send transactions.
    """

    @abc.abstractmethod
    def chain_label(self) -> str:
        """Human label for this chain connection (e.g. "rpc:ethereum")."""

    @abc.abstractmethod
    def latest_block_number(self) -> int:
        """Current chain head, or 0 when unknown/offline."""

    @abc.abstractmethod
    def contract_creations(
        self, deployer: str, from_block: int, to_block: int
    ) -> list[ContractDeployment]:
        """Contract-creation txs sent by ``deployer`` in ``[from_block, to_block]``."""

    @abc.abstractmethod
    def get_logs(
        self, address: str, topics: list[str], from_block: int, to_block: int
    ) -> list[LogRecord]:
        """Event logs for ``address`` matching ``topics`` in the block range."""


class NoopChainClient(ChainClient):
    """Offline stub — the default chain client.

    Does nothing and returns nothing. The watchers still run (cursors
    advance, config is validated), which keeps every code path
    testable and the tool fully usable with zero configuration.
    """

    def chain_label(self) -> str:
        return "noop (offline stub)"

    def latest_block_number(self) -> int:
        return 0

    def contract_creations(
        self, deployer: str, from_block: int, to_block: int
    ) -> list[ContractDeployment]:
        return []

    def get_logs(
        self, address: str, topics: list[str], from_block: int, to_block: int
    ) -> list[LogRecord]:
        return []


class RpcChainClient(ChainClient):
    """Read-only JSON-RPC chain client — strictly opt-in.

    Enable by setting ``WEB3GUARD_RPC_URL`` to an HTTPS JSON-RPC
    endpoint (your own node, or a provider endpoint you control).
    The URL is never written to any file; pass it only via the
    environment.

    Contract creation is detected by scanning blocks for transactions
    with an empty ``to`` field sent by the deployer, then resolving the
    created address from the transaction receipt (works for plain
    CREATE and CREATE2 deployments alike).
    """

    def __init__(
        self,
        rpc_url: str | None = None,
        *,
        chain_label: str = "rpc",
        timeout: int = 15,
        max_blocks_per_poll: int = DEFAULT_MAX_BLOCKS_PER_POLL,
    ) -> None:
        url = (rpc_url or os.environ.get(RPC_URL_ENV, "")).strip()
        if not url:
            raise ChainClientError(
                f"RpcChainClient needs an RPC URL: set the {RPC_URL_ENV} "
                "environment variable (it is never stored in files)."
            )
        if not url.startswith(("https://", "http://")):
            raise ChainClientError(
                f"{RPC_URL_ENV} must be an http(s) JSON-RPC URL."
            )
        self._url = url
        self._label = chain_label
        self._timeout = timeout
        self._max_blocks = min(max_blocks_per_poll, HARD_MAX_BLOCKS_PER_POLL)

    @classmethod
    def from_env(cls, **kwargs: Any) -> RpcChainClient | None:
        """Build from the environment, or return None when not configured."""
        if not os.environ.get(RPC_URL_ENV, "").strip():
            return None
        return cls(**kwargs)

    # -- ChainClient ------------------------------------------------------

    def chain_label(self) -> str:
        return self._label

    def latest_block_number(self) -> int:
        return int(self._rpc("eth_blockNumber", []), 16)

    def contract_creations(
        self, deployer: str, from_block: int, to_block: int
    ) -> list[ContractDeployment]:
        deployer = deployer.lower()
        out: list[ContractDeployment] = []
        start = max(from_block, 0)
        while start <= to_block:
            end = min(start + self._max_blocks - 1, to_block)
            out.extend(self._scan_block_range(deployer, start, end))
            start = end + 1
        return out

    def get_logs(
        self, address: str, topics: list[str], from_block: int, to_block: int
    ) -> list[LogRecord]:
        if from_block > to_block:
            return []
        raw = self._rpc(
            "eth_getLogs",
            [{
                "address": address,
                "topics": topics,
                "fromBlock": hex(from_block),
                "toBlock": hex(to_block),
            }],
        ) or []
        records: list[LogRecord] = []
        for entry in raw:
            try:
                records.append(LogRecord(
                    address=str(entry.get("address", "")),
                    topics=[str(t) for t in entry.get("topics", [])],
                    data=str(entry.get("data", "")),
                    block_number=int(str(entry.get("blockNumber", "0x0")), 16),
                    tx_hash=str(entry.get("transactionHash", "")),
                ))
            except (ValueError, TypeError, AttributeError) as e:
                LOGGER.warning("skipping malformed log entry: %s", e)
        return records

    # -- internals ----------------------------------------------------------

    def _scan_block_range(
        self, deployer: str, from_block: int, to_block: int
    ) -> list[ContractDeployment]:
        out: list[ContractDeployment] = []
        for number in range(from_block, to_block + 1):
            block = self._rpc(
                "eth_getBlockByNumber", [hex(number), True]) or {}
            for tx in block.get("transactions") or []:
                if not isinstance(tx, dict):
                    continue
                if (tx.get("from") or "").lower() != deployer:
                    continue
                if tx.get("to"):  # contract creation has no `to`
                    continue
                tx_hash = str(tx.get("hash", ""))
                receipt = self._rpc(
                    "eth_getTransactionReceipt", [tx_hash]) or {}
                created = receipt.get("contractAddress") or ""
                if not created:
                    continue
                out.append(ContractDeployment(
                    deployer=deployer,
                    contract_address=str(created),
                    block_number=number,
                    tx_hash=tx_hash,
                    chain=self._label,
                ))
        return out

    def _rpc(self, method: str, params: list[Any]) -> Any:
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode()
        req = urllib.request.Request(
            self._url, data=body,
            headers={"Content-Type": "application/json",
                     "User-Agent": "web3guard-deployer-watch/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8", "replace"))
        except OSError as e:
            raise ChainClientError(f"RPC request failed ({method}): {e}") from e
        if payload.get("error"):
            raise ChainClientError(
                f"RPC error ({method}): {payload['error']}")
        return payload.get("result")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class WatchedDeployer:
    address: str
    label: str = ""
    chain: str = ""
    start_block: int = 0  # 0 = start from chain head on first poll

    def __post_init__(self) -> None:
        self.address = self.address.strip()
        if not self.address.startswith("0x") or len(self.address) != 42:
            raise ValueError(
                f"invalid deployer address {self.address!r}: "
                "expected 0x + 40 hex chars")


@dataclass
class DeployerWatchConfig:
    deployers: list[WatchedDeployer] = field(default_factory=list)
    poll_interval_seconds: int = DEFAULT_POLL_INTERVAL_SECONDS
    max_blocks_per_poll: int = DEFAULT_MAX_BLOCKS_PER_POLL

    @classmethod
    def from_yaml(cls, path: Path) -> DeployerWatchConfig:
        """Load from a YAML file. Missing file => empty (disabled) config."""
        import yaml

        if not path.exists():
            LOGGER.info("no deployer config at %s; watcher disabled", path)
            return cls()
        data = yaml.safe_load(path.read_text()) or {}
        deployers = [
            WatchedDeployer(
                address=str(d.get("address", "")),
                label=str(d.get("label", "")),
                chain=str(d.get("chain", "")),
                start_block=int(d.get("start_block", 0) or 0),
            )
            for d in (data.get("deployers") or [])
        ]
        return cls(
            deployers=deployers,
            poll_interval_seconds=int(
                data.get("poll_interval_seconds", DEFAULT_POLL_INTERVAL_SECONDS)),
            max_blocks_per_poll=int(
                data.get("max_blocks_per_poll", DEFAULT_MAX_BLOCKS_PER_POLL)),
        )

    @classmethod
    def example_yaml(cls) -> str:
        """Template config text — the user copies and edits this."""
        return (
            "# Web3Guard deployer-watch config (TEMPLATE — edit me).\n"
            "# List deployer addresses you are authorized to monitor.\n"
            "# Listing an address asserts you may assess its deployments.\n"
            "deployers:\n"
            "  # - address: \"0xYourDeployerAddressHere\"\n"
            "  #   label: \"Example protocol deployer\"\n"
            "  #   chain: \"ethereum\"\n"
            "  #   start_block: 0   # 0 = start from chain head on first run\n"
            "poll_interval_seconds: 300\n"
            "max_blocks_per_poll: 2000\n"
        )


# ---------------------------------------------------------------------------
# Watcher
# ---------------------------------------------------------------------------

def _cursor_key(address: str) -> str:
    return f"deployer_watch:last_block:{address.lower()}"


class DeployerWatcher:
    """Poll watched deployers for new contract deployments.

    ``poll_once()`` returns every new :class:`ContractDeployment`
    since the previous poll and advances the persisted cursor, so a
    restart never re-reports the same deployment.
    """

    def __init__(
        self,
        config: DeployerWatchConfig,
        client: ChainClient | None = None,
        *,
        state: StateStore | None = None,
        workdir: Path = Path("."),
    ) -> None:
        self.config = config
        self.client = client or NoopChainClient()
        self.state = state or open_targeting_state(workdir)
        self.workdir = workdir

    def poll_once(self) -> list[ContractDeployment]:
        """One poll cycle: detect new deployments, advance cursors."""
        found: list[ContractDeployment] = []
        try:
            head = self.client.latest_block_number()
        except ChainClientError as e:
            LOGGER.warning("deployer watch: chain head unavailable: %s", e)
            return []
        for deployer in self.config.deployers:
            key = _cursor_key(deployer.address)
            last = self.state.get(key)
            if last is None:
                # First run: baseline at the head (or the configured
                # start block) so we don't replay ancient history.
                baseline = deployer.start_block or head
                self.state.set(key, baseline)
                self.state.record_event(
                    "deployer_watch_baseline",
                    key=deployer.address,
                    payload={"block": baseline, "label": deployer.label},
                )
                continue
            from_block = int(last) + 1
            if from_block > head:
                continue
            try:
                new = self.client.contract_creations(
                    deployer.address, from_block, head)
            except ChainClientError as e:
                LOGGER.warning("deployer watch: poll failed for %s: %s",
                               deployer.address, e)
                continue
            self.state.set(key, head)
            for dep in new:
                dep.chain = dep.chain or deployer.chain
                self.state.record_event(
                    "deployer_watch_deployment",
                    key=deployer.address,
                    payload=dep.to_dict(),
                )
            found.extend(new)
        return found

    def run_forever(self, *, once: bool = False) -> list[ContractDeployment]:
        """Poll in a loop (``once=True`` for a single cycle, e.g. from cron)."""
        if once:
            return self.poll_once()
        while True:
            self.poll_once()
            time.sleep(max(1, self.config.poll_interval_seconds))
        return []  # pragma: no cover - unreachable

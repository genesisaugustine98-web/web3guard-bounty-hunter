"""Tests for the phase-5 targeting modules (fresh-code targeting + monitoring).

Everything here runs offline: a FakeChainClient returns canned blocks
and logs, git upgrade detection uses throwaway repos in tmp dirs, and
variant sweeping uses a tmp corpus. No network calls, no real keys.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from web3guard.discovery import (
    ChainClient,
    ChainClientError,
    ContractDeployment,
    DeployerWatchConfig,
    DeployerWatcher,
    FindingSignature,
    GitHubCodeSearch,
    GitTagWatcher,
    LogRecord,
    NoopChainClient,
    ProxyUpgradeWatcher,
    RpcChainClient,
    SweepConfig,
    SweepRunner,
    SweepTarget,
    TriggerQueue,
    UpgradeTrigger,
    UpgradeWatchConfig,
    UpgradeWatcher,
    VariantSweeper,
    WatchedDeployer,
    WatchedProject,
    open_targeting_state,
)
from web3guard.discovery.upgrade_watch import UPGRADED_EVENT_TOPIC

DEPLOYER = "0x" + "ab" * 20
PROXY = "0x" + "cd" * 20
OLD_IMPL = "0x" + "11" * 20
NEW_IMPL = "0x" + "22" * 20

GIT_AVAILABLE = shutil.which("git") is not None
needs_git = pytest.mark.skipif(not GIT_AVAILABLE, reason="git not installed")


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeChainClient(ChainClient):
    """Canned chain data: deployments + logs keyed by block range."""

    def __init__(self, head: int = 0,
                 deployments: list[ContractDeployment] | None = None,
                 logs: list[LogRecord] | None = None) -> None:
        self.head = head
        self._deployments = deployments or []
        self._logs = logs or []

    def chain_label(self) -> str:
        return "fake"

    def latest_block_number(self) -> int:
        return self.head

    def contract_creations(self, deployer: str, from_block: int,
                           to_block: int) -> list[ContractDeployment]:
        return [d for d in self._deployments
                if d.deployer.lower() == deployer.lower()
                and from_block <= d.block_number <= to_block]

    def get_logs(self, address: str, topics: list[str], from_block: int,
                 to_block: int) -> list[LogRecord]:
        return [log for log in self._logs
                if log.address.lower() == address.lower()
                and from_block <= log.block_number <= to_block
                and (not topics or log.topics[:len(topics)] == topics)]


def _impl_topic(impl: str) -> str:
    return "0x" + "00" * 12 + impl[2:].lower()


def _upgraded_log(block: int, impl: str, tx: str = "0x" + "ee" * 32) -> LogRecord:
    return LogRecord(address=PROXY, topics=[UPGRADED_EVENT_TOPIC, _impl_topic(impl)],
                     data="0x", block_number=block, tx_hash=tx)


def _git(args: list[str], cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True,
                   capture_output=True, text=True,
                   env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"})


@needs_git
def _make_repo(path: Path, tags: list[str]) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _git(["init"], path)
    _git(["config", "user.email", "test@example.com"], path)
    _git(["config", "user.name", "test"], path)
    (path / "README.md").write_text("hi\n")
    _git(["add", "."], path)
    for i, tag in enumerate(tags):
        (path / "README.md").write_text(f"hi {i}\n")
        _git(["add", "."], path)
        _git(["commit", "-m", f"commit {i}"], path)
        _git(["tag", tag], path)
    return path


# ---------------------------------------------------------------------------
# Chain clients
# ---------------------------------------------------------------------------

def test_noop_client_returns_nothing() -> None:
    client = NoopChainClient()
    assert client.latest_block_number() == 0
    assert client.contract_creations(DEPLOYER, 0, 100) == []
    assert client.get_logs(PROXY, [UPGRADED_EVENT_TOPIC], 0, 100) == []


def test_rpc_client_from_env_none_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEB3GUARD_RPC_URL", raising=False)
    assert RpcChainClient.from_env() is None


def test_rpc_client_rejects_missing_url() -> None:
    with pytest.raises(ChainClientError, match="WEB3GUARD_RPC_URL"):
        RpcChainClient(rpc_url="")


def test_rpc_client_rejects_non_http_url() -> None:
    with pytest.raises(ChainClientError, match="http"):
        RpcChainClient(rpc_url="wss://example.com")


def test_watched_deployer_rejects_bad_address() -> None:
    with pytest.raises(ValueError, match="invalid deployer address"):
        WatchedDeployer(address="not-an-address")


# ---------------------------------------------------------------------------
# Deployer watching
# ---------------------------------------------------------------------------

def test_deployer_watcher_detects_new_deployment(tmp_path: Path) -> None:
    dep = ContractDeployment(deployer=DEPLOYER, contract_address="0x" + "99" * 20,
                             block_number=102, tx_hash="0x" + "aa" * 32)
    client = FakeChainClient(head=105, deployments=[dep])
    state = open_targeting_state(tmp_path)
    state.set(f"deployer_watch:last_block:{DEPLOYER.lower()}", 100)
    watcher = DeployerWatcher(
        DeployerWatchConfig(deployers=[WatchedDeployer(address=DEPLOYER)]),
        client, state=state, workdir=tmp_path)
    found = watcher.poll_once()
    assert len(found) == 1
    assert found[0].contract_address == "0x" + "99" * 20
    assert found[0].block_number == 102
    # Second poll: cursor advanced, no duplicates.
    assert watcher.poll_once() == []
    assert state.get(f"deployer_watch:last_block:{DEPLOYER.lower()}") == 105


def test_deployer_watcher_first_run_baselines_without_replay(tmp_path: Path) -> None:
    dep = ContractDeployment(deployer=DEPLOYER, contract_address="0x" + "99" * 20,
                             block_number=50, tx_hash="0x" + "aa" * 32)
    client = FakeChainClient(head=105, deployments=[dep])
    watcher = DeployerWatcher(
        DeployerWatchConfig(deployers=[WatchedDeployer(address=DEPLOYER)]),
        client, state=open_targeting_state(tmp_path), workdir=tmp_path)
    # Ancient deployment must NOT be reported on first run.
    assert watcher.poll_once() == []


def test_deployer_watcher_baseline_block_still_scanned(tmp_path: Path) -> None:
    # A deployment landing in the baseline head block itself must not be
    # skipped forever (the cursor stores the last *scanned* block).
    dep = ContractDeployment(deployer=DEPLOYER, contract_address="0x" + "99" * 20,
                             block_number=105, tx_hash="0x" + "aa" * 32)
    client = FakeChainClient(head=105, deployments=[dep])
    watcher = DeployerWatcher(
        DeployerWatchConfig(deployers=[WatchedDeployer(address=DEPLOYER)]),
        client, state=open_targeting_state(tmp_path), workdir=tmp_path)
    assert watcher.poll_once() == []  # first run baselines
    found = watcher.poll_once()       # second run scans the baseline block
    assert len(found) == 1
    assert found[0].block_number == 105


def test_deployer_watcher_offline_by_default(tmp_path: Path) -> None:
    watcher = DeployerWatcher(
        DeployerWatchConfig(deployers=[WatchedDeployer(address=DEPLOYER)]),
        state=open_targeting_state(tmp_path), workdir=tmp_path)
    assert isinstance(watcher.client, NoopChainClient)
    assert watcher.poll_once() == []


def test_deployer_config_from_yaml(tmp_path: Path) -> None:
    cfg_file = tmp_path / "deployers.yaml"
    cfg_file.write_text(
        "deployers:\n"
        f"  - address: \"{DEPLOYER}\"\n"
        "    label: \"Example\"\n"
        "    chain: \"ethereum\"\n"
        "poll_interval_seconds: 60\n")
    cfg = DeployerWatchConfig.from_yaml(cfg_file)
    assert len(cfg.deployers) == 1
    assert cfg.deployers[0].label == "Example"
    assert cfg.poll_interval_seconds == 60
    assert "TEMPLATE" in DeployerWatchConfig.example_yaml()


def test_deployer_config_missing_file_is_empty(tmp_path: Path) -> None:
    cfg = DeployerWatchConfig.from_yaml(tmp_path / "nope.yaml")
    assert cfg.deployers == []


# ---------------------------------------------------------------------------
# Upgrade triggers + queue
# ---------------------------------------------------------------------------

def test_trigger_queue_roundtrip_and_dedupe(tmp_path: Path) -> None:
    queue = TriggerQueue(open_targeting_state(tmp_path))
    assert len(queue) == 0
    t = UpgradeTrigger(kind="git_tag", project="p", old_version="v1", new_version="v2")
    queue.push(t)
    queue.push(t)  # duplicate push must not double-enqueue
    assert len(queue) == 1
    peeked = queue.peek_all()
    assert peeked[0].new_version == "v2"
    assert peeked[0].trigger_id == t.trigger_id
    popped = queue.pop()
    assert popped is not None and popped.new_version == "v2"
    assert len(queue) == 0
    assert queue.pop() is None


def test_trigger_serialization() -> None:
    t = UpgradeTrigger(kind="proxy_upgrade", project="p",
                       proxy_address=PROXY, old_implementation=OLD_IMPL,
                       new_implementation=NEW_IMPL, block_number=7)
    t2 = UpgradeTrigger.from_dict(t.to_dict())
    assert t2.new_implementation == NEW_IMPL
    assert t2.trigger_id == t.trigger_id


@needs_git
def test_git_tag_watcher_detects_new_tags(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "repo", ["v1.0.0"])
    state = open_targeting_state(tmp_path)
    watcher = GitTagWatcher(repo, "demo", state)
    assert watcher.poll_once() == []  # first run baselines
    _git(["tag", "v1.1.0"], repo)
    _git(["tag", "v2.0.0"], repo)
    triggers = watcher.poll_once()
    assert [t.new_version for t in triggers] == ["v1.1.0", "v2.0.0"]
    assert all(t.kind == "git_tag" and t.project == "demo" for t in triggers)
    assert triggers[0].old_version == "v1.0.0"
    assert watcher.poll_once() == []  # cursor persisted


@needs_git
def test_git_tag_watcher_handles_missing_repo(tmp_path: Path) -> None:
    watcher = GitTagWatcher(tmp_path / "nope", "demo",
                            open_targeting_state(tmp_path))
    assert watcher.poll_once() == []


def test_proxy_upgrade_watcher_detects_impl_change(tmp_path: Path) -> None:
    state = open_targeting_state(tmp_path)
    state.set(f"upgrade_watch:proxy_block:{PROXY.lower()}", 100)
    state.set(f"upgrade_watch:proxy_impl:{PROXY.lower()}", OLD_IMPL)
    client = FakeChainClient(head=110, logs=[_upgraded_log(105, NEW_IMPL)])
    watcher = ProxyUpgradeWatcher(PROXY, "demo", client, state)
    triggers = watcher.poll_once()
    assert len(triggers) == 1
    t = triggers[0]
    assert t.kind == "proxy_upgrade"
    assert t.old_implementation.lower() == OLD_IMPL.lower()
    assert t.new_implementation.lower() == NEW_IMPL.lower()
    assert t.block_number == 105
    # No duplicate on the next poll.
    assert watcher.poll_once() == []


def test_proxy_upgrade_watcher_first_run_baselines(tmp_path: Path) -> None:
    client = FakeChainClient(head=110, logs=[_upgraded_log(105, NEW_IMPL)])
    watcher = ProxyUpgradeWatcher(PROXY, "demo", client,
                                  open_targeting_state(tmp_path))
    assert watcher.poll_once() == []


def test_proxy_upgrade_watcher_baseline_block_still_scanned(tmp_path: Path) -> None:
    # An upgrade landing in the baseline head block itself must not be
    # skipped forever (the cursor stores the last *scanned* block).
    client = FakeChainClient(head=110, logs=[_upgraded_log(110, NEW_IMPL)])
    state = open_targeting_state(tmp_path)
    watcher = ProxyUpgradeWatcher(PROXY, "demo", client, state)
    assert watcher.poll_once() == []  # first run baselines
    state.set(f"upgrade_watch:proxy_impl:{PROXY.lower()}", OLD_IMPL)
    triggers = watcher.poll_once()    # second run scans the baseline block
    assert len(triggers) == 1
    assert triggers[0].block_number == 110
    assert triggers[0].new_implementation.lower() == NEW_IMPL.lower()


def test_proxy_upgrade_watcher_offline_by_default(tmp_path: Path) -> None:
    watcher = ProxyUpgradeWatcher(PROXY, "demo", NoopChainClient(),
                                  open_targeting_state(tmp_path))
    assert watcher.poll_once() == []


@needs_git
def test_upgrade_watcher_queues_triggers(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "repo", ["v1.0.0"])
    state = open_targeting_state(tmp_path)
    queue = TriggerQueue(state)
    watcher = UpgradeWatcher(
        UpgradeWatchConfig(projects=[
            WatchedProject(name="demo", repo_path=str(repo), proxies=[PROXY]),
        ]),
        FakeChainClient(head=50), state=state, workdir=tmp_path, queue=queue)
    assert watcher.poll_once() == []  # baselines (git + proxy)
    _git(["tag", "v1.1.0"], repo)
    found = watcher.poll_once()
    assert len(found) == 1
    assert len(queue) == 1
    assert queue.pop().new_version == "v1.1.0"


def test_upgrade_config_example(tmp_path: Path) -> None:
    assert "TEMPLATE" in UpgradeWatchConfig.example_yaml()
    cfg = UpgradeWatchConfig.from_yaml(tmp_path / "missing.yaml")
    assert cfg.projects == []


# ---------------------------------------------------------------------------
# Sweep runner (ROE-gated)
# ---------------------------------------------------------------------------

def _sweep_config(**overrides: Any) -> SweepConfig:
    targets = [
        SweepTarget(name="alpha", repo_url="https://github.com/example/alpha"),
        SweepTarget(name="beta", contract_address="0x" + "12" * 20, chain="base"),
    ]
    return SweepConfig(targets=targets, min_interval_seconds=0, **overrides)


def test_sweep_plan_and_resume(tmp_path: Path) -> None:
    runner = SweepRunner(_sweep_config(), state=open_targeting_state(tmp_path),
                         workdir=tmp_path)
    jobs = runner.run()
    assert [j.target.name for j in jobs] == ["alpha", "beta"]
    assert all(j.status == "done" for j in jobs)
    # Second run: everything already done -> empty plan (resumable).
    assert runner.plan() == []
    # Reset one target -> it comes back.
    runner.reset("alpha")
    assert [j.target.name for j in runner.plan()] == ["alpha"]
    runner.reset()
    assert len(runner.plan()) == 2


def test_sweep_plan_is_passive_by_default(tmp_path: Path) -> None:
    runner = SweepRunner(_sweep_config(), state=open_targeting_state(tmp_path),
                         workdir=tmp_path)
    assert runner.allow_network is False
    jobs = runner.run()
    alpha = next(j for j in jobs if j.target.name == "alpha")
    assert "no network" in alpha.detail  # cloned nothing, touched nothing


def test_sweep_denies_localhost_even_when_listed(tmp_path: Path) -> None:
    cfg = SweepConfig(targets=[
        SweepTarget(name="evil", repo_url="http://localhost:8080/repo.git"),
    ], min_interval_seconds=0)
    runner = SweepRunner(cfg, state=open_targeting_state(tmp_path), workdir=tmp_path)
    jobs = runner.plan()
    assert len(jobs) == 1
    assert jobs[0].status == "skipped"
    assert "deny-listed" in jobs[0].detail


def test_sweep_denies_metadata_ip(tmp_path: Path) -> None:
    cfg = SweepConfig(targets=[
        SweepTarget(name="evil", repo_url="http://169.254.169.254/latest"),
    ], min_interval_seconds=0)
    runner = SweepRunner(cfg, state=open_targeting_state(tmp_path), workdir=tmp_path)
    jobs = runner.plan()
    assert len(jobs) == 1
    assert jobs[0].status == "skipped"
    assert "deny-listed" in jobs[0].detail


def test_sweep_denied_target_does_not_abort_plan(tmp_path: Path) -> None:
    cfg = SweepConfig(targets=[
        SweepTarget(name="evil", repo_url="http://localhost:8080/repo.git"),
        SweepTarget(name="good", repo_url="https://github.com/example/fine"),
    ], min_interval_seconds=0)
    runner = SweepRunner(cfg, state=open_targeting_state(tmp_path), workdir=tmp_path)
    jobs = runner.plan()
    assert [j.target.name for j in jobs] == ["evil", "good"]
    assert jobs[0].status == "skipped"
    assert "deny-listed" in jobs[0].detail
    assert jobs[1].status == "pending"
    # run() must handle the skipped job without raising.
    jobs = runner.run()
    assert jobs[0].status == "skipped"
    assert jobs[1].status == "done"


def test_sweep_respects_per_run_budget(tmp_path: Path) -> None:
    cfg = SweepConfig(
        targets=[SweepTarget(name=f"t{i}",
                             repo_url=f"https://github.com/example/t{i}")
                 for i in range(5)],
        min_interval_seconds=0, max_targets_per_run=2)
    runner = SweepRunner(cfg, state=open_targeting_state(tmp_path), workdir=tmp_path)
    assert len(runner.plan()) == 2


def test_sweep_writes_audit_trail(tmp_path: Path) -> None:
    cfg_file = tmp_path / "sweep.yaml"
    cfg_file.write_text(SweepConfig.example_yaml())
    runner = SweepRunner(_sweep_config(), config_path=cfg_file,
                         state=open_targeting_state(tmp_path), workdir=tmp_path)
    runner.run()
    audit_path = tmp_path / "sweep_audit.jsonl"
    assert audit_path.exists()
    events = [json.loads(line)["event"] for line in
              audit_path.read_text().splitlines() if line.strip()]
    assert events[0] == "session_start"
    assert events[-1] == "session_end"
    assert "target_done" in events


def test_sweep_unknown_target_skipped(tmp_path: Path) -> None:
    cfg = SweepConfig(targets=[SweepTarget(name="empty")], min_interval_seconds=0)
    runner = SweepRunner(cfg, state=open_targeting_state(tmp_path), workdir=tmp_path)
    jobs = runner.run()
    assert jobs[0].status == "skipped"


def test_sweep_example_is_template() -> None:
    text = SweepConfig.example_yaml()
    assert "TEMPLATE" in text
    assert "authorized" in text


# ---------------------------------------------------------------------------
# Variant sweeping
# ---------------------------------------------------------------------------

VULN_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"""

CLEAN_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
"""


def _corpus(tmp_path: Path) -> Path:
    corpus = tmp_path / "corpus"
    (corpus / "projA").mkdir(parents=True)
    (corpus / "projB").mkdir(parents=True)
    (corpus / "projA" / "Vault.sol").write_text(VULN_SOL)
    (corpus / "projB" / "VaultCopy.sol").write_text(
        VULN_SOL.replace("contract Vault", "contract VaultFork"))
    (corpus / "projB" / "Safe.sol").write_text(CLEAN_SOL)
    return corpus


def _finding_dict() -> dict[str, Any]:
    return {
        "category": "reentrancy",
        "swc_id": "SWC-107",
        "function": "withdraw",
        "description": "Reentrant withdraw drains funds before balances update",
        "fingerprint": "deadbeef",
        "target": "demo", "language": "solidity", "file": "Vault.sol",
    }


def test_finding_signature_from_dict() -> None:
    sig = FindingSignature.from_finding(_finding_dict())
    assert sig.category == "reentrancy"
    assert sig.swc_id == "SWC-107"
    assert sig.function == "withdraw"
    assert "withdraw" in sig.keywords
    assert sig.source_fingerprint == "deadbeef"


def test_finding_signature_from_object() -> None:
    obj = SimpleNamespace(**_finding_dict())
    sig = FindingSignature.from_finding(obj)
    assert sig.category == "reentrancy"
    # round-trip
    assert FindingSignature.from_dict(sig.to_dict()).function == "withdraw"


def test_variant_sweeper_finds_function_shape(tmp_path: Path) -> None:
    sweeper = VariantSweeper(_corpus(tmp_path))
    sig = FindingSignature.from_finding(_finding_dict())
    matches = sweeper.sweep(sig)
    by_file = {Path(m.file).name: m for m in matches if m.matched_on == "function"}
    assert "Vault.sol" in by_file
    assert "VaultCopy.sol" in by_file
    assert "Safe.sol" not in by_file  # no withdraw() there
    m = by_file["Vault.sol"]
    assert m.line > 0
    assert "withdraw" in m.evidence
    assert m.score > 0


def test_variant_sweeper_pattern_match(tmp_path: Path) -> None:
    sweeper = VariantSweeper(_corpus(tmp_path))
    sig = FindingSignature(category="reentrancy", pattern=r"call\{value:")
    matches = [m for m in sweeper.sweep(sig) if m.matched_on == "pattern"]
    assert {Path(m.file).name for m in matches} == {"Vault.sol", "VaultCopy.sol"}
    assert all("call{value:" in m.evidence for m in matches)


def test_variant_sweeper_keyword_match(tmp_path: Path) -> None:
    sweeper = VariantSweeper(_corpus(tmp_path), min_keyword_hits=2)
    sig = FindingSignature(category="x", keywords=("balances", "msg.sender", "require"))
    matches = [m for m in sweeper.sweep(sig) if m.matched_on == "keywords"]
    assert matches, "expected keyword co-occurrence matches"
    assert all(m.score > 0 for m in matches)


def test_variant_sweeper_missing_corpus(tmp_path: Path) -> None:
    sweeper = VariantSweeper(tmp_path / "nope")
    assert sweeper.sweep(FindingSignature(category="x")) == []


def test_variant_sweeper_bad_pattern_degrades(tmp_path: Path) -> None:
    sweeper = VariantSweeper(_corpus(tmp_path))
    sig = FindingSignature(category="x", pattern="([unclosed")
    # Bad regex must not raise; other signals still work.
    assert isinstance(sweeper.sweep(sig), list)


# ---------------------------------------------------------------------------
# GitHub code search (opt-in)
# ---------------------------------------------------------------------------

def test_github_search_disabled_without_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert GitHubCodeSearch.from_env() is None

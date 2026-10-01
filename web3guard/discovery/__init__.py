"""
Discovery engines — the static + dynamic analyzers that run before
the LLM analysis pass.

The original scanner wired up four engines (Slither, Aderyn, Mythril,
Echidna) and three legacy ones (Securify, Oyente, Manticore) directly
in :func:`run_discovery_phase`. This module restructures that into
pluggable :class:`DiscoveryEngine` adapters and adds several new ones:

- :class:`GitleaksEngine` — secret scanning (private keys, RPC URLs,
  API tokens) on every language.
- :class:`SemgrepEngine` — security-audit ruleset for off-chain
  TypeScript / JavaScript SDKs.
- :class:`NpmAuditEngine` — dependency vulnerability scan.
- :class:`AderynEngine` — Cyfrin's Rust-based static analyzer.
- :class:`CargoAuditEngine` — Rust dependency vulnerability scan.

The original engines (Slither, Mythril, Echidna) are also re-exported
here so the scanner core has a single import.

Phase 5 adds fresh-code targeting and monitoring (not discovery
engines — they don't run tools against a target, so they stay out of
``ALL_ENGINES``):

- :mod:`web3guard.discovery.deployer_watch` — watch deployer
  addresses for new contract deployments (opt-in RPC, offline stub
  by default).
- :mod:`web3guard.discovery.upgrade_watch` — git-tag and on-chain
  proxy-upgrade detection feeding a persistent scan-on-upgrade
  trigger queue.
- :mod:`web3guard.discovery.sweep` — ROE-gated long-tail protocol
  sweep runner (resumable, rate-limited).
- :mod:`web3guard.discovery.variant_sweep` — sweep a local corpus for
  the shape of a confirmed finding.
"""

from web3guard.discovery.aderyn_engine import AderynEngine
from web3guard.discovery.aptos_bytecode_engine import AptosBytecodeEngine
from web3guard.discovery.base import (
    DiscoveryEngineBase,
    DiscoveryResult,
    safe_run_subprocess,
)
from web3guard.discovery.cargo_audit_engine import CargoAuditEngine

# Phase 5: fresh-code targeting + monitoring (not discovery engines).
from web3guard.discovery.deployer_watch import (
    ChainClient,
    ChainClientError,
    ContractDeployment,
    DeployerWatchConfig,
    DeployerWatcher,
    LogRecord,
    NoopChainClient,
    RpcChainClient,
    WatchedDeployer,
)
from web3guard.discovery.echidna_engine import EchidnaEngine
from web3guard.discovery.gitleaks_engine import GitleaksEngine

# Legacy / opt-in engines (from the original scanner)
from web3guard.discovery.legacy import (
    ManticoreEngine,
    OyenteEngine,
    SecurifyEngine,
)
from web3guard.discovery.mythril_engine import MythrilEngine
from web3guard.discovery.npm_audit_engine import NpmAuditEngine
from web3guard.discovery.semgrep_engine import SemgrepEngine
from web3guard.discovery.slither_engine import SlitherEngine
from web3guard.discovery.static_analyzer import StaticAnalyzerEngine
from web3guard.discovery.sweep import (
    SweepAudit,
    SweepConfig,
    SweepJob,
    SweepRunner,
    SweepScopeError,
    SweepTarget,
)
from web3guard.discovery.targeting_state import open_targeting_state
from web3guard.discovery.upgrade_watch import (
    UPGRADED_EVENT_TOPIC,
    GitTagWatcher,
    ProxyUpgradeWatcher,
    TriggerQueue,
    UpgradeTrigger,
    UpgradeWatchConfig,
    UpgradeWatcher,
    WatchedProject,
)
from web3guard.discovery.variant_sweep import (
    FindingSignature,
    GitHubCodeSearch,
    VariantMatch,
    VariantSweeper,
)

ALL_ENGINES = (
    StaticAnalyzerEngine,
    SlitherEngine,
    AderynEngine,
    MythrilEngine,
    EchidnaEngine,
    GitleaksEngine,
    SemgrepEngine,
    NpmAuditEngine,
    CargoAuditEngine,
    AptosBytecodeEngine,
)

__all__ = [
    "DiscoveryEngineBase",
    "DiscoveryResult",
    "safe_run_subprocess",
    "StaticAnalyzerEngine",
    "SlitherEngine",
    "AderynEngine",
    "MythrilEngine",
    "EchidnaEngine",
    "GitleaksEngine",
    "SemgrepEngine",
    "NpmAuditEngine",
    "CargoAuditEngine",
    "AptosBytecodeEngine",
    "OyenteEngine",
    "SecurifyEngine",
    "ManticoreEngine",
    "ALL_ENGINES",
    # Phase 5: fresh-code targeting + monitoring.
    "open_targeting_state",
    "ChainClient",
    "ChainClientError",
    "ContractDeployment",
    "LogRecord",
    "NoopChainClient",
    "RpcChainClient",
    "WatchedDeployer",
    "DeployerWatchConfig",
    "DeployerWatcher",
    "UPGRADED_EVENT_TOPIC",
    "UpgradeTrigger",
    "TriggerQueue",
    "GitTagWatcher",
    "ProxyUpgradeWatcher",
    "WatchedProject",
    "UpgradeWatchConfig",
    "UpgradeWatcher",
    "SweepTarget",
    "SweepJob",
    "SweepConfig",
    "SweepRunner",
    "SweepScopeError",
    "SweepAudit",
    "FindingSignature",
    "VariantMatch",
    "VariantSweeper",
    "GitHubCodeSearch",
]

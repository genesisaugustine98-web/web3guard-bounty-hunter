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
"""

from web3guard.discovery.base import (
    DiscoveryEngineBase,
    DiscoveryResult,
    safe_run_subprocess,
)
from web3guard.discovery.slither_engine import SlitherEngine
from web3guard.discovery.aderyn_engine import AderynEngine
from web3guard.discovery.mythril_engine import MythrilEngine
from web3guard.discovery.echidna_engine import EchidnaEngine
from web3guard.discovery.gitleaks_engine import GitleaksEngine
from web3guard.discovery.semgrep_engine import SemgrepEngine
from web3guard.discovery.npm_audit_engine import NpmAuditEngine
from web3guard.discovery.cargo_audit_engine import CargoAuditEngine
from web3guard.discovery.aptos_bytecode_engine import AptosBytecodeEngine

# Legacy / opt-in engines (from the original scanner)
from web3guard.discovery.legacy import (
    OyenteEngine,
    SecurifyEngine,
    ManticoreEngine,
)

ALL_ENGINES = (
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
]

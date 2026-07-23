"""
Multi-language target support.

The original scanner hard-codes Solidity at seven different points in
``core_scanner.py``. This package introduces a small abstraction layer:

- :class:`TargetLanguage` enumerates every supported target language.
- :class:`LanguageAdapter` is the protocol each language implements
  (file discovery, chunking, context resolution, test runner, etc.).
- :class:`LanguageRegistry` maps a clone of a target repo to a list of
  applicable :class:`LanguageAdapter` instances by inspecting the build
  tool files present (foundry.toml, Anchor.toml, Move.toml, Scarb.toml,
  Clarinet.toml, etc.).

The refactor is **backwards-compatible**: if a target repo is pure
Solidity (or if no language is detected), the registry falls back to the
original Solidity/EVM pipeline. Adding a new language means writing one
new ``LanguageAdapter`` subclass and registering it; no changes to the
scanner core are required.
"""

from web3guard.languages.base import (
    LanguageAdapter,
    DiscoveryEngine,
    TestRunner,
    Chunk,
    RepoSummary,
    TargetLanguage,
)
from web3guard.languages.registry import (
    LanguageRegistry,
    default_registry,
    detect_target_language,
)
from web3guard.languages.solidity import SolidityAdapter
from web3guard.languages.vyper import VyperAdapter
from web3guard.languages.move_lang import MoveAdapter
from web3guard.languages.cairo_lang import CairoAdapter
from web3guard.languages.clarity_lang import ClarityAdapter
from web3guard.languages.func_lang import FunCAdapter
from web3guard.languages.rust_solana import RustSolanaAdapter
from web3guard.languages.ts_sdk import TypeScriptSDKAdapter

__all__ = [
    "LanguageAdapter",
    "DiscoveryEngine",
    "TestRunner",
    "Chunk",
    "RepoSummary",
    "LanguageRegistry",
    "default_registry",
    "detect_target_language",
    "SolidityAdapter",
    "VyperAdapter",
    "MoveAdapter",
    "CairoAdapter",
    "ClarityAdapter",
    "FunCAdapter",
    "RustSolanaAdapter",
    "TypeScriptSDKAdapter",
]

"""
LanguageRegistry — maps a target repo to one or more LanguageAdapter
instances by inspecting build-tool files, lockfiles, and file
extensions.

The registry is the single entry point used by the scanner core to get
the per-language behavior it needs. Adding a new language is a matter
of writing a new ``LanguageAdapter`` subclass and registering it here.

The registry is intentionally conservative: if a target repo is pure
Solidity (the most common case), it returns exactly the
:class:`SolidityAdapter`. If a target is a mixed repo (e.g. a Solidity
contract with a TypeScript SDK), it returns multiple adapters. The
scanner then runs each adapter's analysis in priority order.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from itertools import islice
from pathlib import Path
from typing import Iterable

from web3guard.languages.base import (
    LanguageAdapter,
    TargetLanguage,
)
from web3guard.languages.solidity import SolidityAdapter
from web3guard.languages.vyper import VyperAdapter
from web3guard.languages.move_lang import MoveAdapter
from web3guard.languages.cairo_lang import CairoAdapter
from web3guard.languages.clarity_lang import ClarityAdapter
from web3guard.languages.func_lang import FunCAdapter
from web3guard.languages.rust_solana import RustSolanaAdapter
from web3guard.languages.ts_sdk import TypeScriptSDKAdapter

LOGGER = logging.getLogger("web3guard.languages.registry")


@dataclass
class LanguageDetection:
    """Result of detecting which languages are in a target repo."""
    primary: TargetLanguage
    detected: list[TargetLanguage] = field(default_factory=list)
    build_tools: list[str] = field(default_factory=list)
    confidence_notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Build-tool file patterns. Each entry is a (path glob, language, build_tool)
# tuple used by the registry to identify which language a target uses.
# The first match wins for the build tool, but multiple matches across
# different files in the same target produce a multi-language detection.
# ---------------------------------------------------------------------------

_BUILD_TOOL_SIGNATURES: tuple[tuple[str, TargetLanguage, str], ...] = (
    # Solidity
    ("foundry.toml",            TargetLanguage.SOLIDITY,    "foundry"),
    ("hardhat.config.js",       TargetLanguage.SOLIDITY,    "hardhat"),
    ("hardhat.config.ts",       TargetLanguage.SOLIDITY,    "hardhat"),
    ("hardhat.config.cjs",      TargetLanguage.SOLIDITY,    "hardhat"),
    ("truffle-config.js",       TargetLanguage.SOLIDITY,    "truffle"),
    ("brownie-config.yaml",     TargetLanguage.SOLIDITY,    "brownie"),
    # Vyper
    ("vyper.config.json",       TargetLanguage.VYPER,       "vyper"),
    # Move (Aptos + Sui)
    ("Move.toml",               TargetLanguage.MOVE,        "aptos-move"),
    ("move.lock",               TargetLanguage.MOVE,        "aptos-move"),
    # Cairo (Starknet)
    ("Scarb.toml",              TargetLanguage.CAIRO,       "scarb"),
    ("cairo_project.toml",      TargetLanguage.CAIRO,       "scarb-legacy"),
    # Clarity (Stacks)
    ("Clarinet.toml",           TargetLanguage.CLARITY,     "clarinet"),
    # FunC (TON)
    ("func/",                   TargetLanguage.FUNC,        "ton-blueprint"),
    ("tonproject.json",         TargetLanguage.FUNC,        "ton"),
    # Solana / Anchor (Rust)
    ("Anchor.toml",             TargetLanguage.RUST_SOLANA, "anchor"),
    ("Cargo.toml",              TargetLanguage.RUST_SOLANA, "rust-cargo"),
    # TypeScript SDK
    ("package.json",            TargetLanguage.TS_SDK,      "ts-sdk"),
    ("tsconfig.json",           TargetLanguage.TS_SDK,      "ts-sdk"),
)


def detect_target_language(target_path: Path) -> LanguageDetection:
    """Inspect ``target_path`` and return the detected languages.

    This is the cheap, regex-only check. The full adapter dispatch
    happens through :class:`LanguageRegistry`.
    """
    detected: dict[TargetLanguage, list[str]] = {}
    build_tools: list[str] = []
    notes: list[str] = []

    for pattern, lang, tool in _BUILD_TOOL_SIGNATURES:
        # Match files at the root, or directories (e.g. ``func/``).
        candidate = target_path / pattern
        if candidate.exists():
            detected.setdefault(lang, []).append(tool)
            if tool not in build_tools:
                build_tools.append(tool)
            notes.append(f"detected {tool} ({lang.value}) via {pattern}")

    # If no build tools were found, fall back to file-extension detection.
    if not detected:
        for ext, lang in (
            (".sol",  TargetLanguage.SOLIDITY),
            (".vyper", TargetLanguage.VYPER),
            (".vy",   TargetLanguage.VYPER),
            (".move", TargetLanguage.MOVE),
            (".cairo", TargetLanguage.CAIRO),
            (".clar", TargetLanguage.CLARITY),
            (".fc",   TargetLanguage.FUNC),
            (".rs",   TargetLanguage.RUST_SOLANA),
            (".ts",   TargetLanguage.TS_SDK),
            (".js",   TargetLanguage.TS_SDK),
        ):
            # rglob is slow on huge repos, so cap at 1000 hits.
            try:
                hits = sum(
                    1 for _ in islice(target_path.rglob(f"*{ext}"), 1000)
                    if not any(part.startswith(".") for part in _.relative_to(target_path).parts)
                )
            except Exception:  # noqa: BLE001
                continue
            if hits > 0:
                detected.setdefault(lang, []).append(f"{ext} extension ({hits} files)")
                notes.append(f"detected {lang.value} via {hits} {ext} files")

    if not detected:
        return LanguageDetection(
            primary=TargetLanguage.UNKNOWN,
            detected=[],
            build_tools=[],
            confidence_notes=["no language signatures matched"],
        )

    # Pick a primary. Solidity wins by default; otherwise pick the
    # language with the most build-tool evidence.
    if TargetLanguage.SOLIDITY in detected:
        primary = TargetLanguage.SOLIDITY
    else:
        primary = max(detected.keys(), key=lambda k: len(detected[k]))

    return LanguageDetection(
        primary=primary,
        detected=list(detected.keys()),
        build_tools=build_tools,
        confidence_notes=notes,
    )


class LanguageRegistry:
    """Holds the canonical list of :class:`LanguageAdapter` instances.

    The registry is a process-wide singleton; you typically don't
    instantiate it directly. Use :data:`default_registry` instead.

    To add a new language:

    1. Implement a :class:`LanguageAdapter` subclass in
       ``web3guard/languages/``.
    2. Import it in this module.
    3. Add it to the ``_ADAPTERS`` tuple below.
    """

    _ADAPTERS: tuple[type[LanguageAdapter], ...] = (
        SolidityAdapter,        # most common; check first
        VyperAdapter,
        MoveAdapter,
        CairoAdapter,
        ClarityAdapter,
        FunCAdapter,
        RustSolanaAdapter,
        TypeScriptSDKAdapter,
    )

    def __init__(self, extra_adapters: Iterable[type[LanguageAdapter]] = ()) -> None:
        self._adapters: dict[TargetLanguage, LanguageAdapter] = {}
        for cls in (*self._ADAPTERS, *extra_adapters):
            try:
                instance = cls()
            except Exception as e:  # noqa: BLE001
                LOGGER.warning("Failed to instantiate adapter %s: %s", cls.__name__, e)
                continue
            self._adapters[instance.language] = instance

    def get(self, language: TargetLanguage) -> LanguageAdapter | None:
        return self._adapters.get(language)

    def detect_for(self, target_path: Path) -> list[LanguageAdapter]:
        """Return the adapters that apply to ``target_path``, in priority order."""
        applicable: list[LanguageAdapter] = []
        for lang, adapter in self._adapters.items():
            try:
                if adapter.detect(target_path):
                    applicable.append(adapter)
            except Exception as e:  # noqa: BLE001
                LOGGER.warning("Adapter %s.detect() failed: %s", adapter.__class__.__name__, e)
        applicable.sort(key=lambda a: a.priority)
        return applicable

    def all_adapters(self) -> list[LanguageAdapter]:
        return list(self._adapters.values())


# Module-level singleton used by the scanner core.
default_registry = LanguageRegistry()

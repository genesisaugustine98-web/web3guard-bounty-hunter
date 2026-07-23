"""
Legacy / opt-in discovery engines.

These are the original scanner's three legacy engines (Securify,
Oyente, Manticore), preserved here for compatibility but disabled
by default. See ``docs/ARCHITECTURE.md`` in the original scanner
for the rationale.

Each engine is a stub that returns an empty list and logs a
warning. They are retained so the configuration keys
``use_securify``, ``use_oyente``, ``use_manticore`` are still
understood.
"""

from __future__ import annotations

import logging
from pathlib import Path

from web3guard.discovery.base import (
    DiscoveryEngineBase,
    DiscoveryResult,
    safe_run_subprocess,
)
from web3guard.languages.base import TargetLanguage

LOGGER = logging.getLogger("web3guard.discovery.legacy")


class SecurifyEngine(DiscoveryEngineBase):
    """Legacy: ETH Zurich's Securify. Off by default."""

    name = "securify"
    binary = "securify"
    supported_languages = (TargetLanguage.SOLIDITY,)
    default_timeout = 240
    enabled_by_default = False

    def run(self, target_path, *, timeout=0, extra_args=None):
        if not self.is_installed():
            return []
        timeout = timeout or self.default_timeout
        # Stub: real Securify requires a docker image; we don't enable it.
        return []


class OyenteEngine(DiscoveryEngineBase):
    """Legacy: Oyente. Off by default. Auto-skipped on Solidity >= 0.5."""

    name = "oyente"
    binary = "oyente"
    supported_languages = (TargetLanguage.SOLIDITY,)
    default_timeout = 180
    enabled_by_default = False

    def run(self, target_path, *, timeout=0, extra_args=None):
        if not self.is_installed():
            return []
        return []


class ManticoreEngine(DiscoveryEngineBase):
    """Legacy: Manticore. Off by default. Heavy symbolic execution."""

    name = "manticore"
    binary = "manticore"
    supported_languages = (TargetLanguage.SOLIDITY, TargetLanguage.VYPER)
    default_timeout = 600
    enabled_by_default = False

    def run(self, target_path, *, timeout=0, extra_args=None):
        if not self.is_installed():
            return []
        return []

"""
Sandbox protocol and factory.

A :class:`TestSandbox` wraps one test runner (Foundry, Anchor, Scarb,
Clarinet, Blueprint, etc.) and exposes a uniform API:

.. code-block:: python

    sandbox = create_sandbox(adapter, target_path, workdir)
    ok, output = sandbox.write_and_run(poc_code, fingerprint)

The factory :func:`create_sandbox` dispatches to the right sandbox
based on the language adapter's :class:`TestRunner` description.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from web3guard.languages.base import LanguageAdapter, TestRunner
from web3guard.security import SandboxGuard, SandboxPolicy

LOGGER = logging.getLogger("web3guard.sandbox.base")


@dataclass
class SandboxResult:
    """Result of running a PoC in a sandbox."""
    ok: bool
    output: str
    error: str = ""
    returncode: int = 0
    gas_used: int | None = None
    revert_reason: str = ""


class TestSandbox(Protocol):
    """Protocol every test-runner sandbox implements."""

    language: Any  # TargetLanguage

    def setup(self, target_path: Path) -> Path:
        """Initialize a fresh sandbox; return the path to its root."""
        ...

    def write_poc(self, sandbox_path: Path, code: str, fingerprint: str) -> Path:
        """Write the AI-generated PoC into the sandbox."""
        ...

    def run(self, sandbox_path: Path, poc_path: Path, timeout: int) -> SandboxResult:
        """Compile and run the PoC; return a :class:`SandboxResult`."""
        ...

    def write_and_run(self, code: str, fingerprint: str, timeout: int = 90) -> tuple[bool, str]:
        """Convenience: setup + write + run in one call.

        Used by the scanner core. Subclasses implement idempotent
        caching of the sandbox root in a per-run directory.
        """
        ...


def create_sandbox(
    adapter: LanguageAdapter,
    target_path: Path,
    workdir: Path,
    policy: SandboxPolicy | None = None,
) -> TestSandbox | None:
    """Return a sandbox appropriate for the adapter's test runner.

    The factory dispatches on ``adapter.test_runner.name``. If the
    runner name is unknown, returns ``None`` and logs a warning.
    """
    runner_name = adapter.test_runner.name
    if runner_name == "foundry":
        from web3guard.sandbox.foundry import FoundrySandbox
        return FoundrySandbox(adapter, target_path, workdir, policy)
    if runner_name == "anchor":
        from web3guard.sandbox.anchor import AnchorSandbox
        return AnchorSandbox(adapter, target_path, workdir, policy)
    if runner_name == "scarb":
        from web3guard.sandbox.scarb import ScarbSandbox
        return ScarbSandbox(adapter, target_path, workdir, policy)
    if runner_name == "move-test":
        from web3guard.sandbox.move_test import MoveSandbox
        return MoveSandbox(adapter, target_path, workdir, policy)
    if runner_name == "clarinet":
        from web3guard.sandbox.clarinet import ClarinetSandbox
        return ClarinetSandbox(adapter, target_path, workdir, policy)
    if runner_name == "ton-blueprint":
        from web3guard.sandbox.ton_blueprint import TonBlueprintSandbox
        return TonBlueprintSandbox(adapter, target_path, workdir, policy)
    if runner_name == "ts-sdk":
        from web3guard.sandbox.ts_sdk import TSSandbox
        return TSSandbox(adapter, target_path, workdir, policy)
    LOGGER.warning("no sandbox implementation for runner %r", runner_name)
    return None

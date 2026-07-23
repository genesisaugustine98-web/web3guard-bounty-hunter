"""Aptos bytecode verifier — pre-deployment safety check for Move packages."""

from __future__ import annotations

import logging
from pathlib import Path

from web3guard.discovery.base import (
    DiscoveryEngineBase,
    DiscoveryResult,
    safe_run_subprocess,
)
from web3guard.languages.base import TargetLanguage

LOGGER = logging.getLogger("web3guard.discovery.aptos_bytecode")


class AptosBytecodeEngine(DiscoveryEngineBase):
    """Run `aptos move compile` and capture bytecode verifier errors.

    The Move bytecode verifier is a static analyzer that runs on
    compiled Move bytecode. Many Move-specific issues (resource
    double-borrow, ability mismatch, etc.) only surface at the
    bytecode level.
    """

    name = "aptos-bytecode-verifier"
    binary = "aptos"
    supported_languages = (TargetLanguage.MOVE,)
    default_timeout = 120

    def run(self, target_path: Path, *, timeout: int = 0,
            extra_args: list[str] | None = None) -> list[DiscoveryResult]:
        if not self.is_installed():
            LOGGER.info("aptos CLI not installed; skipping")
            return []
        if not (target_path / "Move.toml").exists():
            return []
        timeout = timeout or self.default_timeout
        cmd = ["aptos", "move", "compile", "--included-artifacts", "bytecode"]
        if extra_args:
            cmd.extend(extra_args)
        rc, stdout, stderr = safe_run_subprocess(cmd, cwd=target_path, timeout=timeout)
        results: list[DiscoveryResult] = []
        # Move compile errors are usually informative; we surface them
        # as DiscoveryResult entries so the LLM pass can confirm.
        if rc != 0:
            for line in (stderr or "").splitlines():
                if "error" in line.lower() and "[" in line:
                    results.append(DiscoveryResult(
                        engine="aptos-bytecode-verifier",
                        target=str(target_path),
                        file=line.split("[")[-1].split("]")[0] if "]" in line else "",
                        line=0,
                        category="bytecode-verify",
                        severity="MEDIUM",
                        title="Move compile error",
                        description=line,
                        confidence=0.6,
                        raw={"stderr": stderr},
                    ))
        return results

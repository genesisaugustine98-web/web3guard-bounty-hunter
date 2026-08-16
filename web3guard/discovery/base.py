"""
Base types for the discovery engine system.

Every static / dynamic analysis tool that runs before the LLM pass
is wrapped in a :class:`DiscoveryEngineBase` subclass. The
scanner core invokes them via the
:func:`run_discovery_phase` orchestrator.
"""

from __future__ import annotations

import abc
import json
import logging
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from web3guard.languages.base import TargetLanguage
from web3guard.security import SandboxGuard, SandboxPolicy

LOGGER = logging.getLogger("web3guard.discovery.base")


def temp_report_path(target_path: Path, name: str) -> Path:
    """Return a report-output path that lives *outside* the scanned repo.

    Several CLI tools (aderyn, gitleaks, semgrep, mythril, echidna)
    write their findings to a JSON report file. The original engines
    wrote those into ``target_path / "<name>_report.json"``, silently
    polluting the repository being scanned (and sometimes being re-
    scanned on the next run). This helper puts the report in a fresh
    OS temp directory instead.
    """
    d = Path(tempfile.mkdtemp(prefix=f"web3guard-{name}-"))
    return d / f"{name}_report.json"


@dataclass
class DiscoveryResult:
    """A single finding from a discovery engine.

    The format is normalized across engines; each engine subclass
    is responsible for translating its own output into this shape.
    """
    engine: str                 # "slither", "aderyn", "mythril", "echidna", ...
    target: str                 # the target URL or path
    file: str
    line: int = 0
    end_line: int = 0
    function: str = ""
    category: str = ""          # "reentrancy" | "access-control" | ...
    severity: str = "MEDIUM"    # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str = ""
    description: str = ""
    swc_id: str = ""
    confidence: float = 0.5     # the engine's own confidence, 0-1
    raw: dict[str, Any] = field(default_factory=dict)


def safe_run_subprocess(
    cmd: list[str],
    *,
    cwd: Path,
    timeout: int,
    env_extra: dict[str, str] | None = None,
    policy: SandboxPolicy | None = None,
) -> tuple[int, str, str]:
    """Run a discovery-engine subprocess under sandbox policy.

    Returns (returncode, stdout, stderr). The subprocess:
    - inherits the policy's resource limits (CPU/AS/FSIZE/NOFILE/NPROC)
    - has its environment filtered to drop API keys
    - has stdout/stderr truncated to a safe size
    """
    guard = SandboxGuard(policy or SandboxPolicy())
    report = guard.prepare_subprocess(cmd, cwd=cwd, extra_env=env_extra)
    try:
        proc = subprocess.run(
            report.command, cwd=report.cwd, env=report.env,
            capture_output=True, text=True, timeout=timeout,
            preexec_fn=guard.apply_resource_limits if sys.platform != "win32" else None,
        )
        return (
            proc.returncode,
            guard.truncate_revert_reason(proc.stdout),
            guard.truncate_revert_reason(proc.stderr),
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"
    except FileNotFoundError as e:
        return 127, "", f"command not found: {e}"


class DiscoveryEngineBase(abc.ABC):
    """Protocol every discovery engine implements.

    Subclasses set ``name`` and ``binary``, and implement
    :meth:`run`. The scanner core calls ``run`` once per target
    with a configurable timeout.
    """

    name: str = "unknown"
    binary: str = ""            # executable name; "" means "no binary" (built-in)
    supported_languages: tuple[TargetLanguage, ...] = (TargetLanguage.SOLIDITY,)
    default_timeout: int = 300
    enabled_by_default: bool = True

    @abc.abstractmethod
    def run(self, target_path: Path, *, timeout: int = 0,
            extra_args: list[str] | None = None) -> list[DiscoveryResult]:
        """Run the engine against ``target_path`` and return a list of results."""

    def is_installed(self) -> bool:
        if not self.binary:
            return True
        import shutil
        return shutil.which(self.binary) is not None

"""Vyper invariant campaign execution (Phase 6).

Runs the rendered titanoboa driver (see
:mod:`web3guard.invariants.vyper_harness`) with the persistent titanoboa
venv's Python under the sandbox policy (resource limits, filtered env, hard
timeout — see :mod:`web3guard.security.sandbox_guard`), then parses the
JSON-lines output:

- a violated invariant becomes a :class:`web3guard.scanner.Finding` with
  ``status="POTENTIAL"``, the exact failing call sequence in
  ``poc_code``/``exploit_log``, and confidence from reproducibility;
- a clean run produces no findings;
- a missing toolchain degrades honestly (skip with a clear message, never
  a crash).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from web3guard.invariants.fuzz import _prepare_project_dir
from web3guard.invariants.harness import write_project
from web3guard.invariants.models import CampaignResult, FuzzBounds, Invariant
from web3guard.scanner import Finding
from web3guard.security.sandbox_guard import run_sandboxed

LOGGER = logging.getLogger("web3guard.invariants.fuzz_vyper")

#: Persistent titanoboa install location (never ~/.local — ephemeral).
VYPER_TOOLS_DIR = Path.home() / "workspace" / "tools" / "vyper-invariants"
VYPER_VENV_PYTHON = VYPER_TOOLS_DIR / "venv" / "bin" / "python"

#: Writable HOME for the sandboxed campaign (vyper/titanoboa caches).
VYPER_SANDBOX_HOME = VYPER_TOOLS_DIR / "sandbox-home"

#: Env override for the runner python, honored first.
VYPER_RUNNER_ENV = "WEB3GUARD_VYPER_PYTHON"

_MAX_LOG_CHARS = 6000

# Cache of "does this python import boa?" so discovery stays cheap.
_BOA_IMPORT_CACHE: dict[str, bool] = {}


def _python_imports_boa(python_bin: str) -> bool:
    """Return True when ``python_bin -c "import boa"`` succeeds."""
    if python_bin in _BOA_IMPORT_CACHE:
        return _BOA_IMPORT_CACHE[python_bin]
    import subprocess  # local import: only needed for discovery

    try:
        proc = subprocess.run(
            [python_bin, "-c", "import boa"],
            capture_output=True,
            timeout=60,
        )
        ok = proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        ok = False
    _BOA_IMPORT_CACHE[python_bin] = ok
    return ok


def discover_vyper_runner(config: Mapping[str, Any] | None = None) -> str | None:
    """Locate a Python with titanoboa (``boa``) installed.

    Order: ``WEB3GUARD_VYPER_PYTHON`` env override, the persistent
    ``~/workspace/tools/vyper-invariants/venv`` install. Returns the python
    binary path, or None when no working runner exists.
    """
    candidates: list[str] = []
    env_bin = os.environ.get(VYPER_RUNNER_ENV)
    if env_bin:
        candidates.append(env_bin)
    candidates.append(str(VYPER_VENV_PYTHON))
    for cand in candidates:
        if cand and Path(cand).is_file() and os.access(cand, os.X_OK):
            if _python_imports_boa(cand):
                return cand
            LOGGER.info("python at %s has no titanoboa; skipping", cand)
    return None


def _sandbox_home() -> Path:
    VYPER_SANDBOX_HOME.mkdir(parents=True, exist_ok=True)
    try:
        # run_sandboxed drops to nobody when we are root; HOME must stay
        # writable for it.
        os.chmod(VYPER_SANDBOX_HOME, 0o777)
    except OSError:
        pass
    return VYPER_SANDBOX_HOME


def parse_vyper_output(
    stdout: str,
    invariants: list[Invariant],
    *,
    contract_path: str = "",
    contract_name: str = "Target",
    target_label: str = "",
) -> tuple[list[Finding], CampaignResult]:
    """Turn the driver's JSON-lines output into findings + campaign summary."""
    campaign = CampaignResult(engine="titanoboa-invariant")
    by_id = {inv.id: inv for inv in invariants}
    violations: list[dict[str, Any]] = []
    summary: dict[str, Any] | None = None

    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("type") == "violation":
            violations.append(obj)
        elif obj.get("type") == "summary":
            summary = obj

    campaign.raw_stdout = stdout[-_MAX_LOG_CHARS:]
    if summary is None:
        LOGGER.warning(
            "vyper campaign for %s produced no summary line",
            target_label or contract_name,
        )
        return [], campaign
    campaign.compile_ok = bool(summary.get("compile_ok", False))
    campaign.clean = bool(summary.get("clean", False)) and not violations
    campaign.runs = int(summary.get("runs", 0) or 0)
    campaign.calls = int(summary.get("calls", 0) or 0)
    campaign.reverts = int(summary.get("reverts", 0) or 0)
    for note in summary.get("notes", []) or []:
        LOGGER.info("vyper campaign note for %s: %s", target_label, note)

    if not campaign.compile_ok:
        return [], campaign

    findings: list[Finding] = []
    for v in violations:
        inv_id = str(v.get("invariant_id", "unknown"))
        inv = by_id.get(inv_id)
        bug_class = str(v.get("bug_class") or (inv.bug_class if inv else "other"))
        severity = str(v.get("severity") or (inv.severity if inv else "HIGH"))
        statement = str(v.get("statement") or (inv.statement if inv else ""))
        sequence = v.get("sequence") or []
        seq_text = "\n".join(
            f"  {i + 1}. {step}" for i, step in enumerate(sequence)
        )
        poc = (
            "# Titanoboa invariant counterexample (machine-checked).\n"
            f"# Reproduce: run this pipeline against {target_label or contract_name}\n"
            f"# Failing invariant: {inv_id}\n"
            f"#   {inv_id} [{bug_class}]: {statement}\n"
            "# Randomized call sequence that breaks it (senders are random EOAs):\n"
            f"{seq_text if seq_text else '  (no call sequence recorded)'}\n"
        )
        fingerprint = hashlib.sha256(
            f"vyper:{inv_id}:{seq_text}".encode()
        ).hexdigest()[:16]
        findings.append(
            Finding(
                target=target_label or contract_name,
                language="vyper",
                file=contract_path,
                function=f"invariant_{inv_id}",
                category="invariant-violation",
                severity=severity,
                confidence=0.85 if sequence else 0.75,
                description=(
                    f"Titanoboa invariant fuzzing broke '{inv_id}': {statement}"
                ),
                reasoning=(
                    f"A bounded randomized campaign ({campaign.runs} runs, "
                    f"{campaign.calls} calls, {campaign.reverts} reverts) "
                    f"found a concrete call sequence violating this "
                    f"must-always-hold property ({bug_class}). The sequence "
                    "below is machine-checkable: re-running the campaign "
                    "reproduces it from the fixed seed."
                ),
                status="POTENTIAL",
                poc_code=poc,
                exploit_log=stdout[-_MAX_LOG_CHARS:],
                fingerprint=f"vyper-invariant-{fingerprint}",
                tool_consensus=["titanoboa-invariant"],
                dynamically_confirmed=True,
                metadata={
                    "invariant_id": inv_id,
                    "bug_class": bug_class,
                    "engine": "titanoboa-invariant",
                    "fuzz_runs": campaign.runs,
                    "fuzz_calls": campaign.calls,
                    "invariant_source": inv.source if inv else "unknown",
                },
            )
        )
    return findings, campaign


def run_vyper_campaign(
    project_dir: Path,
    files: Mapping[str, str],
    invariants: list[Invariant],
    bounds: FuzzBounds,
    config: Mapping[str, Any] | None,
    *,
    runner_bin: str | None = None,
    contract_path: str = "",
    contract_name: str = "Target",
    target_label: str = "",
    notes: list[str] | None = None,
) -> tuple[CampaignResult, list[Finding]]:
    """Write the Vyper project, run the titanoboa driver sandboxed, parse."""
    write_project(project_dir, files)
    _prepare_project_dir(project_dir)

    runner = runner_bin or discover_vyper_runner(config)
    if not runner:
        msg = (
            "titanoboa runner not found (checked WEB3GUARD_VYPER_PYTHON and "
            "~/workspace/tools/vyper-invariants/venv). Vyper fuzz campaign "
            "SKIPPED — install titanoboa or set WEB3GUARD_VYPER_PYTHON."
        )
        LOGGER.warning(msg)
        if notes is not None:
            notes.append(msg)
        return CampaignResult(skipped=True, skip_reason=msg), []

    label = target_label or contract_name
    LOGGER.info(
        "starting vyper invariant campaign for %s: runs=%d depth=%d timeout=%ds (runner=%s)",
        label, bounds.runs, bounds.depth, bounds.timeout_seconds, runner,
    )
    cmd = [runner, "run_invariants.py"]
    started = time.monotonic()
    try:
        rc, stdout, stderr = run_sandboxed(
            cmd,
            cwd=project_dir,
            timeout=bounds.timeout_seconds,
            extra_env={"HOME": str(_sandbox_home())},
        )
    except FileNotFoundError as exc:
        msg = f"vyper runner vanished at campaign time ({exc}); skipping."
        LOGGER.warning(msg)
        if notes is not None:
            notes.append(msg)
        return CampaignResult(skipped=True, skip_reason=msg), []
    elapsed = time.monotonic() - started
    output = (stdout or "") + ("\n" + stderr if stderr else "")

    if rc == 124 or "timed out after" in (stderr or ""):
        msg = (
            f"vyper campaign for {label} hit the {bounds.timeout_seconds}s "
            "timeout; treating as inconclusive (no findings)."
        )
        LOGGER.warning(msg)
        if notes is not None:
            notes.append(msg)
        campaign = CampaignResult(
            engine="titanoboa-invariant", raw_stdout=output[-_MAX_LOG_CHARS:]
        )
        campaign.elapsed_seconds = elapsed
        return campaign, []

    findings, campaign = parse_vyper_output(
        output,
        invariants,
        contract_path=contract_path,
        contract_name=contract_name,
        target_label=label,
    )
    campaign.elapsed_seconds = elapsed
    if findings:
        LOGGER.warning(
            "vyper invariant fuzzing broke %d invariant(s) for %s",
            len(findings), label,
        )
    else:
        LOGGER.info("vyper invariant fuzzing clean for %s (%.1fs)", label, elapsed)
    if notes is not None and not campaign.compile_ok and not campaign.clean:
        notes.append(
            f"vyper campaign for {label} did not compile; see logs. "
            "No invariant verdict either way."
        )
    return campaign, findings


__all__ = [
    "VYPER_RUNNER_ENV",
    "VYPER_SANDBOX_HOME",
    "VYPER_TOOLS_DIR",
    "VYPER_VENV_PYTHON",
    "discover_vyper_runner",
    "parse_vyper_output",
    "run_vyper_campaign",
]

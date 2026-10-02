"""Cairo invariant campaign execution (Phase 6).

Runs the rendered snforge project (see
:mod:`web3guard.invariants.cairo_harness`) with ``snforge test`` under the
sandbox policy (resource limits, filtered env, hard timeout — see
:mod:`web3guard.security.sandbox_guard`), then parses the output:

- a failed ``invariant_*`` test becomes a
  :class:`web3guard.scanner.Finding` with ``status="POTENTIAL"``, the
  fuzzer's counterexample arguments in ``poc_code``/``exploit_log``;
- a clean run produces no findings;
- a missing toolchain degrades honestly (skip with a clear message, never
  a crash).

``SCARB_CACHE`` is smuggled to snforge via the ``env`` command prefix
because it is not on the sandbox env allowlist (and the allowlist lives
outside this phase's files, so it stays untouched).
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from web3guard.invariants.fuzz import (
    _prepare_project_dir,
    classify_process_kill,
    extract_compile_errors,
)
from web3guard.invariants.harness import write_project
from web3guard.invariants.models import CampaignResult, FuzzBounds, Invariant
from web3guard.scanner import Finding
from web3guard.security.sandbox_guard import run_sandboxed

LOGGER = logging.getLogger("web3guard.invariants.fuzz_cairo")

#: Persistent Cairo toolchain locations (never ~/.local — ephemeral).
CAIRO_TOOLS_DIR = Path.home() / "workspace" / "tools" / "starknet-foundry"
SNFORE_BIN = CAIRO_TOOLS_DIR / "bin" / "snforge"
USC_BIN = CAIRO_TOOLS_DIR / "bin" / "universal-sierra-compiler"
SCARB_BIN = Path.home() / "workspace" / "tools" / "scarb" / "bin" / "scarb"

#: Writable HOME / Scarb cache for the sandboxed campaign.
CAIRO_SANDBOX_HOME = CAIRO_TOOLS_DIR / "sandbox-home"
CAIRO_SCARB_CACHE = CAIRO_TOOLS_DIR / "scarb-cache"

#: Env override for the snforge binary, honored first.
SNFORE_BIN_ENV = "WEB3GUARD_SNFORE_BIN"

_MAX_LOG_CHARS = 6000

# "[FAIL] <pkg>::...::invariant_foo (runs: 3, arguments: ["1", "2"])"
_FAIL_RE = re.compile(
    r"\[FAIL\]\s+\S*?(invariant_[A-Za-z0-9_]+)\s+"
    r"\(runs:\s*(\d+)(?:,\s*arguments:\s*(\[.*?\]))?"
)
_FAILURE_DATA_RE = re.compile(r"^\s*Failure data:\s*$")
_FAILURE_LINE_RE = re.compile(r"^\s*(0x[0-9a-fA-F]+(?:\s+\('.*'\))?)\s*$")
_SUITE_RE = re.compile(r"Tests:\s*(\d+)\s+passed,\s*(\d+)\s+failed", re.IGNORECASE)
_COMPILE_FAIL_RES = (
    re.compile(r"could not compile", re.IGNORECASE),
    re.compile(r"^\s*error(\[E\d+\])?:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"Requirements not satisfied"),
)


def discover_cairo_toolchain(
    config: Mapping[str, Any] | None = None,
) -> dict[str, str] | None:
    """Locate snforge + scarb + universal-sierra-compiler.

    Order for snforge: ``WEB3GUARD_SNFORE_BIN`` env override, then the
    persistent ``~/workspace/tools/starknet-foundry/bin/snforge`` install.
    scarb: persistent install, then PATH. Returns a dict of binary paths,
    or None when the toolchain is incomplete.
    """
    snforge: str | None = None
    env_bin = os.environ.get(SNFORE_BIN_ENV)
    if env_bin and Path(env_bin).is_file() and os.access(env_bin, os.X_OK):
        snforge = env_bin
    elif SNFORE_BIN.is_file() and os.access(SNFORE_BIN, os.X_OK):
        snforge = str(SNFORE_BIN)
    if not snforge:
        return None

    scarb: str | None = None
    if SCARB_BIN.is_file() and os.access(SCARB_BIN, os.X_OK):
        scarb = str(SCARB_BIN)
    else:
        scarb = shutil.which("scarb")
    if not scarb:
        LOGGER.info("snforge found but scarb is missing; cairo disabled")
        return None

    # universal-sierra-compiler must be findable by snforge (same dir/PATH).
    usc_ok = (USC_BIN.is_file() and os.access(USC_BIN, os.X_OK)) or bool(
        shutil.which("universal-sierra-compiler")
    )
    if not usc_ok:
        LOGGER.info(
            "snforge found but universal-sierra-compiler is missing; "
            "cairo disabled"
        )
        return None
    return {"snforge": snforge, "scarb": scarb}


def _extract_failure_blocks(output: str) -> list[dict[str, Any]]:
    """Split snforge output into per-invariant failure blocks."""
    blocks: list[dict[str, Any]] = []
    lines = output.splitlines()
    i = 0
    while i < len(lines):
        m = _FAIL_RE.search(lines[i])
        if not m:
            i += 1
            continue
        block: dict[str, Any] = {
            "invariant": m.group(1),
            "runs": int(m.group(2)),
            "arguments": m.group(3) or "",
            "failure_data": [],
        }
        # Collect "Failure data:" lines that follow.
        j = i + 1
        in_data = False
        while j < len(lines):
            nxt = lines[j]
            if _FAIL_RE.search(nxt) or _SUITE_RE.search(nxt):
                break
            if _FAILURE_DATA_RE.match(nxt):
                in_data = True
            elif in_data:
                dm = _FAILURE_LINE_RE.match(nxt)
                if dm:
                    block["failure_data"].append(dm.group(1).strip())
                elif nxt.strip() and not nxt.startswith("note:"):
                    in_data = False
            j += 1
        blocks.append(block)
        i = j
    return blocks


def _sanitized_invariant_fn(inv_id: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_]", "_", "invariant_" + inv_id)
    return clean or "invariant_unnamed"


def parse_snforge_output(
    output: str,
    invariants: list[Invariant],
    *,
    contract_path: str = "",
    contract_name: str = "Target",
    target_label: str = "",
) -> tuple[list[Finding], CampaignResult]:
    """Turn ``snforge test`` output into findings + a campaign summary."""
    campaign = CampaignResult(engine="snforge-invariant")
    by_fn = {_sanitized_invariant_fn(inv.id): inv for inv in invariants}
    campaign.raw_stdout = output[-_MAX_LOG_CHARS:]

    if any(rx.search(output) for rx in _COMPILE_FAIL_RES):
        campaign.compile_ok = False
        LOGGER.warning("snforge compile failed for %s", target_label or contract_name)
        return [], campaign

    suite = _SUITE_RE.search(output)
    failing = _extract_failure_blocks(output)
    if suite and int(suite.group(2)) == 0 and not failing:
        if int(suite.group(1)) > 0:
            campaign.compile_ok = True
            campaign.clean = True
            return [], campaign
        # A "Tests: 0 passed, 0 failed" line means the harness ran but no
        # invariant test was discovered/executed — an INCONCLUSIVE run,
        # never a clean verdict. compile_ok stays False so downstream
        # labels this "cause unknown" instead of silently passing.
        LOGGER.warning(
            "snforge executed 0 invariant tests for %s; inconclusive, "
            "not clean",
            target_label or contract_name,
        )
        return [], campaign

    campaign.compile_ok = True
    findings: list[Finding] = []
    for block in failing:
        fn = block["invariant"]
        inv = by_fn.get(fn)
        inv_id = inv.id if inv else fn[len("invariant_"):]
        bug_class = inv.bug_class if inv else "other"
        severity = inv.severity if inv else "HIGH"
        statement = inv.statement if inv else "violated invariant"
        args = block["arguments"]
        failure_data = "\n".join(block["failure_data"])
        # Reproducibility: the fuzzer prints the exact counterexample args.
        confidence = 0.85 if args else 0.75
        poc = (
            "# snforge invariant counterexample (machine-checked).\n"
            f"# Reproduce: run this pipeline against {target_label or contract_name}\n"
            f"# Failing test: {fn}\n"
            f"#   {inv_id} [{bug_class}]: {statement}\n"
            "# Fuzzer counterexample arguments (the `ops` array that breaks it):\n"
            f"#   arguments: {args or '(not printed)'}\n"
            f"# Failure data:\n#   {failure_data or '(none)'}\n"
        )
        fingerprint = hashlib.sha256(
            f"cairo:{inv_id}:{args}".encode()
        ).hexdigest()[:16]
        findings.append(
            Finding(
                target=target_label or contract_name,
                language="cairo",
                file=contract_path,
                function=fn,
                category="invariant-violation",
                severity=severity,
                confidence=confidence,
                description=(
                    f"snforge invariant fuzzing broke '{inv_id}': {statement}"
                ),
                reasoning=(
                    f"A bounded fuzz campaign ({block['runs']} runs) found a "
                    f"concrete randomized call sequence violating this "
                    f"must-always-hold property ({bug_class}). The fuzzer's "
                    "counterexample arguments below reproduce it."
                ),
                status="POTENTIAL",
                poc_code=poc,
                exploit_log=output[-_MAX_LOG_CHARS:],
                fingerprint=f"cairo-invariant-{fingerprint}",
                tool_consensus=["snforge-invariant"],
                dynamically_confirmed=True,
                metadata={
                    "invariant_id": inv_id,
                    "bug_class": bug_class,
                    "engine": "snforge-invariant",
                    "fuzz_runs": block["runs"],
                    "invariant_source": inv.source if inv else "unknown",
                },
            )
        )
    if not findings and not (suite and int(suite.group(2)) == 0):
        # Nonzero failure with no attributable invariant blocks: infra noise.
        LOGGER.warning(
            "snforge exited with failures for %s but no attributable "
            "invariant blocks; treating as inconclusive",
            target_label or contract_name,
        )
    return findings, campaign


def _sandbox_home() -> Path:
    CAIRO_SANDBOX_HOME.mkdir(parents=True, exist_ok=True)
    CAIRO_SCARB_CACHE.mkdir(parents=True, exist_ok=True)
    for d in (CAIRO_SANDBOX_HOME, CAIRO_SCARB_CACHE):
        try:
            # run_sandboxed drops to nobody when we are root; HOME and the
            # Scarb cache must stay writable for it.
            os.chmod(d, 0o777)
        except OSError:
            pass
    # Scarb opens its registry index lock files for writing even on
    # cache hits; as nobody that fails unless the locks are writable.
    # (Only a handful of files — cheap to fix on every campaign.)
    cache_locks = CAIRO_SCARB_CACHE / "registry" / "cache"
    if cache_locks.is_dir():
        for lock in cache_locks.glob("*.lock"):
            try:
                os.chmod(lock, 0o666)
            except OSError:
                pass
    return CAIRO_SANDBOX_HOME


def run_cairo_campaign(
    project_dir: Path,
    files: Mapping[str, str],
    invariants: list[Invariant],
    bounds: FuzzBounds,
    config: Mapping[str, Any] | None,
    *,
    toolchain: dict[str, str] | None = None,
    contract_path: str = "",
    contract_name: str = "Target",
    target_label: str = "",
    notes: list[str] | None = None,
) -> tuple[CampaignResult, list[Finding]]:
    """Write the snforge project, run ``snforge test`` sandboxed, parse."""
    write_project(project_dir, files)
    _prepare_project_dir(project_dir)

    tc = toolchain or discover_cairo_toolchain(config)
    if not tc:
        msg = (
            "cairo toolchain not found (need snforge + scarb + "
            "universal-sierra-compiler; checked WEB3GUARD_SNFORE_BIN, "
            "~/workspace/tools/starknet-foundry/bin, and PATH). Cairo fuzz "
            "campaign SKIPPED — install the toolchain to "
            "~/workspace/tools/starknet-foundry."
        )
        LOGGER.warning(msg)
        if notes is not None:
            notes.append(msg)
        return CampaignResult(skipped=True, skip_reason=msg), []

    label = target_label or contract_name
    LOGGER.info(
        "starting cairo invariant campaign for %s: runs=%d timeout=%ds (snforge=%s)",
        label, bounds.runs, bounds.timeout_seconds, tc["snforge"],
    )
    # SCARB_CACHE is not on the sandbox env allowlist, so smuggle it via
    # the `env` command prefix instead of extra_env.
    cmd = [
        "env",
        f"SCARB_CACHE={CAIRO_SCARB_CACHE}",
        tc["snforge"],
        "test",
    ]
    path_extra = os.pathsep.join(
        [str(CAIRO_TOOLS_DIR / "bin"),
         str(SCARB_BIN.parent),
         os.environ.get("PATH", "")]
    )
    started = time.monotonic()
    try:
        rc, stdout, stderr = run_sandboxed(
            cmd,
            cwd=project_dir,
            timeout=bounds.timeout_seconds,
            extra_env={
                "HOME": str(_sandbox_home()),
                "PATH": path_extra,
            },
        )
    except FileNotFoundError as exc:
        msg = f"cairo toolchain vanished at campaign time ({exc}); skipping."
        LOGGER.warning(msg)
        if notes is not None:
            notes.append(msg)
        return CampaignResult(skipped=True, skip_reason=msg), []
    elapsed = time.monotonic() - started
    output = (stdout or "") + ("\n" + stderr if stderr else "")

    if rc == 124 or "timed out after" in (stderr or ""):
        # Fix D: a timeout is resource exhaustion, never "did not compile".
        detail = (
            f"timeout after {bounds.timeout_seconds}s — the campaign "
            "wall-clock budget was exhausted before the runner finished"
        )
        msg = (
            f"cairo campaign for {label} RESOURCE_EXHAUSTED ({detail}); "
            "no invariant verdict — this target was NOT checked."
        )
        LOGGER.warning(msg)
        if notes is not None:
            notes.append(msg)
        campaign = CampaignResult(
            engine="snforge-invariant",
            raw_stdout=output[-_MAX_LOG_CHARS:],
            resource_exhausted=True,
            resource_detail=detail,
        )
        campaign.elapsed_seconds = elapsed
        return campaign, []

    kill_detail = classify_process_kill(rc, stdout, stderr)
    if kill_detail is not None:
        # Fix D: signal/OOM kills get their own verdict, never "did not compile".
        msg = (
            f"cairo campaign for {label} RESOURCE_EXHAUSTED ({kill_detail}); "
            "no invariant verdict — this target was NOT checked."
        )
        LOGGER.warning(msg)
        if notes is not None:
            notes.append(msg)
        campaign = CampaignResult(
            engine="snforge-invariant",
            raw_stdout=output[-_MAX_LOG_CHARS:],
            resource_exhausted=True,
            resource_detail=kill_detail,
        )
        campaign.elapsed_seconds = elapsed
        return campaign, []

    findings, campaign = parse_snforge_output(
        output,
        invariants,
        contract_path=contract_path,
        contract_name=contract_name,
        target_label=label,
    )
    campaign.elapsed_seconds = elapsed
    if findings:
        LOGGER.warning(
            "cairo invariant fuzzing broke %d invariant(s) for %s",
            len(findings), label,
        )
    elif campaign.clean:
        LOGGER.info("cairo invariant fuzzing clean for %s (%.1fs)", label, elapsed)
    else:
        # Non-clean, non-violating outcomes (compile failure, resource
        # exhaustion handled above, inconclusive runs) must not be
        # logged as "clean".
        LOGGER.info("cairo invariant fuzzing ended without a clean verdict for %s (%.1fs)", label, elapsed)
    if notes is not None and not campaign.compile_ok and not campaign.clean:
        # Fix D: "did not compile" requires actual compiler-failure
        # evidence — provable or absent. Signal/timeout kills already
        # returned above with RESOURCE_EXHAUSTED.
        if campaign.resource_exhausted or campaign.skipped:
            pass
        elif extract_compile_errors(output):
            notes.append(
                f"cairo campaign for {label} did not compile; see logs. "
                "No invariant verdict either way."
            )
        else:
            notes.append(
                f"cairo campaign for {label} ended with no parseable suite "
                "result and no compiler errors in the output (cause "
                "unknown); no invariant verdict either way."
            )
    return campaign, findings


__all__ = [
    "CAIRO_SANDBOX_HOME",
    "CAIRO_SCARB_CACHE",
    "CAIRO_TOOLS_DIR",
    "SCARB_BIN",
    "SNFORE_BIN",
    "SNFORE_BIN_ENV",
    "USC_BIN",
    "discover_cairo_toolchain",
    "parse_snforge_output",
    "run_cairo_campaign",
]

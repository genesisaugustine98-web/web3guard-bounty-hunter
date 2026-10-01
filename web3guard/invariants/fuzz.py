"""Fuzz campaign execution (Phase 2, step 3).

Runs the rendered Foundry invariant project with ``forge test`` under the
sandbox policy (resource limits, filtered env, hard timeout — see
:mod:`web3guard.security.sandbox_guard`), then parses the output:

- a violated invariant becomes a :class:`web3guard.scanner.Finding` with
  ``status="POTENTIAL"``, the exact failing call sequence in
  ``poc_code``/``exploit_log`` (a machine-checkable PoC), and confidence
  derived from reproducibility;
- a clean run produces no findings;
- a missing ``forge`` binary degrades honestly (skip with a clear message,
  never a crash). If ``echidna`` happens to be installed, a best-effort
  assertion-mode fallback runs, reusing the flag conventions of
  :mod:`web3guard.discovery.echidna_engine`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from web3guard.invariants.harness import write_project
from web3guard.invariants.models import CampaignResult, FuzzBounds, Invariant
from web3guard.scanner import Finding
from web3guard.security.sandbox_guard import run_sandboxed

LOGGER = logging.getLogger("web3guard.invariants.fuzz")

#: Persistent Foundry install location (never ~/.foundry — ephemeral).
FOUNDRY_BIN_DIR = Path.home() / "workspace" / "tools" / "foundry" / "bin"
FOUNDRY_FORGE = FOUNDRY_BIN_DIR / "forge"

#: Writable HOME for sandboxed forge runs. The sandbox drops privileges to
#: ``nobody`` when the scanner runs as root, so forge needs a HOME it can
#: read/write (solc downloads / caches live in ``$HOME/.svm``).
FOUNDRY_SANDBOX_HOME = FOUNDRY_BIN_DIR.parent / "sandbox-home"

#: Env override for the forge binary, honored first.
FORGE_BIN_ENV = "WEB3GUARD_FORGE_BIN"

# ---------------------------------------------------------------------------
# forge output parsing
# ---------------------------------------------------------------------------

# Matches "[FAIL: <reason>]" summary lines that name the invariant directly,
# e.g. "[FAIL: invariant_solvency] (runs: 256, ...)".
_FAIL_NAMED_RE = re.compile(r"\[FAIL:\s*(invariant[A-Za-z0-9_]*)\s*\]")
# Matches the trailing " invariant_foo() (runs: N, ...)" line that follows a
# "[FAIL: <reason>]" + "[Sequence]" block in forge >= 1.x output.
_FAIL_TRAILING_RE = re.compile(r"^\s*(invariant[A-Za-z0-9_]*)\(\)\s*\(runs:")
_SUITE_RE = re.compile(r"Suite result:\s*(ok|FAILED)", re.IGNORECASE)
_RUNS_RE = re.compile(r"\(runs:\s*(\d+),\s*calls:\s*(\d+),\s*reverts:\s*(\d+)\)")
_COMPILE_FAIL_RES = (
    re.compile(r"Compiler run failed", re.IGNORECASE),
    re.compile(r"^\[ERROR[^\n]*$", re.MULTILINE),
    re.compile(r"Error \(6275\)|ParserError|DeclarationError", re.IGNORECASE),
)

_MAX_LOG_CHARS = 6000


def _sanitized_invariant_fn(inv_id: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_]", "_", "invariant_" + inv_id)
    if clean and clean[0].isdigit():
        clean = "inv_" + clean
    return clean or "inv_unnamed"


def _extract_failure_blocks(output: str) -> list[dict[str, Any]]:
    """Split forge output into per-failure blocks.

    Handles both forge output shapes:
    - ``[FAIL: <reason>]`` followed by a ``[Sequence]`` block and a
      trailing `` invariant_foo() (runs: ...)`` line (forge 1.x), and
    - ``[FAIL: invariant_foo] (runs: ...)`` summary lines.
    Each block yields {"invariant": name | None, "sequence": [lines]}.
    """
    blocks: list[dict[str, Any]] = []
    lines = output.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if "[FAIL" not in line:
            i += 1
            continue
        block: dict[str, Any] = {"invariant": None, "sequence": []}
        m = _FAIL_NAMED_RE.search(line)
        if m:
            block["invariant"] = m.group(1)
        # Scan the following lines: sequence steps (sender=/calldata=) and
        # the trailing " invariant_foo() (runs: ...)" line. Stop at the next
        # FAIL line, the suite summary, or a JSON event line.
        j = i + 1
        while j < len(lines):
            nxt = lines[j]
            if "[FAIL" in nxt or _SUITE_RE.search(nxt) or nxt.lstrip().startswith('{"timestamp"'):
                break
            tm = _FAIL_TRAILING_RE.match(nxt)
            if tm:
                block["invariant"] = tm.group(1)
            s = nxt.strip()
            if "sender=" in s and "calldata=" in s:
                block["sequence"].append(s)
            j += 1
        blocks.append(block)
        i = j
    return blocks


def parse_forge_output(
    output: str,
    invariants: list[Invariant],
    *,
    contract_path: str = "",
    contract_name: str = "Target",
    target_label: str = "",
) -> tuple[list[Finding], CampaignResult]:
    """Turn ``forge test`` output into findings + a campaign summary."""
    campaign = CampaignResult(engine="foundry-invariant")
    by_fn = {_sanitized_invariant_fn(inv.id): inv for inv in invariants}

    suite = _SUITE_RE.search(output)
    runs_m = _RUNS_RE.search(output)
    if runs_m:
        campaign.runs = int(runs_m.group(1))
        campaign.calls = int(runs_m.group(2))
        campaign.reverts = int(runs_m.group(3))
    campaign.raw_stdout = output[-_MAX_LOG_CHARS:]

    if suite and suite.group(1).lower() == "ok":
        campaign.compile_ok = True
        campaign.clean = True
        return [], campaign

    failing = _extract_failure_blocks(output)
    # Attribute each block to a known invariant; drop unattributable ones.
    named = [b for b in failing if b["invariant"]]
    # Merge sequence lines across repeated blocks for the same invariant
    # (forge prints the failure once per test and once in the summary).
    by_inv: dict[str, list[str]] = {}
    for b in named:
        fn = b["invariant"]
        assert isinstance(fn, str)
        seq = by_inv.setdefault(fn, [])
        for step in b["sequence"]:
            if step not in seq:
                seq.append(step)

    if not by_inv:
        # Nonzero exit but no attributable invariant failures and no clean
        # suite line: almost always a compile error or an infra problem.
        if any(rx.search(output) for rx in _COMPILE_FAIL_RES):
            campaign.compile_ok = False
            LOGGER.warning("forge compile failed for %s", target_label or contract_name)
        else:
            LOGGER.warning(
                "forge exited without a parseable suite result for %s",
                target_label or contract_name,
            )
        return [], campaign

    campaign.compile_ok = True
    findings: list[Finding] = []
    for fn, sequence in by_inv.items():
        inv = by_fn.get(fn)
        inv_id = inv.id if inv else fn[len("invariant_"):]
        bug_class = inv.bug_class if inv else "other"
        severity = inv.severity if inv else "HIGH"
        statement = inv.statement if inv else "violated invariant"

        # Confidence from reproducibility: a captured call sequence raises
        # it, and seeing the same invariant fail in both the per-test block
        # and the "Failing tests" summary raises it further.
        confidence = 0.80
        if sequence:
            confidence += 0.05
        repeats = sum(1 for b in named if b["invariant"] == fn)
        if repeats > 1:
            confidence += 0.05
        confidence = min(confidence, 0.95)

        seq_text = "\n".join(f"  {i+1}. {step}" for i, step in enumerate(sequence))
        poc = (
            "# Forge invariant counterexample (machine-checked).\n"
            f"# Reproduce: run this pipeline against {target_label or contract_name}\n"
            f"# Failing invariant: {fn}\n"
            f"#   {inv_id} [{bug_class}]: {statement}\n"
            "# Call sequence that breaks it:\n"
            f"{seq_text if seq_text else '  (forge did not print a call sequence)'}\n"
        )
        fingerprint = hashlib.sha256(
            f"{inv_id}:{sequence}".encode()
        ).hexdigest()[:16]
        findings.append(
            Finding(
                target=target_label or contract_name,
                language="solidity",
                file=contract_path,
                function=fn,
                category="invariant-violation",
                severity=severity,
                confidence=confidence,
                description=(
                    f"Foundry invariant fuzzing broke '{inv_id}': {statement}"
                ),
                reasoning=(
                    f"A bounded fuzz campaign ({campaign.runs} runs, "
                    f"{campaign.calls} calls) found a concrete transaction "
                    f"sequence violating this must-always-hold property "
                    f"({bug_class}). The sequence below is machine-checkable."
                ),
                status="POTENTIAL",
                poc_code=poc,
                exploit_log=output[-_MAX_LOG_CHARS:],
                fingerprint=f"invariant-{fingerprint}",
                tool_consensus=["foundry-invariant"],
                dynamically_confirmed=True,
                metadata={
                    "invariant_id": inv_id,
                    "bug_class": bug_class,
                    "engine": "foundry-invariant",
                    "fuzz_runs": campaign.runs,
                    "fuzz_calls": campaign.calls,
                    "invariant_source": inv.source if inv else "unknown",
                },
            )
        )
    return findings, campaign


# ---------------------------------------------------------------------------
# forge discovery + campaign runner
# ---------------------------------------------------------------------------


def discover_forge(config: Mapping[str, Any] | None = None) -> str | None:
    """Locate a forge binary.

    Order: ``WEB3GUARD_FORGE_BIN`` env override, the persistent
    ``~/workspace/tools/foundry/bin/forge`` install, then PATH.
    """
    candidates: list[str] = []
    env_bin = os.environ.get(FORGE_BIN_ENV)
    if env_bin:
        candidates.append(env_bin)
    candidates.append(str(FOUNDRY_FORGE))
    for cand in candidates:
        if cand and Path(cand).is_file() and os.access(cand, os.X_OK):
            return cand
    which = shutil.which("forge")
    return which


def _prepare_project_dir(project_dir: Path) -> None:
    """Make the rendered project usable by the privilege-dropped child.

    :func:`run_sandboxed` drops to ``nobody`` when the scanner runs as
    root, but the project lives in a root-owned 0700 tempdir. Forge needs
    to read the sources and write ``out/``/``cache/`` there, so the tree
    is opened up. This is safe: the directory is ephemeral, contains only
    our generated harness plus a copy of the target source, and is
    deleted when the campaign ends.
    """
    for root, dirs, files in os.walk(project_dir):
        for d in dirs:
            try:
                os.chmod(os.path.join(root, d), 0o777)
            except OSError:
                pass
        for f in files:
            try:
                os.chmod(os.path.join(root, f), 0o666)
            except OSError:
                pass
    try:
        os.chmod(project_dir, 0o777)
    except OSError:
        pass


def _sandbox_home() -> Path:
    """Return a writable HOME for the sandboxed forge child, creating it."""
    FOUNDRY_SANDBOX_HOME.mkdir(parents=True, exist_ok=True)
    return FOUNDRY_SANDBOX_HOME


def run_fuzz_campaign(
    project_dir: Path,
    files: Mapping[str, str],
    invariants: list[Invariant],
    bounds: FuzzBounds,
    config: Mapping[str, Any] | None,
    *,
    forge_bin: str | None = None,
    contract_path: str = "",
    contract_name: str = "Target",
    target_label: str = "",
    notes: list[str] | None = None,
) -> tuple[CampaignResult, list[Finding]]:
    """Write the project, run ``forge test`` sandboxed, parse the output."""
    write_project(project_dir, files)
    _prepare_project_dir(project_dir)

    forge = forge_bin or discover_forge(config)
    if not forge:
        msg = (
            "forge not found (checked WEB3GUARD_FORGE_BIN, "
            "~/workspace/tools/foundry/bin/forge, and PATH). Fuzz campaign "
            "SKIPPED — install Foundry or set WEB3GUARD_FORGE_BIN."
        )
        LOGGER.warning(msg)
        if notes is not None:
            notes.append(msg)
        return CampaignResult(skipped=True, skip_reason=msg), []

    label = target_label or contract_name
    LOGGER.info(
        "starting invariant fuzz campaign for %s: runs=%d depth=%d timeout=%ds (forge=%s)",
        label, bounds.runs, bounds.depth, bounds.timeout_seconds, forge,
    )
    cmd = [forge, "test", "--match-contract", "InvariantTest", "-vv"]
    started = time.monotonic()
    try:
        rc, stdout, stderr = run_sandboxed(
            cmd,
            cwd=project_dir,
            timeout=bounds.timeout_seconds,
            # A writable HOME for the privilege-dropped child (solc cache).
            extra_env={
                "HOME": str(_sandbox_home()),
                "FOUNDRY_DISABLE_NIGHTLY_WARNING": "1",
            },
        )
    except FileNotFoundError as exc:
        msg = f"forge binary vanished at campaign time ({exc}); skipping."
        LOGGER.warning(msg)
        if notes is not None:
            notes.append(msg)
        return CampaignResult(skipped=True, skip_reason=msg), []
    elapsed = time.monotonic() - started
    output = (stdout or "") + ("\n" + stderr if stderr else "")

    if rc == 124 or "timed out after" in (stderr or ""):
        msg = (
            f"fuzz campaign for {label} hit the {bounds.timeout_seconds}s "
            "timeout; treating as inconclusive (no findings)."
        )
        LOGGER.warning(msg)
        if notes is not None:
            notes.append(msg)
        campaign = CampaignResult(engine="foundry-invariant", raw_stdout=output[-_MAX_LOG_CHARS:])
        campaign.elapsed_seconds = elapsed
        return campaign, []

    findings, campaign = parse_forge_output(
        output,
        invariants,
        contract_path=contract_path,
        contract_name=contract_name,
        target_label=label,
    )
    campaign.elapsed_seconds = elapsed
    if campaign.skipped:
        return campaign, []
    if findings:
        LOGGER.warning(
            "invariant fuzzing broke %d invariant(s) for %s", len(findings), label
        )
    else:
        LOGGER.info("invariant fuzzing clean for %s (%.1fs)", label, elapsed)
    if notes is not None and not campaign.compile_ok and not campaign.clean:
        notes.append(
            f"forge campaign for {label} did not compile; see logs. "
            "No invariant verdict either way."
        )
    return campaign, findings


# ---------------------------------------------------------------------------
# Optional echidna fallback (only when the binary is already installed)
# ---------------------------------------------------------------------------


def run_echidna_fallback(
    project_dir: Path,
    contract_name: str,
    config: Mapping[str, Any] | None,
    *,
    contract_path: str = "",
    target_label: str = "",
    timeout: int = 180,
) -> list[Finding]:
    """Best-effort echidna assertion-mode run over the rendered project.

    Only runs when an ``echidna`` binary is already on PATH; never installs
    anything. Flag conventions mirror :mod:`web3guard.discovery.echidna_engine`.
    """
    echidna = shutil.which("echidna")
    if not echidna:
        return []
    src = project_dir / f"src/{contract_name}.sol"
    if not src.exists():
        return []
    out_file = project_dir / "echidna_report.json"
    cmd = [
        echidna, str(src),
        "--contract", contract_name,
        "--format", "json",
        "--output", str(out_file),
        "--test-limit", "10000",
        "--seq-len", "50",
    ]
    try:
        _rc, _stdout, _stderr = run_sandboxed(
            cmd, cwd=project_dir, timeout=min(timeout, 180),
        )
    except (FileNotFoundError, RuntimeError) as exc:
        LOGGER.info("echidna fallback failed (%s); skipping", exc)
        return []
    if not out_file.exists():
        return []
    try:
        data = json.loads(out_file.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    findings: list[Finding] = []
    for issue in data.get("issues", []) or []:
        tx_seq = issue.get("tx_seq", [])
        poc = "# Echidna assertion-mode counterexample\n" + "\n".join(
            f"  {i+1}. {tx}" for i, tx in enumerate(tx_seq)
        )
        findings.append(
            Finding(
                target=target_label or contract_name,
                language="solidity",
                file=contract_path,
                function=str(issue.get("function", "") or ""),
                category="assertion-failure",
                severity="HIGH",
                confidence=0.8,
                description=f"Echidna assertion failure: {issue.get('bug', '')}"[:2000],
                status="POTENTIAL",
                poc_code=poc,
                exploit_log=json.dumps(issue)[:_MAX_LOG_CHARS],
                fingerprint="echidna-" + hashlib.sha256(
                    json.dumps(issue, sort_keys=True).encode()
                ).hexdigest()[:16],
                tool_consensus=["echidna"],
                dynamically_confirmed=True,
                metadata={"engine": "echidna", "invariant_source": "assertion-mode"},
            )
        )
    return findings

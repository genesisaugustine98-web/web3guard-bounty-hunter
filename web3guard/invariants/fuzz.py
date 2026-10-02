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
import signal
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from web3guard.invariants.harness import write_project
from web3guard.invariants.models import CampaignResult, FuzzBounds, Invariant
from web3guard.scanner import Finding
from web3guard.security.sandbox_guard import SandboxPolicy, run_sandboxed

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

#: Fix C (weakness-hunt round, target 3): the sandbox truncates campaign
#: stdout/stderr at 8 KiB (head+tail), which used to destroy the
#: human-readable [FAIL] blocks sitting in the middle of the output while
#: the machine-readable JSON failure events at the END of stderr survived.
#: Campaign output gets a higher truncation floor so the [FAIL] blocks and
#: their call sequences usually survive intact too. The JSON events remain
#: the primary (truncation-proof) signal regardless.
_CAMPAIGN_OUTPUT_CAP_BYTES = 65536

#: Lines worth surfacing when a campaign fails to compile (weakness-hunt
#: round, target 2: silence about compile failures is the worst failure
#: mode — these lines make the INCONCLUSIVE verdict specific).
_COMPILE_ERROR_LINE_RE = re.compile(
    r"(?i)^.*\b(error(\s*\(\d+\))?|parsererror|declarationerror|typeerror|"
    r"compiler run failed)\b.*$"
)


def extract_compile_errors(output: str, *, limit: int = 5) -> list[str]:
    """Pull the most informative compiler-error lines out of forge output."""
    errors: list[str] = []
    for line in output.splitlines():
        text = line.strip()
        if len(text) > 220:
            text = text[:220] + "…"
        if _COMPILE_ERROR_LINE_RE.match(text):
            if text not in errors:
                errors.append(text)
        if len(errors) >= limit:
            break
    return errors


# ---------------------------------------------------------------------------
# resource-exhaustion verdicts (Fix D)
# ---------------------------------------------------------------------------
# A campaign that dies by signal (SIGKILL/OOM -> exit 137 in shell
# convention, -9 in Python's Popen convention) or by the wall-clock timeout
# must NEVER be labeled "did not compile". classify_process_kill() names the
# cause; runners turn it into a RESOURCE_EXHAUSTED verdict with the
# signal/timeout named. "Did not compile" requires actual compiler-failure
# evidence (see extract_compile_errors) — provable or absent.

#: Shell exit-code convention for signal deaths: 128 + signo.
_SHELL_SIGNAL_EXIT = {128 + 9: "SIGKILL", 128 + 15: "SIGTERM"}

#: stderr markers left behind by the OOM killer / a dying allocator.
_OOM_MARKERS = (
    "out of memory",
    "memory exhausted",
    "cannot allocate memory",
    "killed process",
)


def classify_process_kill(
    rc: int | None,
    stdout: str | None = "",
    stderr: str | None = "",
) -> str | None:
    """Name the resource-exhaustion cause when a campaign process died badly.

    Returns a human-readable cause (e.g. ``"SIGKILL (shell exit 137) —
    likely killed by the OOM killer or the sandbox memory ceiling"``) or
    ``None`` when the exit looks unrelated to resource exhaustion (normal
    exits, nonzero-but-parsed forge failures, and the 124 timeout which the
    runners handle with their own message).
    """
    if rc is None or rc == 124:
        return None
    if rc == 0:
        return None
    detail: str | None = None
    if rc < 0:
        # Python's Popen convention: negative == killed by signal -rc.
        signo = -rc
        try:
            name = signal.Signals(signo).name
        except ValueError:
            name = f"SIG{signo}"
        detail = f"{name} (killed by signal {signo})"
        if signo == signal.SIGKILL:
            detail += (
                " — likely the OOM killer or the sandbox memory ceiling "
                "(shells report this as exit 137)"
            )
        elif signo == signal.SIGXCPU:
            detail += " — CPU time limit (RLIMIT_CPU) hit"
        elif signo == signal.SIGXFSZ:
            detail += " — file-size limit (RLIMIT_FSIZE) hit"
    elif rc in _SHELL_SIGNAL_EXIT:
        # Some launchers report 128+signo instead of Python's negative rc.
        name = _SHELL_SIGNAL_EXIT[rc]
        detail = f"{name} (shell exit {rc})"
        if rc == 137:
            detail += " — likely the OOM killer or the sandbox memory ceiling"
    if detail is None:
        # No signal evidence: only OOM-marker text can still implicate
        # resource exhaustion (e.g. the allocator died but the rc is odd).
        haystack = f"{stderr or ''}\n{stdout or ''}".lower()
        if any(marker in haystack for marker in _OOM_MARKERS):
            detail = (
                "process output reports memory exhaustion "
                f"(exit code {rc}) — likely OOM-killed"
            )
    return detail


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


def parse_forge_json_events(text: str) -> list[dict[str, Any]]:
    """Extract forge's NDJSON invariant-failure events from campaign output.

    Forge (1.x) prints one JSON object per line on stderr for every
    invariant it breaks, even in plain text mode (no ``--json`` flag)::
        {"timestamp":...,"event":"failure","invariant":"invariant_foo",
         "target":"test/Invariant.t.sol:InvariantTest","reason":"..."}

    These events are the truncation-proof PRIMARY signal (Fix C): they are
    emitted at the very END of stderr, so they survive the sandbox's
    head+tail output truncation even when the human-readable ``[FAIL]``
    block in the middle of stdout is destroyed. A named invariant failure
    here is a machine-checked catch — forge only emits the event after
    fuzzing actually found a violating call sequence. Rules that are false
    at deployment produce ``failed to set up invariant testing
    environment`` and NO failure event (verified against forge
    1.6.0-nightly), so an event can never be a false-at-deployment
    artifact.
    """
    events: list[dict[str, Any]] = []
    if not text:
        return events
    for line in text.splitlines():
        s = line.strip()
        # Event lines are tiny (~200 bytes). Skip anything huge without
        # attempting a parse (e.g. a --json suite blob is one giant line).
        if len(s) < 2 or len(s) > 8192 or not s.startswith("{"):
            continue
        if '"event"' not in s or '"invariant"' not in s:
            continue
        try:
            obj = json.loads(s)
        except (json.JSONDecodeError, ValueError):
            continue
        if (
            isinstance(obj, dict)
            and obj.get("event") == "failure"
            and isinstance(obj.get("invariant"), str)
            and obj["invariant"]
        ):
            events.append(obj)
    return events


_POOL_PUSH_RE = re.compile(r"wgSenderPool\.push\(([^;]+)\);")
_UINT160_RE = re.compile(r"address\(uint160\((0x[0-9a-fA-F]+|\d+)\)\)")
_PASSTHROUGH_RE = re.compile(r"function (\w+)\([^)]*uint256 _wgSender\)")
_STEP_CALLDATA_RE = re.compile(r"calldata=(\w+)\(")
_STEP_ARGS_RE = re.compile(r"args=\[(.*)\]\s*$")


def _extract_sender_pool(test_source: str) -> list[str]:
    """Extract the handler's sender pool in push order.

    The ghost/attack handler resolves a fuzzer-chosen sender seed via
    ``wgSenderPool[seed % len]`` and pranks as that address — so forge's
    ``sender=`` field shows the outer EOA, NOT the address the target
    actually saw. Resolving the seed through the pool (rendered into
    ``test/Invariant.t.sol``) reveals the true caller for PoC honesty.
    ``address(uint160(N))`` entries become lowercase hex; anything else
    (``address(this)``, contract variables) is kept verbatim as a marker.
    """
    pool: list[str] = []
    for m in _POOL_PUSH_RE.finditer(test_source or ""):
        expr = m.group(1).strip()
        um = _UINT160_RE.fullmatch(expr)
        if um:
            raw = um.group(1)
            pool.append("0x" + format(int(raw, 16 if raw.startswith("0x") else 10), "040x"))
        else:
            pool.append(expr)
    return pool


def _extract_passthrough_names(test_source: str) -> set[str]:
    """Names of handler functions taking a trailing sender seed.

    Passthroughs (one per target function, plus a ``uint256 _wgSender``
    seed) pick their caller from the sender pool; only their steps can
    have the seed resolved.
    """
    return set(_PASSTHROUGH_RE.findall(test_source or ""))


def _annotate_step_sender(
    step: str, pool: list[str], passthroughs: set[str]
) -> str:
    """Append the resolved on-chain sender to a PoC step, when knowable.

    A passthrough step like ``calldata=mint(address,uint256,uint256)
    args=[to, amt, 129157760]`` pranks as ``pool[seed % len(pool)]`` —
    the address the TARGET saw as ``msg.sender``. Without this, the PoC
    shows forge's outer EOA (which would revert) and hides the real
    caller, e.g. a mined hardcoded role address. Unresolvable steps are
    returned unchanged.
    """
    if not pool or not passthroughs:
        return step
    cm = _STEP_CALLDATA_RE.search(step)
    if not cm or cm.group(1) not in passthroughs:
        return step
    am = _STEP_ARGS_RE.search(step)
    if not am:
        return step
    args = [a.strip() for a in am.group(1).split(",")]
    if not args:
        return step
    seed_txt = args[-1].split()[0].strip("[]")
    try:
        seed = int(seed_txt, 16 if seed_txt.startswith("0x") else 10)
    except ValueError:
        return step
    resolved = pool[seed % len(pool)]
    return f"{step} [target saw sender {resolved}]"


def _recover_truncated_sequences(
    output: str, wanted: set[str]
) -> dict[str, list[str]]:
    """Recover call sequences whose ``[FAIL]`` header was truncated away.

    When the sandbox truncates campaign output mid-table, the ``[FAIL:
    <reason>]`` header line is destroyed but the per-test ``[Sequence]``
    steps and the trailing `` invariant_foo() (runs: ...)`` line usually
    survive in the tail. For each wanted invariant, find its trailing
    runs-line and walk BACKWARD collecting ``sender=``/``calldata=`` steps
    until a blank line, another FAIL block, the suite summary, or a JSON
    event line. The lookback is bounded so a pathological log cannot pin
    the scanner.
    """
    found: dict[str, list[str]] = {}
    if not wanted:
        return found
    lines = output.splitlines()
    for idx, line in enumerate(lines):
        m = _FAIL_TRAILING_RE.match(line)
        if not m or m.group(1) not in wanted or m.group(1) in found:
            continue
        steps: list[str] = []
        for back in range(idx - 1, max(idx - 121, -1), -1):
            prev = lines[back]
            if (
                not prev.strip()
                or "[FAIL" in prev
                or _SUITE_RE.search(prev)
                or prev.lstrip().startswith('{"timestamp"')
                or _FAIL_TRAILING_RE.match(prev)
            ):
                break
            s = prev.strip()
            if "sender=" in s and "calldata=" in s and s not in steps:
                steps.append(s)
        if steps:
            steps.reverse()
            found[m.group(1)] = steps
    return found


def parse_forge_output(
    output: str,
    invariants: list[Invariant],
    *,
    contract_path: str = "",
    contract_name: str = "Target",
    target_label: str = "",
    forge_rc: int | None = None,
    test_source: str = "",
) -> tuple[list[Finding], CampaignResult]:
    """Turn ``forge test`` output into findings + a campaign summary.

    Signal priority (Fix C):
    1. forge's NDJSON invariant-failure events
       (:func:`parse_forge_json_events`) — the truncation-proof primary
       signal; a named invariant failure here is a machine-checked catch
       regardless of what the truncated text shows;
    2. the human-readable ``[FAIL]`` text blocks (fallback);
    3. a clean ``Suite result: ok`` line — or forge's own exit code 0,
       which is ground truth that the campaign compiled and passed even
       when the suite line was truncated away.

    ``forge_rc`` is forge's process exit code when known: 0 means the
    campaign compiled and every test passed.
    """
    campaign = CampaignResult(engine="foundry-invariant")
    by_fn = {_sanitized_invariant_fn(inv.id): inv for inv in invariants}

    # Sender-pool resolution for PoC honesty: the handler pranks as
    # pool[seed % len], so forge's sender= field hides the real caller.
    # Resolving the seed reveals e.g. a mined hardcoded role address.
    sender_pool = _extract_sender_pool(test_source)
    passthrough_names = _extract_passthrough_names(test_source)

    suite = _SUITE_RE.search(output)
    runs_m = _RUNS_RE.search(output)
    if runs_m:
        campaign.runs = int(runs_m.group(1))
        campaign.calls = int(runs_m.group(2))
        campaign.reverts = int(runs_m.group(3))
    campaign.raw_stdout = output[-_MAX_LOG_CHARS:]

    # --- Primary signal (Fix C): forge's JSON failure events. ---
    # A named invariant failure in forge's own event stream is a
    # machine-checked catch regardless of what the (possibly truncated)
    # human-readable text shows. This mirrors the old text behavior of
    # reporting EVERY named failure: the harness auto-adds invariants
    # (e.g. invariant_attacker_no_profit) that are not in the caller's
    # list, and those are real catches too (unknown invariants get their
    # id/bug_class derived from the function name, as before).
    events = parse_forge_json_events(output)
    if events:
        return _findings_from_json_events(
            events,
            output,
            by_fn,
            campaign,
            contract_path=contract_path,
            contract_name=contract_name,
            target_label=target_label,
            sender_pool=sender_pool,
            passthrough_names=passthrough_names,
        )

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
        elif forge_rc == 0:
            # Fix C: forge's own exit code is ground truth — 0 means the
            # campaign compiled and every test passed, even when the
            # "Suite result: ok" line was truncated away. Without this, a
            # clean-but-truncated run was mislabeled "did not compile".
            campaign.compile_ok = True
            campaign.clean = True
            LOGGER.info(
                "forge exited 0 for %s; suite line truncated away, "
                "marking clean",
                target_label or contract_name,
            )
        else:
            LOGGER.warning(
                "forge exited without a parseable suite result for %s",
                target_label or contract_name,
            )
        return [], campaign

    campaign.compile_ok = True
    findings = _build_invariant_findings(
        by_inv,
        by_fn,
        campaign,
        contract_path=contract_path,
        contract_name=contract_name,
        target_label=target_label,
        output=output,
        repeats={fn: sum(1 for b in named if b["invariant"] == fn) for fn in by_inv},
        sender_pool=sender_pool,
        passthrough_names=passthrough_names,
    )
    return findings, campaign


def _findings_from_json_events(
    events: list[dict[str, Any]],
    output: str,
    by_fn: dict[str, Invariant],
    campaign: CampaignResult,
    *,
    contract_path: str,
    contract_name: str,
    target_label: str,
    sender_pool: list[str] | None = None,
    passthrough_names: set[str] | None = None,
) -> tuple[list[Finding], CampaignResult]:
    """Build findings from forge's NDJSON failure events (Fix C primary).

    Every event names an invariant forge itself broke while fuzzing — a
    machine-checked catch regardless of what the (possibly truncated)
    human-readable text shows. Call sequences come from the surviving
    text blocks when intact, else from
    :func:`_recover_truncated_sequences` (the ``[FAIL]`` header may be
    gone while the steps and trailing runs-line survive in the tail).

    Like the legacy text path, EVERY named failure becomes a finding —
    including harness-auto-added invariants (e.g.
    ``invariant_attacker_no_profit``) that are not in the caller's
    invariant list; their metadata is derived from the function name.
    """
    # Sequences from intact [FAIL] blocks first (existing text extraction).
    by_inv: dict[str, list[str]] = {}
    for b in _extract_failure_blocks(output):
        fn = b["invariant"]
        if isinstance(fn, str) and fn:
            seq = by_inv.setdefault(fn, [])
            for step in b["sequence"]:
                if step not in seq:
                    seq.append(step)
    # Then recover sequences whose [FAIL] header was truncated away.
    missing = {str(e["invariant"]) for e in events} - set(by_inv)
    for fn, steps in _recover_truncated_sequences(output, missing).items():
        by_inv.setdefault(fn, steps)
    # Events with no recoverable sequence still count: the event itself is
    # forge's machine-checked verdict (see parse_forge_json_events).
    for e in events:
        fn = str(e["invariant"])
        by_inv.setdefault(fn, [])

    campaign.compile_ok = True
    campaign.clean = False
    event_reasons = {str(e["invariant"]): str(e.get("reason") or "") for e in events}
    # Embed only the STABLE event fields in the PoC: the "timestamp" field
    # differs on every run and would make the PoC non-reproducible for a
    # fixed fuzz seed (see test_e2e_campaign_is_reproducible_for_fixed_seed).
    event_lines = {
        str(e["invariant"]): json.dumps(
            {
                "event": e.get("event"),
                "invariant": e.get("invariant"),
                "reason": e.get("reason") or "",
                "target": e.get("target") or "",
            },
            sort_keys=True,
        )
        for e in events
    }
    findings = _build_invariant_findings(
        by_inv,
        by_fn,
        campaign,
        contract_path=contract_path,
        contract_name=contract_name,
        target_label=target_label,
        output=output,
        repeats={fn: 1 for fn in by_inv},
        event_reasons=event_reasons,
        event_lines=event_lines,
        sender_pool=sender_pool,
        passthrough_names=passthrough_names,
    )
    return findings, campaign


def _build_invariant_findings(
    by_inv: dict[str, list[str]],
    by_fn: dict[str, Invariant],
    campaign: CampaignResult,
    *,
    contract_path: str,
    contract_name: str,
    target_label: str,
    output: str,
    repeats: dict[str, int],
    event_reasons: dict[str, str] | None = None,
    event_lines: dict[str, str] | None = None,
    sender_pool: list[str] | None = None,
    passthrough_names: set[str] | None = None,
) -> list[Finding]:
    """Build one :class:`Finding` per broken invariant.

    ``event_reasons``/``event_lines`` carry forge's JSON failure-event
    data when the finding came from the truncation-proof event signal
    (Fix C); otherwise the finding came from the text blocks.
    """
    event_reasons = event_reasons or {}
    event_lines = event_lines or {}
    pool = sender_pool or []
    pthroughs = passthrough_names or set()
    findings: list[Finding] = []
    for fn, sequence in by_inv.items():
        inv = by_fn.get(fn)
        inv_id = inv.id if inv else fn[len("invariant_") :]
        bug_class = inv.bug_class if inv else "other"
        severity = inv.severity if inv else "HIGH"
        statement = inv.statement if inv else "violated invariant"

        # Confidence from reproducibility: a captured call sequence raises
        # it, and seeing the same invariant fail in both the per-test block
        # and the "Failing tests" summary raises it further.
        confidence = 0.80
        if sequence:
            confidence += 0.05
        if repeats.get(fn, 1) > 1:
            confidence += 0.05
        confidence = min(confidence, 0.95)

        # PoC honesty: resolve passthrough sender seeds through the
        # handler's pool so the PoC shows the address the target actually
        # saw (e.g. a mined hardcoded role), not forge's outer EOA.
        shown = [_annotate_step_sender(s, pool, pthroughs) for s in sequence]
        seq_text = "\n".join(f"  {i + 1}. {step}" for i, step in enumerate(shown))
        event_note = ""
        if fn in event_lines:
            event_note = (
                "# Forge's own JSON event stream reports this invariant "
                "violated (truncation-proof machine verdict):\n"
                f"#   {event_lines[fn]}\n"
            )
            if event_reasons.get(fn):
                event_note += f"#   forge reason: {event_reasons[fn]}\n"
        if seq_text:
            seq_block = seq_text
        elif fn in event_lines:
            seq_block = (
                "  (call sequence truncated from forge output; the JSON "
                "failure event above is forge's machine-checked verdict)"
            )
        else:
            seq_block = "  (forge did not print a call sequence)"
        poc = (
            "# Forge invariant counterexample (machine-checked).\n"
            f"# Reproduce: run this pipeline against {target_label or contract_name}\n"
            f"# Failing invariant: {fn}\n"
            f"#   {inv_id} [{bug_class}]: {statement}\n"
            f"{event_note}"
            "# Call sequence that breaks it:\n"
            f"{seq_block}\n"
        )
        fingerprint = hashlib.sha256(f"{inv_id}:{sequence}".encode()).hexdigest()[:16]
        metadata = {
            "invariant_id": inv_id,
            "bug_class": bug_class,
            "engine": "foundry-invariant",
            "fuzz_runs": campaign.runs,
            "fuzz_calls": campaign.calls,
            "invariant_source": inv.source if inv else "unknown",
        }
        if fn in event_lines:
            # Fix C: record which signal produced this finding — the
            # truncation-proof JSON event, not the text blocks.
            metadata["proof_signal"] = "forge-json-event"
        findings.append(
            Finding(
                target=target_label or contract_name,
                language="solidity",
                file=contract_path,
                function=fn,
                category="invariant-violation",
                severity=severity,
                confidence=confidence,
                description=(f"Foundry invariant fuzzing broke '{inv_id}': {statement}"),
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
                metadata=metadata,
            )
        )
    return findings


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
        "starting invariant fuzz campaign for %s: runs=%d depth=%d timeout=%ds seed=%d (forge=%s)",
        label,
        bounds.runs,
        bounds.depth,
        bounds.timeout_seconds,
        bounds.seed,
        forge,
    )
    # --fuzz-seed: the fixed default campaign seed (FuzzBounds.seed, 1337
    # unless overridden). Verified against this Foundry build: campaigns
    # reproduce bit-identically across reruns for a fixed seed.
    cmd = [
        forge,
        "test",
        "--match-contract",
        "InvariantTest",
        "-vv",
        "--fuzz-seed",
        str(bounds.seed),
    ]
    started = time.monotonic()
    # Fix C (secondary hardening): campaign output used to be truncated at
    # the sandbox default of 8 KiB, which destroyed the human-readable
    # [FAIL] blocks in the middle of long traces. Raise the truncation
    # floor for campaign output only — everything else about the sandbox
    # policy (resource limits, env filtering, privilege drop) is
    # unchanged. The JSON failure events are the primary signal and
    # survive any truncation; this keeps their call sequences readable.
    campaign_policy = SandboxPolicy(
        max_revert_reason_bytes=_CAMPAIGN_OUTPUT_CAP_BYTES
    )
    try:
        rc, stdout, stderr = run_sandboxed(
            cmd,
            cwd=project_dir,
            timeout=bounds.timeout_seconds,
            policy=campaign_policy,
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
        # Fix D: a timeout is resource exhaustion (the time budget gave
        # out), never "did not compile".
        detail = (
            f"timeout after {bounds.timeout_seconds}s — the campaign "
            "wall-clock budget was exhausted before forge finished"
        )
        msg = (
            f"forge campaign for {label} RESOURCE_EXHAUSTED ({detail}); "
            "no invariant verdict — this target was NOT checked."
        )
        LOGGER.warning(msg)
        if notes is not None:
            notes.append(msg)
        campaign = CampaignResult(
            engine="foundry-invariant",
            raw_stdout=output[-_MAX_LOG_CHARS:],
            resource_exhausted=True,
            resource_detail=detail,
        )
        campaign.elapsed_seconds = elapsed
        return campaign, []

    kill_detail = classify_process_kill(rc, stdout, stderr)
    if kill_detail is not None:
        # Fix D: a signal/OOM kill gets its own loud verdict — never the
        # "did not compile" label.
        msg = (
            f"forge campaign for {label} RESOURCE_EXHAUSTED ({kill_detail}); "
            "no invariant verdict — this target was NOT checked."
        )
        LOGGER.warning(msg)
        if notes is not None:
            notes.append(msg)
        campaign = CampaignResult(
            engine="foundry-invariant",
            raw_stdout=output[-_MAX_LOG_CHARS:],
            resource_exhausted=True,
            resource_detail=kill_detail,
        )
        campaign.elapsed_seconds = elapsed
        return campaign, []

    findings, campaign = parse_forge_output(
        output,
        invariants,
        contract_path=contract_path,
        contract_name=contract_name,
        target_label=label,
        forge_rc=rc,
        test_source=files.get("test/Invariant.t.sol", ""),
    )
    campaign.elapsed_seconds = elapsed
    _record_strategy_feedback(files, bounds, findings, campaign)
    if campaign.skipped:
        return campaign, []
    if findings:
        LOGGER.warning("invariant fuzzing broke %d invariant(s) for %s", len(findings), label)
    else:
        LOGGER.info("invariant fuzzing clean for %s (%.1fs)", label, elapsed)
    if notes is not None and not campaign.compile_ok and not campaign.clean:
        # Fix D: "did not compile" requires actual compiler-failure
        # evidence in the output — provable or absent. A campaign that
        # died by signal/timeout already returned above with its own
        # RESOURCE_EXHAUSTED verdict; anything else unparseable gets an
        # honest unknown-cause note here and in the pipeline verdict.
        if campaign.resource_exhausted or campaign.skipped:
            pass
        elif extract_compile_errors(output):
            notes.append(
                f"forge campaign for {label} did not compile; see logs. "
                "No invariant verdict either way."
            )
        else:
            notes.append(
                f"forge campaign for {label} ended with no parseable suite "
                "result and no compiler errors in the output (cause "
                "unknown); no invariant verdict either way."
            )
    return campaign, findings


def _extract_strategy_markers(
    files: Mapping[str, str],
) -> tuple[list[str], str]:
    """Read the WG-STRATEGIES / WG-PRIMARY-STRATEGY markers from the rendered test.

    The attack harness stamps its strategy plan into the test file header;
    the plain harness has no markers (returns empty).
    """
    strategies: list[str] = []
    primary = ""
    test_src = files.get("test/Invariant.t.sol", "")
    for line in test_src.splitlines():
        stripped = line.strip()
        if stripped.startswith("// WG-STRATEGIES:"):
            strategies = [
                part.strip() for part in stripped.split(":", 1)[1].split(",") if part.strip()
            ]
        elif stripped.startswith("// WG-PRIMARY-STRATEGY:"):
            primary = stripped.split(":", 1)[1].strip()
    return strategies, primary


def _record_strategy_feedback(
    files: Mapping[str, str],
    bounds: FuzzBounds,
    findings: list[Finding],
    campaign: CampaignResult,
) -> None:
    """Fold this campaign's outcome into the adaptive strategy selector.

    Phase 1: the bandit learns which strategies produce evidence. Findings
    attribute credit to the strategies whose handler actions appear in the
    PoC call sequence; clean campaigns give every used strategy a small
    participation reward. Persisted to the strategy state file so the next
    campaign's render-time pick adapts. Never breaks a campaign.
    """
    try:
        campaign.campaign_seed = bounds.seed
        strategies_used, primary = _extract_strategy_markers(files)
        if not strategies_used and primary:
            strategies_used = [primary]
        campaign.strategies_used = strategies_used
        if not strategies_used:
            return  # plain harness: nothing to learn
        from web3guard.invariants import strategies as _strategies

        _strategies.record_campaign_outcome(
            _strategies.resolve_state_path(),
            strategies_used,
            [f.poc_code or "" for f in findings],
            epsilon=bounds.strategy_epsilon,
            seed=bounds.seed,
        )
    except Exception:  # bookkeeping must never break a campaign
        LOGGER.debug("strategy feedback failed (non-fatal)", exc_info=True)


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
        echidna,
        str(src),
        "--contract",
        contract_name,
        "--format",
        "json",
        "--output",
        str(out_file),
        "--test-limit",
        "10000",
        "--seq-len",
        "50",
    ]
    try:
        _rc, _stdout, _stderr = run_sandboxed(
            cmd,
            cwd=project_dir,
            timeout=min(timeout, 180),
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
            f"  {i + 1}. {tx}" for i, tx in enumerate(tx_seq)
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
                fingerprint="echidna-"
                + hashlib.sha256(json.dumps(issue, sort_keys=True).encode()).hexdigest()[:16],
                tool_consensus=["echidna"],
                dynamically_confirmed=True,
                metadata={"engine": "echidna", "invariant_source": "assertion-mode"},
            )
        )
    return findings

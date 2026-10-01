"""Vyper invariant harness (Phase 6).

Renders a self-contained invariant campaign for Vyper contracts:

- ``contract/<Name>.vy`` — the target source, verbatim.
- ``run_invariants.py`` — a driver (stdlib + titanoboa only) that compiles
  the target once, redeploys it fresh for every run, executes randomized
  call sequences (random senders via ``boa.env.prank``, random args per ABI
  type), and evaluates every invariant after each call. Violations are
  printed as JSON lines; a final ``summary`` line reports
  runs/calls/reverts/timing.

Invariant assertions are written in a small Python-over-titanoboa dialect:
a boolean expression over ``target`` where ``target.<getter>()`` calls into
the deployed contract (e.g. ``target.totalSupply() == target.totalAssets()``).
The driver translates residual Solidity-isms (``&&``/``||``/``!``,
``true``/``false``, ``address(0)``) to Python before compiling each
assertion; an assertion that does not compile is reported as uncheckable,
never as a finding.

The module is unit-testable WITHOUT titanoboa: rendering and assertion
translation are pure string building. Execution needs the persistent
titanoboa venv at ``~/workspace/tools/vyper-invariants`` (see
:mod:`web3guard.invariants.fuzz_vyper`).
"""

from __future__ import annotations

import json
import logging
import re

from web3guard.invariants.harness import register_renderer
from web3guard.invariants.models import FuzzBounds, Invariant

LOGGER = logging.getLogger("web3guard.invariants.vyper_harness")

#: Fixed seed so campaigns are reproducible run-to-run.
DEFAULT_SEED = 20261001

#: Cap on recorded violations per campaign (bounds output size).
MAX_VIOLATIONS = 25


# ---------------------------------------------------------------------------
# Assertion translation (Solidity-isms -> Python)
# ---------------------------------------------------------------------------

_ZERO_ADDRESS = "0x" + "0" * 40


def translate_assertion_to_python(expr: str) -> str:
    """Translate a template/LLM assertion into the driver's Python dialect.

    Handles the operators Solidity and Python disagree on (``&&``/``||``/
    ``!``, ``true``/``false``) and ``address(0)``. Everything else passes
    through unchanged — the driver compiles the result with ``compile()``
    and treats a syntax error as "uncheckable", never as a finding.
    """
    e = expr.replace("&&", " and ").replace("||", " or ")
    e = re.sub(r"!(?!=)", " not ", e)
    e = re.sub(r"\btrue\b", "True", e)
    e = re.sub(r"\bfalse\b", "False", e)
    e = e.replace("address(0)", "'" + _ZERO_ADDRESS + "'")
    return e


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

_DRIVER_TEMPLATE = '''\
#!/usr/bin/env python3
"""Web3Guard-generated Vyper invariant campaign (Phase 6).

Randomized call sequences against the target contract via titanoboa;
every invariant is evaluated after each call. Machine-generated file:
the invariants below were produced by web3guard's synthesis step.
Violations print as JSON lines; the last line is always a "summary".
"""
import json
import random
import re
import sys
import time

import boa
from vyper import compile_code

CONTRACT_FILE = "__CONTRACT_FILE__"
RUNS = __RUNS__
DEPTH = __DEPTH__
SEED = __SEED__
MAX_VIOLATIONS = __MAX_VIOLATIONS__

INVARIANTS = json.loads('__INVARIANTS_JSON__')

ZERO_ADDRESS = "0x" + "0" * 40
_UINT_RE = re.compile(r"^uint(\\d+)$")
_INT_RE = re.compile(r"^int(\\d+)$")


def translate_assertion(expr):
    e = expr.replace("&&", " and ").replace("||", " or ")
    e = re.sub(r"!(?!=)", " not ", e)
    e = re.sub(r"\\btrue\\b", "True", e)
    e = re.sub(r"\\bfalse\\b", "False", e)
    e = e.replace("address(0)", "'" + ZERO_ADDRESS + "'")
    return e


class UnsupportedType(Exception):
    pass


def is_supported_type(typ):
    return bool(
        _UINT_RE.match(typ)
        or _INT_RE.match(typ)
        or typ in ("bool", "address", "bytes32")
    )


def gen_arg(rng, typ):
    m = _UINT_RE.match(typ)
    if m:
        bits = int(m.group(1))
        return rng.choice(
            [0, 1, 2, (1 << bits) - 1,
             rng.getrandbits(min(bits, 32)), rng.getrandbits(bits)]
        )
    m = _INT_RE.match(typ)
    if m:
        bits = int(m.group(1))
        lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
        return rng.choice([0, 1, -1, lo, hi, rng.randint(lo, hi)])
    if typ == "bool":
        return rng.choice([True, False])
    if typ == "address":
        return rng.choice(
            [ZERO_ADDRESS, "0x%040x" % rng.getrandbits(160),
             "0x%040x" % rng.getrandbits(160)]
        )
    if typ == "bytes32":
        return rng.getrandbits(256).to_bytes(32, "big")
    raise UnsupportedType(typ)


def fmt_arg(a):
    if isinstance(a, bytes):
        return "0x" + a.hex()
    return repr(a)


def emit(obj):
    sys.stdout.write(json.dumps(obj) + "\\n")
    sys.stdout.flush()


def main():
    t0 = time.monotonic()
    notes = []
    violations = []
    done_ids = set()

    def summary(**kw):
        s = {
            "type": "summary",
            "runs": 0,
            "calls": 0,
            "reverts": 0,
            "violations": len(violations),
            "compile_ok": True,
            "clean": not violations,
            "elapsed_seconds": round(time.monotonic() - t0, 2),
            "notes": notes,
        }
        s.update(kw)
        return s

    # --- 1. compile -----------------------------------------------------
    try:
        with open(CONTRACT_FILE) as fh:
            src = fh.read()
        abi = compile_code(src, output_formats=["abi"])["abi"]
        deployer = boa.loads_partial(src)
    except Exception as exc:  # noqa: BLE001 - compile errors are data
        notes.append("vyper compile failed: %s" % str(exc)[:500])
        emit(summary(compile_ok=False, clean=False))
        return 0

    # --- 2. plan the campaign -------------------------------------------
    ctor_inputs = []
    for entry in abi:
        if entry.get("type") == "constructor":
            ctor_inputs = [i["type"] for i in entry.get("inputs", [])]
    fuzzable = []
    skipped_functions = []
    for entry in abi:
        if entry.get("type") != "function":
            continue
        name = entry.get("name", "")
        if name.startswith("_"):
            continue
        if entry.get("stateMutability") not in ("nonpayable", "payable"):
            continue  # view/pure: nothing to fuzz
        inputs = [i["type"] for i in entry.get("inputs", [])]
        if all(is_supported_type(t) for t in inputs):
            fuzzable.append({"name": name, "inputs": inputs})
        else:
            skipped_functions.append(name)
    if skipped_functions:
        notes.append(
            "functions not fuzzed (unsupported arg types): "
            + ", ".join(sorted(set(skipped_functions)))
        )
    if [t for t in ctor_inputs if not is_supported_type(t)]:
        notes.append(
            "constructor takes unsupported arg types; deployment may fail."
        )

    # --- 3. compile the invariant assertions -----------------------------
    checkable = []
    for inv in INVARIANTS:
        try:
            code = compile(
                translate_assertion(inv["assertion"]), "<invariant>", "eval"
            )
        except Exception as exc:  # noqa: BLE001 - uncheckable is honest data
            notes.append(
                "invariant '%s' is not a valid Python expression (%s); "
                "skipped, NOT treated as passing." % (inv["id"], exc)
            )
            continue
        checkable.append({"inv": inv, "code": code})
    if not checkable and not notes:
        notes.append("no checkable invariants; nothing to assert.")

    # --- 4. run ----------------------------------------------------------
    rng = random.Random(SEED)
    senders = ["0x%040x" % rng.getrandbits(160) for _ in range(4)]
    runs = 0
    calls = 0
    reverts = 0
    stop = False
    for _run in range(RUNS):
        if stop:
            break
        try:
            ctor_args = [gen_arg(rng, t) for t in ctor_inputs]
        except UnsupportedType as exc:
            notes.append("cannot build constructor args (%s); stopping." % exc)
            break
        deploy_sender = rng.choice(senders)
        try:
            with boa.env.prank(deploy_sender):
                contract = deployer.deploy(*ctor_args)
        except Exception as exc:  # noqa: BLE001 - deploy failures are data
            notes.append(
                "deployment failed on run %d (%s); stopping campaign."
                % (_run, str(exc)[:300])
            )
            break
        runs += 1
        seq = []
        for _step in range(DEPTH):
            if not fuzzable or stop:
                break
            fn = rng.choice(fuzzable)
            sender = rng.choice(senders)
            try:
                args = [gen_arg(rng, t) for t in fn["inputs"]]
            except UnsupportedType:
                continue
            label = "%s %s(%s)" % (
                sender[:10], fn["name"], ", ".join(fmt_arg(a) for a in args)
            )
            try:
                with boa.env.prank(sender):
                    getattr(contract, fn["name"])(*args)
            except boa.BoaError as exc:
                reverts += 1
                seq.append(label + " -> REVERT(%s)" % str(exc)[:120])
                continue
            except Exception as exc:  # noqa: BLE001 - unexpected; record
                notes.append(
                    "unexpected error calling %s: %s"
                    % (fn["name"], str(exc)[:200])
                )
                seq.append(label + " -> ERROR")
                continue
            calls += 1
            seq.append(label)
            for item in checkable:
                inv = item["inv"]
                if inv["id"] in done_ids:
                    continue
                try:
                    ok = eval(
                        item["code"], {"__builtins__": {}},
                        {"target": contract},
                    )
                except Exception as exc:  # noqa: BLE001
                    notes.append(
                        "invariant '%s' raised during evaluation (%s); "
                        "skipped from here on." % (inv["id"], str(exc)[:200])
                    )
                    done_ids.add(inv["id"])
                    continue
                if not ok:
                    done_ids.add(inv["id"])
                    violations.append({
                        "type": "violation",
                        "invariant_id": inv["id"],
                        "statement": inv["statement"],
                        "bug_class": inv.get("bug_class", "other"),
                        "severity": inv.get("severity", "HIGH"),
                        "run": _run,
                        "sequence": list(seq),
                    })
                    emit(violations[-1])
                    if len(violations) >= MAX_VIOLATIONS:
                        notes.append(
                            "violation cap (%d) reached; stopping."
                            % MAX_VIOLATIONS
                        )
                        stop = True
                        break
    emit(summary(runs=runs, calls=calls, reverts=reverts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def _sanitize_name(name: str) -> str:
    clean = re.sub(r"\W", "_", name)
    if clean and clean[0].isdigit():
        clean = "vy_" + clean
    return clean or "Target"


def render_vyper_project(
    contract_source: str,
    contract_name: str,
    invariants: list[Invariant],
    bounds: FuzzBounds,
) -> dict[str, str]:
    """Render a titanoboa invariant campaign as {relative_path: content}."""
    name = _sanitize_name(contract_name)
    invariants_json = json.dumps(
        [
            {
                "id": inv.id,
                "statement": inv.statement,
                "assertion": inv.assertion,
                "bug_class": inv.bug_class,
                "severity": inv.severity,
            }
            for inv in invariants
        ]
    )
    driver = (
        _DRIVER_TEMPLATE.replace("__CONTRACT_FILE__", f"contract/{name}.vy")
        .replace("__RUNS__", str(bounds.runs))
        .replace("__DEPTH__", str(bounds.depth))
        .replace("__SEED__", str(DEFAULT_SEED))
        .replace("__MAX_VIOLATIONS__", str(MAX_VIOLATIONS))
        .replace("__INVARIANTS_JSON__", invariants_json.replace("'", "\\'"))
    )
    return {
        f"contract/{name}.vy": contract_source,
        "run_invariants.py": driver,
    }


register_renderer("vyper", render_vyper_project)


__all__ = [
    "DEFAULT_SEED",
    "MAX_VIOLATIONS",
    "render_vyper_project",
    "translate_assertion_to_python",
]

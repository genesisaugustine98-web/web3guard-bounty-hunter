"""Foundry harness rendering (Phase 2, step 2).

Turns (contract source + invariants) into a self-contained Foundry project:

- ``src/<Contract>.sol`` — the target source, verbatim.
- ``test/Invariant.t.sol`` — deploys the target in ``setUp()`` and asserts
  each invariant in an ``invariant_*`` function. Foundry's invariant engine
  automatically targets every contract deployed in ``setUp()`` and fuzzes
  its public functions with random inputs and senders, so no hand-written
  handler is needed — and none is emitted (an uncalled handler would be
  dead, misleading code).
- ``foundry.toml`` — hardened (``ffi = false``, ``fs_permissions = []``)
  with the ``[invariant]`` profile wired to the campaign bounds.

The renderer is deliberately forge-std-free, so a campaign needs no
dependency downloads — only ``forge`` and a solc download on first run.

The module is unit-testable WITHOUT forge: rendering is pure string
building. A per-language renderer registry lets Phase 6 plug in
Move/Cairo/Clarity harnesses later.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Mapping
from pathlib import Path

from web3guard.invariants.models import FuzzBounds, Invariant

LOGGER = logging.getLogger("web3guard.invariants.harness")

# ---------------------------------------------------------------------------
# Source introspection (regex-based; good enough for harness generation)
# ---------------------------------------------------------------------------

_CONTRACT_RE = re.compile(r"^\s*contract\s+(\w+)", re.MULTILINE)
_PRAGMA_RE = re.compile(r"^\s*pragma\s+solidity\s+([^;]+);", re.MULTILINE)
_FUNC_RE = re.compile(
    r"function\s+(\w+)\s*\(([^)]*)\)\s*"
    r"((?:external|public|internal|private)\s*)?"
    r"((?:payable|view|pure)\s*)?",
)

# Primitive Solidity types the entry-point generator can fuzz.
_PRIMITIVE_RE = re.compile(
    r"^(uint(8|16|32|64|128|256)?|int(8|16|32|64|128|256)?|address|bool|bytes32)$"
)


def extract_contract_name(source: str) -> str:
    """Return the first concrete contract name, defaulting to "Target"."""
    m = _CONTRACT_RE.search(source)
    return m.group(1) if m else "Target"


def extract_pragma(source: str) -> str:
    """Return the source's pragma line, or a safe default."""
    m = _PRAGMA_RE.search(source)
    if m:
        return f"pragma solidity {m.group(1).strip()};"
    return "pragma solidity ^0.8.20;"


class FunctionSig:
    """A parsed function signature relevant to fuzz-entry generation."""

    def __init__(
        self,
        name: str,
        params: list[tuple[str, str]],
        mutability: str,
    ) -> None:
        self.name = name
        self.params = params            # (type, name) pairs
        self.mutability = mutability    # "payable" | "view" | "pure" | ""

    @property
    def state_changing(self) -> bool:
        return self.mutability not in ("view", "pure")

    @property
    def fuzzable(self) -> bool:
        """True when every parameter is a fuzzable primitive type."""
        if not self.state_changing:
            return False
        if self.name.startswith(("invariant", "entry_")):
            return False
        return all(_PRIMITIVE_RE.match(t) for t, _ in self.params)


def extract_functions(source: str) -> list[FunctionSig]:
    """Parse top-level function signatures out of Solidity source."""
    sigs: list[FunctionSig] = []
    for m in _FUNC_RE.finditer(source):
        name = m.group(1)
        if name in ("constructor",):
            continue
        raw_params = m.group(2).strip()
        params: list[tuple[str, str]] = []
        if raw_params:
            for i, part in enumerate(raw_params.split(",")):
                tokens = part.strip().split()
                if not tokens:
                    continue
                ptype = tokens[0]
                pname = tokens[1] if len(tokens) > 1 else f"p{i}"
                # strip data-location / calldata keywords leaking into the type
                ptype = ptype.replace("calldata", "").replace("memory", "").strip()
                params.append((ptype, re.sub(r"\W", "", pname) or f"p{i}"))
        mutability = (m.group(4) or "").strip()
        sigs.append(FunctionSig(name, params, mutability))
    return sigs


# ---------------------------------------------------------------------------
# Solidity renderer
# ---------------------------------------------------------------------------


def _sanitize_fn(name: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if clean and clean[0].isdigit():
        clean = "inv_" + clean
    return clean or "inv_unnamed"


def _render_invariant(inv: Invariant) -> str:
    fn = _sanitize_fn("invariant_" + inv.id)
    stmt = inv.statement.replace("*/", "* /").replace("\n", " ")
    assertion = " ".join(inv.assertion.split())
    return (
        f"    // {inv.id} [{inv.bug_class}, {inv.source}]: {stmt}\n"
        f"    function {fn}() public view {{\n"
        f"        assert({assertion});\n"
        f"    }}"
    )


def render_solidity_project(
    contract_source: str,
    contract_name: str,
    invariants: list[Invariant],
    bounds: FuzzBounds,
) -> dict[str, str]:
    """Render a complete Foundry project as {relative_path: content}.

    The test contract only deploys the target and asserts the invariants:
    Foundry's invariant engine automatically targets every contract
    deployed in ``setUp()`` and fuzzes its public functions, so no
    hand-written handler is needed (and none is emitted — dead handler
    code would never be called).
    """
    test_parts: list[str] = [
        "// SPDX-License-Identifier: MIT",
        extract_pragma(contract_source),
        "",
        "// Web3Guard-generated invariant harness (Phase 2).",
        "// Foundry's invariant engine automatically targets every contract",
        "// deployed in setUp() and fuzzes its public functions with random",
        "// inputs and senders; each invariant_* function below must hold",
        "// after every call sequence. No forge-std dependency is needed.",
        f'import "../src/{contract_name}.sol";',
        "",
        "contract InvariantTest {",
        f"    {contract_name} public target;",
        "",
        "    function setUp() public {",
        f"        target = new {contract_name}();",
        "    }",
        "",
    ]

    if invariants:
        test_parts.append("    // --- invariants under test ---")
        for inv in invariants:
            test_parts.append(_render_invariant(inv))
            test_parts.append("")
    else:
        test_parts.append("    // NOTE: no invariants applied; nothing to assert.")
        test_parts.append("")

    test_parts.append("}")
    test_src = "\n".join(test_parts) + "\n"

    foundry_toml = f"""\
# Web3Guard-generated foundry.toml (Phase 2 invariant harness).
# Generated by our renderer -- never by the LLM -- so it is trusted input.
# Hardened: no ffi, no filesystem access for the fuzzed code.
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
test = "test"
auto_detect_solc = true
ffi = false
fs_permissions = []

[invariant]
runs = {bounds.runs}
depth = {bounds.depth}
fail_on_revert = {"true" if bounds.fail_on_revert else "false"}
"""

    return {
        "foundry.toml": foundry_toml,
        f"src/{contract_name}.sol": contract_source,
        "test/Invariant.t.sol": test_src,
    }


# ---------------------------------------------------------------------------
# Renderer registry (Phase 6 plugs new languages in here)
# ---------------------------------------------------------------------------

Renderer = Callable[[str, str, list[Invariant], FuzzBounds], dict[str, str]]

_RENDERERS: dict[str, Renderer] = {}


def register_renderer(language: str, renderer: Renderer) -> None:
    """Register a harness renderer for a language (Phase 6 extension point)."""
    _RENDERERS[language.lower()] = renderer


register_renderer("solidity", render_solidity_project)


def render_project(
    language: str,
    contract_source: str,
    contract_name: str,
    invariants: list[Invariant],
    bounds: FuzzBounds,
) -> dict[str, str]:
    """Render a fuzz project for ``language`` via its registered renderer."""
    renderer = _RENDERERS.get(language.lower())
    if renderer is None:
        raise ValueError(
            f"no invariant harness renderer for language {language!r} "
            f"(registered: {sorted(_RENDERERS)})"
        )
    return renderer(contract_source, contract_name, invariants, bounds)


def write_project(project_dir: Path, files: Mapping[str, str]) -> None:
    """Write a rendered project to disk."""
    for rel, content in files.items():
        dest = project_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content)
    LOGGER.info("wrote invariant harness project to %s (%d files)", project_dir, len(files))

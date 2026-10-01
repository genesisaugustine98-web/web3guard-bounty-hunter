"""Invariant synthesis + fuzzing pipeline (Phase 2 of the Hunt Bigger Fish build).

The engine that catches business-logic bugs pattern matching can't see:
an LLM (when keys exist) drafts "must-always-hold" invariants, hand-written
templates always provide a keyless baseline, a Foundry project is rendered
from (contract + invariants), and a bounded ``forge test`` invariant
campaign tries to break them. Every violated invariant becomes a Finding
with a machine-checkable call sequence as its PoC.

Public entry point for phase 7::

    from web3guard.invariants import run_invariant_pipeline
    findings = run_invariant_pipeline(contract_path, config)
"""

from __future__ import annotations

from web3guard.invariants import cairo_harness as _cairo_harness  # noqa: F401
from web3guard.invariants import vyper_harness as _vyper_harness  # noqa: F401
from web3guard.invariants.fuzz import (
    FOUNDRY_BIN_DIR,
    discover_forge,
    parse_forge_output,
    run_echidna_fallback,
    run_fuzz_campaign,
)
from web3guard.invariants.fuzz_cairo import (
    discover_cairo_toolchain,
    parse_snforge_output,
    run_cairo_campaign,
)
from web3guard.invariants.fuzz_vyper import (
    discover_vyper_runner,
    parse_vyper_output,
    run_vyper_campaign,
)

# The two imports above are load-bearing: they run the modules'
# ``register_renderer("vyper"/"cairo", ...)`` calls, which is what makes
# ``render_project("vyper"/"cairo", ...)`` resolve for direct users of
# this package (the pipeline imports them too, belt and suspenders).
from web3guard.invariants.harness import (
    extract_contract_name,
    extract_functions,
    register_renderer,
    render_project,
    render_solidity_project,
    write_project,
)
from web3guard.invariants.models import (
    CampaignResult,
    FuzzBounds,
    Invariant,
    PipelineResult,
    SynthesisResult,
)
from web3guard.invariants.pipeline import (
    SUPPORTED_LANGUAGES,
    detect_language,
    run_invariant_pipeline,
    run_invariant_pipeline_full,
)
from web3guard.invariants.synthesize import (
    CAIRO_TEMPLATES,
    GENERIC_TEMPLATES,
    VYPER_TEMPLATES,
    synthesize_invariants,
    template_invariants,
)

__all__ = [
    "FOUNDRY_BIN_DIR",
    "CAIRO_TEMPLATES",
    "GENERIC_TEMPLATES",
    "VYPER_TEMPLATES",
    "SUPPORTED_LANGUAGES",
    "CampaignResult",
    "FuzzBounds",
    "Invariant",
    "PipelineResult",
    "SynthesisResult",
    "detect_language",
    "discover_cairo_toolchain",
    "discover_forge",
    "discover_vyper_runner",
    "extract_contract_name",
    "extract_functions",
    "parse_forge_output",
    "parse_snforge_output",
    "parse_vyper_output",
    "register_renderer",
    "render_project",
    "render_solidity_project",
    "run_cairo_campaign",
    "run_echidna_fallback",
    "run_fuzz_campaign",
    "run_invariant_pipeline",
    "run_invariant_pipeline_full",
    "run_vyper_campaign",
    "synthesize_invariants",
    "template_invariants",
    "write_project",
]

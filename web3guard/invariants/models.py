"""Shared data types for the invariant synthesis + fuzzing pipeline (Phase 2).

This module is deliberately free of I/O: it only defines the shapes that
:mod:`web3guard.invariants.synthesize`, :mod:`web3guard.invariants.harness`,
and :mod:`web3guard.invariants.fuzz` pass between each other.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Invariant:
    """One "must-always-hold" property of a contract.

    PROMFUZZ pattern: the property is drafted in natural language, but it
    always ships with a machine-checkable ``assertion`` — a single Solidity
    boolean expression evaluated against the *public* interface of the
    contract under test, where the contract instance is named ``target``.
    No ghost state is required, so the same shape works for the template
    fallback and for LLM-drafted invariants alike.
    """

    id: str                     # short slug, e.g. "solvency-1-1"
    statement: str              # natural-language statement of the property
    variables: list[str] = field(default_factory=list)   # state vars involved
    functions: list[str] = field(default_factory=list)  # functions involved
    assertion: str = ""         # Solidity boolean expression over `target`
    rationale: str = ""         # why this property matters for security
    bug_class: str = "accounting-desync"  # accounting-desync | access-control
                                            # | oracle-price | rounding
                                            # | share-price | other
    source: str = "template"    # "template" | "llm"
    severity: str = "HIGH"      # severity if the invariant is violated


@dataclass
class FuzzBounds:
    """Resource bounds for one fuzz campaign.

    Defaults are sized for a small 2-CPU / 7 GB VM: a campaign should
    finish in a few minutes, never dominate the host.
    """

    runs: int = 256             # invariant runs per campaign
    depth: int = 15             # max call-sequence depth
    timeout_seconds: int = 300  # hard wall-clock cap per campaign
    fail_on_revert: bool = False

    @classmethod
    def from_config(cls, config: Any) -> FuzzBounds:
        bounds = cls()
        if not isinstance(config, dict):
            return bounds
        inv_cfg = config.get("invariants")
        if not isinstance(inv_cfg, dict):
            return bounds
        for key in ("runs", "depth", "timeout_seconds"):
            if key in inv_cfg:
                try:
                    val = int(inv_cfg[key])
                    if val > 0:
                        setattr(bounds, key, val)
                except (TypeError, ValueError):
                    continue
        if "fail_on_revert" in inv_cfg:
            bounds.fail_on_revert = bool(inv_cfg["fail_on_revert"])
        return bounds


@dataclass
class CampaignResult:
    """Outcome of running one fuzz campaign."""

    skipped: bool = False
    skip_reason: str = ""
    compile_ok: bool = False
    clean: bool = False               # ran to completion, nothing violated
    runs: int = 0
    calls: int = 0
    reverts: int = 0
    elapsed_seconds: float = 0.0
    raw_stdout: str = ""
    raw_stderr: str = ""
    engine: str = "foundry-invariant"


@dataclass
class SynthesisResult:
    """Outcome of the invariant-synthesis step."""

    invariants: list[Invariant] = field(default_factory=list)
    ai_used: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class PipelineResult:
    """Full outcome of :func:`run_invariant_pipeline`, for phase 7 wiring."""

    findings: list[Any] = field(default_factory=list)  # list[Finding]
    notes: list[str] = field(default_factory=list)
    invariants: list[Invariant] = field(default_factory=list)
    campaign: CampaignResult | None = None

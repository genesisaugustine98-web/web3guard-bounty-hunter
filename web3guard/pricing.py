"""
Verifier economics / pricing model.

This module implements two complementary pricing surfaces:

1. **Researcher-side (per-finding)** — the bug-bounty revenue share
   a researcher receives when Web3Guard helps them find a bug.
   Industry standard is 10% of the paid bounty, capped at $50,000
   per finding to avoid being wiped out by a single $10M payout.

2. **Program-side (per-target subscription)** — protocols that want
   continuous scanning (rather than a one-shot bug-bounty) pay a
   monthly subscription. The tiers are calibrated to break even
   against the LLM cost of the most active research programs.

3. **LLM cost estimates** — given a target size and chosen model,
   how much will a scan cost? Used by the CLI's ``price`` subcommand
   and by the scanner core's cost ceiling.

Why this is here: the original scanner was a research artifact with
no economic model. To make it sustainable as a product, the pricing
has to be explicit and defensible. This module is also the public
artifact a program would see when evaluating whether to subscribe.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Mapping

LOGGER = logging.getLogger("web3guard.pricing")


# ---------------------------------------------------------------------------
# Researcher-side pricing
# ---------------------------------------------------------------------------

# 10% is the industry standard for bug-bounty platforms (Immunefi,
# HackerOne, Sherlock all hover here). We cap at $50K so a $1M
# critical pays $100K rather than the full 10% / 100K.
RESEARCHER_REVENUE_SHARE = 0.10
RESEARCHER_REVENUE_CAP_USD = 50_000.0
RESEARCHER_MIN_PAYOUT_USD = 100.0


def researcher_payout(bounty_usd: float) -> float:
    """Compute the researcher's share of a paid bounty."""
    if bounty_usd <= 0:
        return 0.0
    payout = bounty_usd * RESEARCHER_REVENUE_SHARE
    return min(payout, RESEARCHER_REVENUE_CAP_USD)


# ---------------------------------------------------------------------------
# Program-side subscriptions
# ---------------------------------------------------------------------------

PROGRAM_TIERS: dict[str, dict[str, object]] = {
    "free": {
        "monthly_usd": 0,
        "max_targets": 1,
        "daily_chunk_limit": 50,
        "max_chunk_chars": 6_000,
        "discovery_engines": ["slither", "gitleaks"],
        "ai_provider": "nim",
    },
    "pro": {
        "monthly_usd": 499,
        "max_targets": 5,
        "daily_chunk_limit": 1_000,
        "max_chunk_chars": 12_000,
        "discovery_engines": ["slither", "aderyn", "gitleaks", "semgrep"],
        "ai_provider": "nim",
    },
    "scale": {
        "monthly_usd": 2_499,
        "max_targets": 25,
        "daily_chunk_limit": 10_000,
        "max_chunk_chars": 24_000,
        "discovery_engines": ["slither", "aderyn", "mythril", "echidna", "gitleaks", "semgrep"],
        "ai_provider": "nim-openrouter",
    },
    "enterprise": {
        "monthly_usd": None,  # contact us
        "max_targets": None,  # unlimited
        "daily_chunk_limit": None,  # unlimited
        "max_chunk_chars": 32_000,
        "discovery_engines": ["slither", "aderyn", "mythril", "echidna", "gitleaks", "semgrep", "cargo-audit", "aptos-bytecode-verifier"],
        "ai_provider": "nim-openrouter-groq",
    },
}


# ---------------------------------------------------------------------------
# LLM cost estimates
# ---------------------------------------------------------------------------

# Per 1M tokens. Mirror this in the CostTracker.
DEFAULT_RATES: dict[str, dict[str, float]] = {
    "deepseek-ai/deepseek-v4-flash-0731": {"input": 0.0, "output": 0.0},  # free on NIM
    "deepseek/deepseek-chat":         {"input": 0.14, "output": 0.28},
    "llama-3.3-70b-versatile":        {"input": 0.59, "output": 0.79},
    "gpt-4o":                         {"input": 5.00, "output": 15.00},
    "gpt-4o-mini":                    {"input": 0.15, "output": 0.60},
    "claude-3-5-sonnet-latest":       {"input": 3.00, "output": 15.00},
}

# Average token consumption per analysis chunk. These are rough
# measurements from real scans; tune them in your own deployment.
AVG_PROMPT_TOKENS_PER_CHUNK = 4_500
AVG_COMPLETION_TOKENS_PER_CHUNK = 800
AVG_TOKENS_PER_EXPLOIT_CALL = 3_000
AVG_EXPLOIT_COMPLETION_TOKENS = 2_000
AVG_TOKENS_PER_CRITIQUE_CALL = 3_000
AVG_CRITIQUE_COMPLETION_TOKENS = 600


@dataclass
class ScanEstimate:
    """Estimated cost and time of a scan before it starts."""
    estimated_cost_usd: float
    estimated_seconds: float
    estimated_total_tokens: int
    breakdown: dict[str, float]


def compute_estimate(
    *,
    num_chunks: int,
    model: str = "deepseek-ai/deepseek-v4-flash-0731",
    include_exploit: bool = True,
    include_self_critique: bool = True,
) -> ScanEstimate:
    """Compute a pre-scan cost estimate.

    The estimate assumes a single-pass analysis with the configured
    discovery engines. The actual cost will be lower if the response
    cache hits, and higher if the LLM re-generates PoCs.
    """
    rates = DEFAULT_RATES.get(model, {"input": 0.0, "output": 0.0})
    in_rate = rates["input"]
    out_rate = rates["output"]
    analysis_calls = num_chunks
    exploit_calls = num_chunks if include_exploit else 0
    critique_calls = num_chunks if include_self_critique else 0
    in_tok = (
        analysis_calls * AVG_PROMPT_TOKENS_PER_CHUNK
        + exploit_calls * AVG_TOKENS_PER_EXPLOIT_CALL
        + critique_calls * AVG_TOKENS_PER_CRITIQUE_CALL
    )
    out_tok = (
        analysis_calls * AVG_COMPLETION_TOKENS_PER_CHUNK
        + exploit_calls * AVG_EXPLOIT_COMPLETION_TOKENS
        + critique_calls * AVG_CRITIQUE_COMPLETION_TOKENS
    )
    cost = (in_tok / 1_000_000.0) * in_rate + (out_tok / 1_000_000.0) * out_rate
    # Wall-clock: roughly 6s per LLM call (NIM free tier is 35 rpm).
    seconds = (analysis_calls + exploit_calls + critique_calls) * 6.0
    return ScanEstimate(
        estimated_cost_usd=cost,
        estimated_seconds=seconds,
        estimated_total_tokens=in_tok + out_tok,
        breakdown={
            "analysis": analysis_calls * AVG_PROMPT_TOKENS_PER_CHUNK / 1_000_000.0 * in_rate,
            "exploit":  exploit_calls * AVG_TOKENS_PER_EXPLOIT_CALL / 1_000_000.0 * in_rate,
            "critique": critique_calls * AVG_TOKENS_PER_CRITIQUE_CALL / 1_000_000.0 * in_rate,
        },
    )


def pricing_summary() -> dict[str, dict[str, float]]:
    """Return the LLM pricing table for display."""
    return {k: dict(v) for k, v in DEFAULT_RATES.items()}

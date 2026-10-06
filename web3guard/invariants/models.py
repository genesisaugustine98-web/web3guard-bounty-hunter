"""Shared data types for the invariant synthesis + fuzzing pipeline (Phase 2).

This module is deliberately free of I/O: it only defines the shapes that
:mod:`web3guard.invariants.synthesize`, :mod:`web3guard.invariants.harness`,
and :mod:`web3guard.invariants.fuzz` pass between each other.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Primitive Solidity types the entry-point generator can fuzz.
# "address payable" is included (weakness-hunt round, target 3): it must
# survive parameter parsing, or functions like `sweep(address payable to)`
# become unrenderable.
_PRIMITIVE_RE = re.compile(
    r"^(uint(8|16|32|64|128|256)?|int(8|16|32|64|128|256)?|address(\s+payable)?|bool|bytes32)$"
)


@dataclass
class FunctionSig:
    """A parsed function signature relevant to fuzz-entry generation.

    (Moved here from :mod:`web3guard.invariants.harness` in the Phase 1
    attack-simulator upgrade so :mod:`web3guard.invariants.attackers` can
    use it without creating an import cycle. It is still importable from
    ``harness`` — same object, same behavior.)
    """

    name: str
    params: list[tuple[str, str]] = field(default_factory=list)  # (type, name)
    mutability: str = ""  # "payable" | "view" | "pure" | ""

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

    id: str  # short slug, e.g. "solvency-1-1"
    statement: str  # natural-language statement of the property
    variables: list[str] = field(default_factory=list)  # state vars involved
    functions: list[str] = field(default_factory=list)  # functions involved
    assertion: str = ""  # Solidity boolean expression over `target`
    rationale: str = ""  # why this property matters for security
    bug_class: str = "accounting-desync"  # accounting-desync | access-control
    # | oracle-price | rounding
    # | share-price | other
    source: str = "template"  # "template" | "llm"
    severity: str = "HIGH"  # severity if the invariant is violated
    temporal_scope: str = "permanent"
    # Weakness-hunt round, target 5: "permanent" (must hold at all times,
    # time-warp is a valid test) vs "time-limited" (only meaningful within
    # a time window, e.g. oracle freshness — warping the clock past the
    # window would be a false positive, so warp actions are disabled).


@dataclass
class FuzzBounds:
    """Resource bounds for one fuzz campaign.

    Defaults are sized for a small 2-CPU / 7 GB VM: a campaign should
    finish in a few minutes, never dominate the host.

    Phase 1 attack-simulator fields (all additive, all default-ON so the
    pipeline needs no changes to get the attacking simulator):

    - ``seed``: fixed default campaign seed (reproducibility). Plumbed to
      ``forge test --fuzz-seed``, the ``[fuzz] seed`` config key, and the
      on-chain strategy PRNG inside the attack handler.
    - ``attack_enabled``: render the attack harness (value-carrying
      handler, deployed attacker contracts, time-warp + heist actions,
      adaptive strategy mixing) instead of the legacy plain harness.
    - ``attack_depth``: call-sequence depth for attack campaigns. The old
      15-call ceiling is what kept multi-step exploits unreachable; the
      rendered ``[invariant] depth`` becomes
      ``max(depth, attack_depth)`` when attacks are on.
    - ``attack_max_value_wei``: cap on ETH value any single handler
      action may move (fuzzed per-call amounts are clamped to this).
    - ``strategy_epsilon``: exploration rate of the epsilon-greedy
      strategy selector (0 = always exploit the best-known strategy,
      1 = always explore randomly).
    """

    runs: int = 256  # invariant runs per campaign
    depth: int = 15  # max call-sequence depth
    timeout_seconds: int = 300  # hard wall-clock cap per campaign
    fail_on_revert: bool = False
    seed: int = 1337  # fixed default campaign seed
    # Fix-campaign #7 (seed dilution): on very large contracts a single
    # fixed seed can deterministically miss the vulnerable function. When
    # seed_count > 1, the campaign runs that many seeds (deterministically
    # derived from `seed`) and aggregates findings across all runs.
    # Each seed run is fully reproducible; total wall-clock scales with
    # seed_count. Default 1 = legacy single-seed behavior.
    seed_count: int = 1
    attack_enabled: bool = True  # attack harness ON by default
    attack_depth: int = 64  # attack call-sequence depth
    attack_max_value_wei: int = 10_000_000_000_000_000_000  # 10 ETH/call
    strategy_epsilon: float = 0.25  # bandit exploration rate
    # Weakness-hunt round, target 1: extra sender addresses the harness may
    # act as (in addition to the addresses mined from the target source).
    # Lets an operator point the fuzzer at a known privileged address
    # (e.g. a multisig) without editing the contract. Empty by default.
    impersonate_senders: tuple[str, ...] = ()
    # Fix A (weakness 1's overcorrection): run the compromised-key leg — a
    # separate bounded campaign where the handler impersonates the owner
    # ON DEMAND (prank as the neutral deployer), so owner-gated
    # invariants stay testable without reintroducing owner-confusion
    # false alarms. ON by default; disable with
    # ``invariants: {compromised_key_leg: false}``.
    compromised_key_leg: bool = True

    @classmethod
    def from_config(cls, config: Any) -> FuzzBounds:
        bounds = cls()
        if not isinstance(config, dict):
            return bounds
        inv_cfg = config.get("invariants")
        if not isinstance(inv_cfg, dict):
            return bounds
        for key in ("runs", "depth", "timeout_seconds", "seed_count"):
            if key in inv_cfg:
                try:
                    val = int(inv_cfg[key])
                    if val > 0:
                        setattr(bounds, key, val)
                except (TypeError, ValueError):
                    continue
        for key in ("seed", "attack_depth", "attack_max_value_wei"):
            if key in inv_cfg:
                try:
                    val = int(inv_cfg[key])
                    if val >= 0:
                        setattr(bounds, key, val)
                except (TypeError, ValueError):
                    continue
        if "fail_on_revert" in inv_cfg:
            bounds.fail_on_revert = bool(inv_cfg["fail_on_revert"])
        if "attack_enabled" in inv_cfg:
            bounds.attack_enabled = _coerce_bool(inv_cfg["attack_enabled"], True)
        if "strategy_epsilon" in inv_cfg:
            try:
                eps = float(inv_cfg["strategy_epsilon"])
                if 0.0 <= eps <= 1.0:
                    bounds.strategy_epsilon = eps
            except (TypeError, ValueError):
                pass
        if "impersonate_senders" in inv_cfg:
            bounds.impersonate_senders = _coerce_address_list(
                inv_cfg["impersonate_senders"])
        if "compromised_key_leg" in inv_cfg:
            bounds.compromised_key_leg = _coerce_bool(
                inv_cfg["compromised_key_leg"], True)
        return bounds

    @property
    def effective_depth(self) -> int:
        """Call-sequence depth actually rendered into foundry.toml."""
        if self.attack_enabled:
            return max(self.depth, self.attack_depth)
        return self.depth


def _coerce_bool(value: Any, default: bool) -> bool:
    """Parse a config boolean without ``bool("false") == True`` traps."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "y", "on")
    if isinstance(value, (int, float)):
        return bool(value)
    return default


_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}\Z")


def _coerce_address_list(value: Any) -> tuple[str, ...]:
    """Parse a config list of hex addresses; drop anything malformed."""
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return ()
    out: list[str] = []
    for item in value:
        if isinstance(item, str) and _ADDRESS_RE.match(item.strip()):
            addr = item.strip().lower()
            if addr not in out:
                out.append(addr)
    return tuple(out)


@dataclass
class CampaignResult:
    """Outcome of running one fuzz campaign."""

    skipped: bool = False
    skip_reason: str = ""
    compile_ok: bool = False
    clean: bool = False  # ran to completion, nothing violated
    runs: int = 0
    calls: int = 0
    reverts: int = 0
    elapsed_seconds: float = 0.0
    raw_stdout: str = ""
    raw_stderr: str = ""
    engine: str = "foundry-invariant"
    # Fix D (resource-exhaustion mislabeling): a campaign that dies by
    # signal (SIGKILL/OOM, exit 137) or by the wall-clock timeout is a
    # RESOURCE_EXHAUSTED verdict, NEVER "did not compile". resource_detail
    # names the signal/timeout so the report can say exactly what happened.
    resource_exhausted: bool = False
    resource_detail: str = ""
    # Phase 1 (additive): which attack strategies the campaign emphasized,
    # and the campaign seed actually used. Empty for legacy campaigns.
    strategies_used: list[str] = field(default_factory=list)
    campaign_seed: int = 1337
    # Fix-campaign #7 (seed dilution): seeds actually run in a multi-seed
    # campaign. Single-element (or empty for legacy) when seed_count == 1.
    seeds_run: list[int] = field(default_factory=list)


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
    #: Rules the proof gate quarantined (pre-render or post-campaign), as
    #: dicts with invariant_id / reason / stage. Additive (Phase 3).
    quarantined_rules: list[Any] = field(default_factory=list)
    #: Weakness-hunt round, target 2: explicit "could not check" verdicts.
    #: A compile failure (or render failure) anywhere in the pipeline lands
    #: here — it must NEVER read as a clean "no findings". The hunt report
    #: renders these loudly.
    inconclusive: list[str] = field(default_factory=list)

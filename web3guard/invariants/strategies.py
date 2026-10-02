"""Adaptive attack-strategy selection (Phase 1 attack-simulator upgrade).

The old simulator ran one fixed script: plain direct calls, no variation.
This module implements the strategy *portfolio* the new simulator attacks
with, plus the epsilon-greedy bandit that varies the approach based on
observations:

1. **Render time** — :func:`contract_features` reads the target's shape
   (payable functions? ``block.timestamp``? external calls? a vault-like
   deposit/withdraw pair?) and :func:`weight_strategies` turns those into
   prior weights over the portfolio. An :class:`EpsilonGreedySelector`
   then picks the primary strategy: usually the best-weighted one,
   sometimes a random one (exploration).
2. **Inside the fuzzer** — the rendered handler contains an on-chain
   epsilon-greedy bandit (``act_adaptiveAssault``) that mixes the attack
   modes within a run and reinforces whichever mode extracts real profit
   from the attacker contracts.
3. **Across campaigns** — :func:`record_campaign_outcome` persists
   per-strategy rewards to a small JSON state file, so the next
   campaign's selector starts from what previous campaigns learned.

Everything here is pure Python (no forge, no network) and unit-testable.
"""

from __future__ import annotations

import json
import logging
import os
import random
from dataclasses import dataclass, field
from pathlib import Path

from web3guard.invariants.attackers import detect_vault_interface
from web3guard.invariants.models import FunctionSig

LOGGER = logging.getLogger("web3guard.invariants.strategies")

#: Where cross-campaign bandit state lives (workspace-local, never the repo).
DEFAULT_STATE_PATH = Path.home() / "workspace" / "tools" / "foundry" / "strategy_state.json"

#: Env var overriding the state path (used by tests for isolation).
STATE_PATH_ENV = "WEB3GUARD_STRATEGY_STATE"


def resolve_state_path() -> Path:
    """Resolve the bandit state path, honoring the test-isolation override."""
    override = os.environ.get(STATE_PATH_ENV)
    if override:
        return Path(override)
    return DEFAULT_STATE_PATH


@dataclass(frozen=True)
class Strategy:
    """One attack approach in the portfolio."""

    name: str
    description: str
    #: contract feature -> extra weight when the feature is present.
    affinities: dict[str, float] = field(default_factory=dict)
    base_weight: float = 1.0


#: The portfolio. Names are stable identifiers used in reports, the state
#: file, and the action->strategy attribution map below.
PORTFOLIO: tuple[Strategy, ...] = (
    Strategy(
        "direct",
        "Plain multi-sender calls with fuzzed arguments (the old baseline).",
        affinities={},
        base_weight=1.0,
    ),
    Strategy(
        "value-heavy",
        "Calls carrying ETH: payable paths, fee logic, forced-ETH donation.",
        affinities={"has_payable": 3.0, "has_receive": 1.5},
        base_weight=0.7,
    ),
    Strategy(
        "attacker-contract",
        "Drive the exploit through deployed malicious contracts (reentrancy, approval drain).",
        affinities={
            "has_external_call": 2.5,
            "vault_pair": 3.0,
            "has_approve": 1.5,
        },
        base_weight=0.5,
    ),
    Strategy(
        "time-warped",
        "Advance block.timestamp / block.number between calls (vesting, TWAP, lockups, deadlines).",
        affinities={"uses_timestamp": 3.0, "uses_block_number": 2.0},
        base_weight=0.4,
    ),
    Strategy(
        "multi-step",
        "Long scripted heists inside one handler action: "
        "deposit -> warp -> borrow -> reenter -> drain.",
        affinities={"vault_pair": 1.5, "uses_timestamp": 1.5},
        base_weight=0.6,
    ),
    Strategy(
        "mixed",
        "Adaptive on-chain bandit mixing every mode and reinforcing "
        "whichever extracts real profit.",
        affinities={},
        base_weight=0.8,
    ),
)

_STRATEGY_BY_NAME = {s.name: s for s in PORTFOLIO}

#: Handler-action substring -> strategy, used to attribute a campaign's
#: findings back to the strategies whose actions produced them.
ACTION_STRATEGY_HINTS: dict[str, str] = {
    "attack_reenter": "attacker-contract",
    "approvaldrain": "attacker-contract",
    "donate": "value-heavy",
    "deposit": "value-heavy",
    "warp": "time-warped",
    "heist": "multi-step",
    "adaptiveassault": "mixed",
}


def contract_features(source: str, functions: list[FunctionSig]) -> dict[str, bool]:
    """Extract the boolean features that weight the strategy portfolio."""
    lowered_names = {fn.name.lower() for fn in functions}
    return {
        "has_payable": any(fn.mutability == "payable" for fn in functions),
        "has_receive": "receive()" in source or "receive (" in source,
        "uses_timestamp": "block.timestamp" in source,
        "uses_block_number": "block.number" in source,
        "has_external_call": ".call{" in source or ".call(" in source,
        "has_delegatecall": ".delegatecall(" in source,
        "has_approve": bool(lowered_names & {"approve", "permit"}),
        "has_transfer_from": "transferfrom" in lowered_names,
        "vault_pair": detect_vault_interface(functions) is not None,
        "many_entry_points": sum(1 for fn in functions if fn.fuzzable) >= 4,
    }


def weight_strategies(
    features: dict[str, bool],
) -> dict[str, float]:
    """Turn contract features into prior weights over the portfolio."""
    weights: dict[str, float] = {}
    for strategy in PORTFOLIO:
        w = strategy.base_weight
        for feature, affinity in strategy.affinities.items():
            if features.get(feature):
                w += affinity
        weights[strategy.name] = round(w, 3)
    return weights


class EpsilonGreedySelector:
    """Bandit over the strategy portfolio.

    ``select()`` exploits (picks the highest-valued strategy) most of the
    time and explores (weighted-random pick) with probability ``epsilon``.
    ``update()`` folds an observed reward into the strategy's running
    mean, so strategies that actually break invariants get picked more
    often in later campaigns. The RNG is seeded, so selection is
    reproducible for a fixed seed.
    """

    def __init__(
        self,
        strategies: tuple[Strategy, ...] = PORTFOLIO,
        epsilon: float = 0.25,
        seed: int = 1337,
    ) -> None:
        self._strategies = strategies
        self.epsilon = epsilon
        self.seed = seed
        self._rng = random.Random(seed)
        self.counts: dict[str, int] = {s.name: 0 for s in strategies}
        self.values: dict[str, float] = {s.name: 0.0 for s in strategies}

    # -- selection ------------------------------------------------------
    def select(self, weights: dict[str, float] | None = None) -> Strategy:
        """Pick a strategy: weighted-random explore, else best-known."""
        weights = weights or {s.name: s.base_weight for s in self._strategies}
        if self._rng.random() < self.epsilon:
            return self._weighted_random(weights)
        best = max(
            self._strategies,
            key=lambda s: (self.values[s.name], weights.get(s.name, 0.0)),
        )
        return best

    def _weighted_random(self, weights: dict[str, float]) -> Strategy:
        total = sum(max(0.0, weights.get(s.name, 0.0)) for s in self._strategies)
        if total <= 0:
            return self._rng.choice(list(self._strategies))
        pick = self._rng.random() * total
        for s in self._strategies:
            pick -= max(0.0, weights.get(s.name, 0.0))
            if pick <= 0:
                return s
        return self._strategies[-1]

    # -- learning -------------------------------------------------------
    def update(self, strategy_name: str, reward: float) -> None:
        """Fold an observed reward (0.0..1.0, but any float works) in."""
        if strategy_name not in self.values:
            LOGGER.warning("unknown strategy %r in bandit update; ignoring", strategy_name)
            return
        self.counts[strategy_name] += 1
        n = self.counts[strategy_name]
        old = self.values[strategy_name]
        self.values[strategy_name] = old + (reward - old) / n

    # -- persistence ----------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "epsilon": self.epsilon,
            "seed": self.seed,
            "counts": dict(self.counts),
            "values": {k: round(v, 6) for k, v in self.values.items()},
        }

    @classmethod
    def from_dict(cls, data: dict, epsilon: float, seed: int) -> EpsilonGreedySelector:
        sel = cls(epsilon=epsilon, seed=seed)
        counts = data.get("counts") or {}
        values = data.get("values") or {}
        for name in sel.counts:
            if isinstance(counts.get(name), int):
                sel.counts[name] = counts[name]
            if isinstance(values.get(name), (int, float)):
                sel.values[name] = float(values[name])
        return sel

    def save(self, path: Path | str) -> None:
        """Persist bandit state atomically; never raises."""
        try:
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(path.name + ".tmp")
            tmp.write_text(json.dumps(self.to_dict(), indent=2))
            os.replace(tmp, path)
        except OSError as exc:
            LOGGER.warning("could not persist strategy state to %s: %s", path, exc)

    @classmethod
    def load(cls, path: Path | str, epsilon: float, seed: int) -> EpsilonGreedySelector:
        """Load bandit state; a missing/corrupt file yields a fresh selector."""
        try:
            data = json.loads(Path(path).read_text())
            if isinstance(data, dict):
                return cls.from_dict(data, epsilon=epsilon, seed=seed)
        except (OSError, json.JSONDecodeError) as exc:
            LOGGER.info("no usable strategy state at %s (%s); starting fresh", path, exc)
        return cls(epsilon=epsilon, seed=seed)


def attribute_strategies(poc_text: str) -> set[str]:
    """Map a finding's PoC call sequence back to strategy names."""
    lowered = (poc_text or "").lower()
    return {strategy for hint, strategy in ACTION_STRATEGY_HINTS.items() if hint in lowered}


def record_campaign_outcome(
    state_path: Path | str,
    strategies_used: list[str],
    poc_texts: list[str],
    *,
    epsilon: float = 0.25,
    seed: int = 1337,
) -> None:
    """Fold one campaign's outcome into the persisted bandit. Never raises.

    Strategies whose actions appear in a finding's PoC get reward 1.0
    (they produced evidence); strategies used in a clean campaign get a
    small 0.05 participation reward so unexplored arms stay viable.
    """
    try:
        sel = EpsilonGreedySelector.load(state_path, epsilon=epsilon, seed=seed)
        credited = set()
        for poc in poc_texts:
            for name in attribute_strategies(poc):
                sel.update(name, 1.0)
                credited.add(name)
        for name in strategies_used:
            if name not in credited:
                sel.update(name, 0.05)
        sel.save(state_path)
    except Exception as exc:  # never break a campaign over bookkeeping
        LOGGER.warning("strategy bookkeeping failed (non-fatal): %s", exc)


def plan_campaign(
    source: str,
    functions: list[FunctionSig],
    *,
    epsilon: float = 0.25,
    seed: int = 1337,
    state_path: Path | str | None = None,
) -> tuple[dict[str, float], Strategy, list[str], EpsilonGreedySelector]:
    """Render-time strategy planning: weights, primary pick, attacker set.

    Returns (weights, primary_strategy, attacker_names, selector). The
    selector carries the persisted cross-campaign learning, so the pick
    adapts to what previous campaigns observed.
    """
    features = contract_features(source, functions)
    weights = weight_strategies(features)
    resolved = Path(state_path) if state_path is not None else resolve_state_path()
    selector = EpsilonGreedySelector.load(resolved, epsilon=epsilon, seed=seed)
    primary = selector.select(weights)
    attacker_names = ["DonationAttacker"]
    if features.get("vault_pair"):
        attacker_names.append("ReentrancyAttacker")
    if features.get("has_approve") or features.get("has_transfer_from"):
        attacker_names.append("ApprovalDrainer")
    return weights, primary, attacker_names, selector

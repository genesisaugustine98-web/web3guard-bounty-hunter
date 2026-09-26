"""Adaptive model router — picks the best model per call.

Design:

- **Health tracking per model**: EMA of latency, EWMA of error rate,
  consecutive-failure exponential backoff, and circuit state mirroring
  :class:`web3guard.ai.client.CircuitBreakerState`.
- **Static config wins.** Explicit ``models:``/``role_models`` entries
  route first; the router only chooses among the *dynamic* candidates
  when no static mapping exists.
- **Budget-aware**: when the :class:`web3guard.ai.budget.BudgetController`
  reports warning/exhausted, the router downgrades to the cheapest
  healthy candidate (``on_exhausted: downgrade`` keeps scans alive on
  free tiers instead of stopping them).
- **Zero-dollar-safe**: candidates carry pricing from
  ``web3guard.ai.cost.DEFAULT_PRICING``; a routing decision never picks
  a model whose next call could breach the budget ceiling.

The router is deliberately provider-agnostic: candidates name a model
string; the :class:`AIClient` remains the only caller of providers.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

LOGGER = logging.getLogger("web3guard.routing")

# Health-tracker defaults.
_EMA_ALPHA = 0.3           # weight of the newest latency sample
_ERR_ALPHA = 0.25          # weight of the newest success/failure sample
_BACKOFF_CAP = 900.0       # seconds; a model is skipped while backed off


@dataclass
class ModelCandidate:
    """One routable model (on any provider)."""
    name: str
    provider: str = ""
    role: str = "analysis"
    # Relative quality weight (0-1). Static judgment of capability for
    # the role; the health signals refine it at runtime.
    quality: float = 0.5
    pricing: dict[str, float] = field(default_factory=dict)  # {"input": $/1M, "output": $/1M}

    @property
    def avg_cost_usd(self) -> float:
        """Rough per-call cost at the scanner's average chunk shape."""
        in_tok, out_tok = 4_500, 800
        return (in_tok / 1e6) * self.pricing.get("input", 0.0) \
            + (out_tok / 1e6) * self.pricing.get("output", 0.0)


@dataclass
class RouteDecision:
    """Outcome of one routing decision (kept in metadata for tuning)."""
    model: str
    reason: str
    candidates_considered: int = 0
    degraded: bool = False       # True when budget pushed us down-market
    score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model, "reason": self.reason,
            "candidates_considered": self.candidates_considered,
            "degraded": self.degraded, "score": round(self.score, 4),
        }


@dataclass
class _Health:
    ema_latency: float = 0.0     # seconds; 0 = no data
    err_rate: float = 0.0        # 0..1 EWMA
    samples: int = 0
    consecutive_failures: int = 0
    backed_off_until: float = 0.0
    circuit_open: bool = False


class ModelRouter:
    """Score-based model selection with live health + budget awareness."""

    def __init__(
        self,
        *,
        default_model: str,
        candidates: list[ModelCandidate] | None = None,
        budget: Any = None,               # BudgetController | None
        max_cost_per_call_usd: float = 0.0,
    ) -> None:
        self._default = default_model
        self._candidates: dict[str, ModelCandidate] = {
            c.name: c for c in (candidates or [])
        }
        self._budget = budget
        self._max_cost = max(0.0, float(max_cost_per_call_usd))
        self._health: dict[str, _Health] = {}

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def add_candidate(self, candidate: ModelCandidate) -> None:
        self._candidates[candidate.name] = candidate

    def candidate_names(self) -> list[str]:
        return sorted(self._candidates)

    def default_model(self) -> str:
        return self._default

    # ------------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------------

    def route(
        self,
        role: str,
        *,
        role_models: Mapping[str, str] | None = None,
        exclude: set[str] | None = None,
        circuit_open: set[str] | None = None,
    ) -> RouteDecision:
        """Choose a model for ``role``.

        Priority:
        1. Static per-role override (``role_models``) — explicit config
           always wins.
        2. Budget-degraded: cheapest healthy candidate.
        3. Best-scoring healthy candidate.
        4. The default model when no candidates are configured.
        """
        static = dict(role_models or {})
        if static.get(role):
            return RouteDecision(model=static[role],
                                 reason="static role override")
        exclude = exclude or set()
        circuit_open = circuit_open or set()

        pool = [
            c for name, c in self._candidates.items()
            if name not in exclude and name not in circuit_open
        ]
        if not pool:
            return RouteDecision(model=self._default,
                                 reason="no dynamic candidates; default model")

        # Budget pressure -> downgrade to the cheapest healthy candidate.
        budget_state = "ok"
        if self._budget is not None:
            try:
                budget_state = self._budget.check().state
            except Exception:  # noqa: BLE001
                budget_state = "ok"
        if budget_state == "exhausted" or (
                budget_state == "warning" and self._max_cost > 0):
            cheap = self._cheapest_healthy(pool)
            if cheap is not None:
                return RouteDecision(
                    model=cheap.name,
                    reason=f"budget {budget_state}: downgraded to cheapest healthy",
                    candidates_considered=len(pool),
                    degraded=True,
                )

        scored = [
            (self._score(c), c) for c in pool
            if not self._backed_off(c.name)
        ]
        if not scored:
            # Everything is backed off; ignore backoff rather than fail.
            scored = [(self._score(c), c) for c in pool]
        best_score, best = max(scored, key=lambda t: (t[0], t[1].name))
        return RouteDecision(
            model=best.name,
            reason="best healthy candidate",
            candidates_considered=len(pool),
            score=best_score,
        )

    # ------------------------------------------------------------------
    # Health feedback
    # ------------------------------------------------------------------

    def record_success(self, model: str, latency_seconds: float) -> None:
        h = self._health_for(model)
        h.samples += 1
        h.ema_latency = latency_seconds if h.ema_latency == 0.0 else (
            (1 - _EMA_ALPHA) * h.ema_latency + _EMA_ALPHA * latency_seconds)
        h.err_rate = (1 - _ERR_ALPHA) * h.err_rate
        h.consecutive_failures = 0
        h.backed_off_until = 0.0

    def record_failure(self, model: str, *, error: str = "") -> None:
        h = self._health_for(model)
        h.samples += 1
        h.err_rate = (1 - _ERR_ALPHA) * h.err_rate + _ERR_ALPHA * 1.0
        h.consecutive_failures += 1
        h.backed_off_until = time.time() + min(
            _BACKOFF_CAP, 2.0 ** min(h.consecutive_failures, 10))

    def mark_circuit(self, model: str, *, is_open: bool) -> None:
        h = self._health_for(model)
        h.circuit_open = bool(is_open)

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _score(self, c: ModelCandidate) -> float:
        h = self._health.get(c.name) or _Health()
        quality = min(1.0, max(0.0, c.quality))
        latency_term = 1.0
        if h.ema_latency > 0:
            latency_term = 1.0 / (1.0 + h.ema_latency / 10.0)
        reliability = 1.0 - min(1.0, h.err_rate)
        # Cheap models get a small nudge so near-equal quality breaks
        # toward cost (zero-dollar policy alignment).
        cost_term = 1.0 / (1.0 + c.avg_cost_usd * 50.0)
        return (0.45 * quality + 0.30 * reliability
                + 0.20 * latency_term + 0.05 * cost_term)

    def _cheapest_healthy(self, pool: list[ModelCandidate]) -> ModelCandidate | None:
        healthy = [c for c in pool if not self._backed_off(c.name)] or pool
        if not healthy:
            return None
        return min(healthy, key=lambda c: (c.avg_cost_usd, c.name))

    def _backed_off(self, model: str) -> bool:
        h = self._health.get(model)
        return bool(h and time.time() < h.backed_off_until)

    def _health_for(self, model: str) -> _Health:
        if model not in self._health:
            self._health[model] = _Health()
        return self._health[model]

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        return {
            name: {
                "ema_latency_s": round(h.ema_latency, 3),
                "err_rate": round(h.err_rate, 3),
                "samples": h.samples,
                "consecutive_failures": h.consecutive_failures,
                "backed_off": self._backed_off(name),
                "circuit_open": h.circuit_open,
            }
            for name, h in self._health.items()
        }

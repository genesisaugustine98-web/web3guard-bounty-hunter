"""Global budget control for LLM spend.

v3.5 problem solved: :class:`web3guard.ai.cost.CostTracker` ceilings are
per-``CostTracker`` instance — every ``Scanner`` builds its own, and
``web3guard serve`` builds one per request. Five concurrent scan
requests are five independent ceilings. Nothing looked across runs.

:class:`BudgetController` adds process-wide **and durable** budget
accounting on top of the storage layer:

- **Global ceiling** across all scanners/runs in this process.
- **Durable daily ceiling** — reads cost history from the store, so the
  limit survives restarts and is enforced across CLI + bot + serve.
- **Budget states**: OK -> WARNING (>= ``warning_frac`` of budget) ->
  EXHAUSTED. Exhaustion raises :class:`BudgetExhausted`, which the
  scanner treats exactly like the existing
  :class:`CostCeilingExceeded` (graceful abort, partial results kept).
- **Configurable action** at exhaustion: ``abort`` (default) or
  ``downgrade`` (see :mod:`web3guard.routing` — switch to the cheapest
  model instead of stopping).

Zero-dollar note: on free-tier-only setups the computed cost is $0 and
budgets never trip — the controller is then a passive accounting feed
(the durable ledger still powers ``/cost`` and the dashboard).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

LOGGER = logging.getLogger("web3guard.ai.budget")


class BudgetExhausted(RuntimeError):
    """Raised when a budget horizon is exhausted (global/daily/monthly)."""


@dataclass
class BudgetVerdict:
    """Result of a budget check before (or after) a spend."""
    allowed: bool
    state: str                     # "ok" | "warning" | "exhausted"
    horizon: str                   # "global" | "daily" | "monthly"
    spent_usd: float
    limit_usd: float
    reason: str = ""

    @property
    def remaining_usd(self) -> float:
        return max(0.0, self.limit_usd - self.spent_usd)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "state": self.state,
            "horizon": self.horizon,
            "spent_usd": round(self.spent_usd, 6),
            "limit_usd": self.limit_usd,
            "remaining_usd": round(self.remaining_usd, 6),
            "reason": self.reason,
        }


class BudgetController:
    """Durable, cross-run, cross-scanner LLM budget enforcement."""

    def __init__(
        self,
        store: Any = None,            # DurableStore; Any to avoid import cycle
        *,
        global_limit_usd: float = 0.0,
        daily_limit_usd: float = 0.0,
        monthly_limit_usd: float = 0.0,
        warning_frac: float = 0.8,
        on_exhausted: str = "abort",  # "abort" | "downgrade"
        clock: Any = None,
    ) -> None:
        self._store = store
        self._global_limit = max(0.0, float(global_limit_usd))
        self._daily_limit = max(0.0, float(daily_limit_usd))
        self._monthly_limit = max(0.0, float(monthly_limit_usd))
        self._warning_frac = min(1.0, max(0.0, float(warning_frac)))
        if on_exhausted not in ("abort", "downgrade"):
            on_exhausted = "abort"
        self.on_exhausted = on_exhausted
        self._session_spend = 0.0
        self._clock = clock or time.time
        # Process-wide dedup of warnings (log once per horizon).
        self._warned: set[str] = set()

    # ------------------------------------------------------------------
    # Spend queries (durable when a store is present)
    # ------------------------------------------------------------------

    def _durable_spend(self, since_ts: float) -> float:
        if self._store is None:
            return 0.0
        try:
            rows = self._store.local.query_all(
                "SELECT COALESCE(SUM(cost_usd), 0) AS total FROM cost_records"
                " WHERE timestamp >= ?", (since_ts,))
            return float(rows[0]["total"] or 0.0)
        except Exception as e:  # noqa: BLE001
            LOGGER.warning("budget spend query failed: %s", e)
            return 0.0

    def spent_today(self) -> float:
        """Durable spend since local midnight (survives restarts)."""
        t = self._clock()
        local_midnight = t - (t % 86_400)  # UTC day; deterministic everywhere
        return self._durable_spend(local_midnight)

    def spent_month(self) -> float:
        """Durable spend over the trailing 30 days."""
        return self._durable_spend(self._clock() - 30 * 86_400)

    @property
    def session_spend(self) -> float:
        return self._session_spend

    # ------------------------------------------------------------------
    # Enforcement API
    # ------------------------------------------------------------------

    def check(self) -> BudgetVerdict:
        """Evaluate every configured horizon; worst state wins."""
        verdicts: list[BudgetVerdict] = []

        def _make(horizon: str, spent: float, limit: float) -> BudgetVerdict:
            if limit <= 0:
                return BudgetVerdict(True, "ok", horizon, spent, limit)
            if spent >= limit:
                return BudgetVerdict(False, "exhausted", horizon, spent, limit,
                                     reason=f"{horizon} budget exhausted "
                                            f"(${spent:.4f} >= ${limit:.2f})")
            frac = spent / limit
            if frac >= self._warning_frac:
                return BudgetVerdict(True, "warning", horizon, spent, limit,
                                     reason=f"{horizon} budget {frac:.0%} used")
            return BudgetVerdict(True, "ok", horizon, spent, limit)

        if self._global_limit > 0:
            verdicts.append(_make("global", self.session_spend, self._global_limit))
        if self._daily_limit > 0:
            verdicts.append(_make("daily", self.spent_today(), self._daily_limit))
        if self._monthly_limit > 0:
            verdicts.append(_make("monthly", self.spent_month(), self._monthly_limit))

        if not verdicts:
            return BudgetVerdict(True, "ok", "global", 0.0, 0.0)
        # Priority: exhausted > warning > ok; deterministic order when ties.
        rank = {"exhausted": 0, "warning": 1, "ok": 2}
        verdicts.sort(key=lambda v: (rank[v.state], v.horizon))
        worst = verdicts[0]
        self._maybe_warn(worst)
        return worst

    def _maybe_warn(self, verdict: BudgetVerdict) -> None:
        if verdict.state == "ok":
            return
        key = f"{verdict.horizon}:{verdict.state}"
        if key in self._warned:
            return
        self._warned.add(key)
        log = LOGGER.warning if verdict.state == "exhausted" else LOGGER.info
        log("budget %s: %s", verdict.state, verdict.reason)

    def preflight(self) -> BudgetVerdict:
        """Check before starting a scan; raise when exhausted + abort."""
        verdict = self.check()
        if verdict.state == "exhausted" and self.on_exhausted == "abort":
            raise BudgetExhausted(verdict.reason)
        return verdict

    def record_spend(self, cost_usd: float) -> BudgetVerdict:
        """Register an incurred cost and re-check; raise when exhausted."""
        self._session_spend += max(0.0, float(cost_usd))
        verdict = self.check()
        if verdict.state == "exhausted" and self.on_exhausted == "abort":
            raise BudgetExhausted(verdict.reason)
        return verdict

    def summary(self) -> dict[str, Any]:
        verdict = self.check()
        return {
            **verdict.to_dict(),
            "session_spend_usd": round(self._session_spend, 6),
            "on_exhausted": self.on_exhausted,
            "limits": {
                "global_usd": self._global_limit,
                "daily_usd": self._daily_limit,
                "monthly_usd": self._monthly_limit,
            },
        }

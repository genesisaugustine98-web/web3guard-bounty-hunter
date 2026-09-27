"""
Token and dollar cost tracking for LLM calls.

The cost tracker is process-wide: it accumulates a record per call
and produces a per-run summary that is included in the report. It
also enforces a hard ceiling: if the cost exceeds ``max_cost_usd``
the client raises and the run is aborted.

Pricing is maintained in a small table that ships with the scanner.
You can override per-model pricing in ``config.yaml``.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

LOGGER = logging.getLogger("web3guard.ai.cost")


class CostCeilingExceeded(RuntimeError):
    """Raised when a scan's accumulated LLM cost crosses ``max_cost_usd``.

    The scanner catches this and returns partial results instead of
    crashing, so findings discovered before the ceiling still land in
    the report and DB.
    """

# ---------------------------------------------------------------------------
# Default pricing (USD per 1M tokens, June 2026 rates).
# Override per-model via the ``model_pricing`` config key.
# ---------------------------------------------------------------------------

DEFAULT_PRICING: dict[str, dict[str, float]] = {
    "deepseek-ai/deepseek-v4-flash-0731": {"input": 0.0, "output": 0.0},  # free on NIM
    "deepseek/deepseek-v4-flash-0731:free": {"input": 0.0, "output": 0.0},  # free on OpenRouter
    "deepseek/deepseek-chat":         {"input": 0.14, "output": 0.28},
    "deepseek/deepseek-coder":        {"input": 0.14, "output": 0.28},
    "meta/llama-3.3-70b-instruct":    {"input": 0.59, "output": 0.79},
    "llama-3.3-70b-versatile":        {"input": 0.59, "output": 0.79},
    "gpt-4o":                         {"input": 5.00, "output": 15.00},
    "gpt-4o-mini":                    {"input": 0.15, "output": 0.60},
    "o3-mini":                        {"input": 1.10, "output": 4.40},
    "claude-3-5-sonnet-latest":       {"input": 3.00, "output": 15.00},
}


@dataclass
class CostRecord:
    """One LLM call's cost contribution."""
    timestamp: float
    provider: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float
    role: str = "analysis"  # "analysis" | "exploit" | "self_critique" | "brainstorm" | "other"

    def to_dict(self) -> dict[str, object]:
        return {
            "timestamp": self.timestamp,
            "provider": self.provider,
            "model": self.model,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "cost_usd": self.cost_usd,
            "role": self.role,
        }


class CostTracker:
    """Accumulate LLM costs and enforce a hard ceiling."""

    def __init__(
        self,
        *,
        pricing: Mapping[str, Mapping[str, float]] | None = None,
        max_cost_usd: float = 50.0,
        persist_path: Path | None = None,
        allow_unknown_pricing: bool = False,
    ) -> None:
        self._pricing: dict[str, dict[str, float]] = {
            k: dict(v) for k, v in (pricing or DEFAULT_PRICING).items()
        }
        self._max_cost_usd = max_cost_usd
        self._records: list[CostRecord] = []
        self._persist_path = persist_path
        self._allow_unknown_pricing = allow_unknown_pricing
        if persist_path is not None:
            self._init_db(persist_path)

    def _init_db(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(str(path))) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cost_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL,
                    prompt_tokens INTEGER NOT NULL,
                    completion_tokens INTEGER NOT NULL,
                    cost_usd REAL NOT NULL,
                    role TEXT NOT NULL
                )
            """)
            conn.commit()

    def cost_for(self, model: str, prompt_tokens: int, completion_tokens: int) -> float:
        """Compute the dollar cost of a single call."""
        # Try exact model match first
        rates = self._pricing.get(model)
        if rates is None:
            # Try prefix match (e.g. "deepseek-ai/deepseek-v4-flash-0731@2026-01-15"
            # matches "deepseek-ai/deepseek-v4-flash-0731")
            for key, r in self._pricing.items():
                if model.startswith(key):
                    rates = r
                    break
        if rates is None:
            if self._allow_unknown_pricing:
                LOGGER.warning("unknown model pricing for %s; treating as zero by explicit override", model)
                return 0.0
            raise ValueError(
                f"unknown LLM model pricing for {model!r}; configure model_pricing before using it"
            )
        return (
            (prompt_tokens / 1_000_000.0) * rates.get("input", 0.0)
            + (completion_tokens / 1_000_000.0) * rates.get("output", 0.0)
        )

    def record(
        self,
        *,
        provider: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        role: str = "analysis",
    ) -> CostRecord:
        cost = self.cost_for(model, prompt_tokens, completion_tokens)
        rec = CostRecord(
            timestamp=time.time(),
            provider=provider,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=cost,
            role=role,
        )
        if self._persist_path is None:
            projected_total = self._local_total_cost() + cost
            if self._max_cost_usd > 0 and projected_total > self._max_cost_usd:
                raise CostCeilingExceeded(
                    f"cost ceiling exceeded: ${projected_total:.4f} > ${self._max_cost_usd:.4f}"
                )
            self._records.append(rec)
            return rec

        with closing(sqlite3.connect(str(self._persist_path), timeout=5.0)) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("BEGIN IMMEDIATE")
            persisted_total = float(
                conn.execute("SELECT COALESCE(SUM(cost_usd), 0) FROM cost_records").fetchone()[0] or 0.0
            )
            projected_total = max(self._local_total_cost(), persisted_total) + cost
            if self._max_cost_usd > 0 and projected_total > self._max_cost_usd:
                conn.rollback()
                raise CostCeilingExceeded(
                    f"cost ceiling exceeded: ${projected_total:.4f} > ${self._max_cost_usd:.4f}"
                )
            conn.execute(
                "INSERT INTO cost_records (timestamp, provider, model, "
                "prompt_tokens, completion_tokens, cost_usd, role) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (rec.timestamp, rec.provider, rec.model, rec.prompt_tokens,
                 rec.completion_tokens, rec.cost_usd, rec.role),
            )
            conn.commit()
        self._records.append(rec)
        return rec

    def _local_total_cost(self) -> float:
        return sum(r.cost_usd for r in self._records)

    def total_cost(self) -> float:
        local = self._local_total_cost()
        if self._persist_path is None:
            return local
        try:
            with closing(sqlite3.connect(str(self._persist_path), timeout=5.0)) as conn:
                conn.execute("PRAGMA busy_timeout=5000")
                persisted = float(
                    conn.execute("SELECT COALESCE(SUM(cost_usd), 0) FROM cost_records").fetchone()[0] or 0.0
                )
                return max(local, persisted)
        except sqlite3.Error:
            return local

    def total_tokens(self) -> tuple[int, int]:
        """Return (prompt_tokens, completion_tokens) totals."""
        return (
            sum(r.prompt_tokens for r in self._records),
            sum(r.completion_tokens for r in self._records),
        )

    def by_role(self) -> dict[str, dict[str, float]]:
        out: dict[str, dict[str, float]] = {}
        for r in self._records:
            entry = out.setdefault(r.role, {"cost": 0.0, "calls": 0, "tokens_in": 0, "tokens_out": 0})
            entry["cost"] += r.cost_usd
            entry["calls"] += 1
            entry["tokens_in"] += r.prompt_tokens
            entry["tokens_out"] += r.completion_tokens
        return out

    def summary(self) -> dict[str, object]:
        return {
            "total_cost_usd": self.total_cost(),
            "total_prompt_tokens": self.total_tokens()[0],
            "total_completion_tokens": self.total_tokens()[1],
            "by_role": self.by_role(),
            "calls": len(self._records),
        }

    def records(self) -> list[CostRecord]:
        return list(self._records)

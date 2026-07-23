"""
High-level AIClient.

Wraps a list of :class:`AIProvider` instances with:

- **prompt-injection guard** — sanitizes user-supplied code before
  it is inserted into the prompt.
- **response caching** — keyed on (model, prompt, temperature, seed)
  so a re-run against the same target is free.
- **circuit breaker** — if a provider returns 5 errors in a row, it
  is taken out of rotation for 60 s; the client falls through to
  the next provider in the list.
- **deterministic replay** — ``seed`` parameter is propagated to the
  provider when supported.
- **cost tracking** — every call is recorded and the per-run cost
  is enforced against the configured ceiling.

This is the *only* class the scanner core needs to know about;
provider switching and error recovery are transparent.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping

from web3guard.ai.cost import CostTracker
from web3guard.ai.provider import (
    AIProvider,
    ChatMessage,
    ChatResponse,
    ProviderError,
)
from web3guard.security import PromptInjectionGuard

LOGGER = logging.getLogger("web3guard.ai.client")


@dataclass
class CircuitBreakerState:
    """Per-provider circuit breaker state."""
    consecutive_errors: int = 0
    opened_at: float = 0.0

    def is_open(self, *, cooldown: float = 60.0) -> bool:
        if self.consecutive_errors < 5:
            return False
        return (time.monotonic() - self.opened_at) < cooldown

    def record_error(self) -> None:
        self.consecutive_errors += 1
        if self.consecutive_errors == 5:
            self.opened_at = time.monotonic()

    def record_success(self) -> None:
        self.consecutive_errors = 0
        self.opened_at = 0.0


class AIClient:
    """High-level client with multi-provider fallback, caching, and cost tracking.

    The scanner core uses this directly; it does not interact with
    individual providers.
    """

    def __init__(
        self,
        *,
        providers: list[AIProvider],
        model: str = "deepseek-ai/deepseek-v4-flash",
        cost_tracker: CostTracker | None = None,
        cache_path: Path | None = None,
        injection_guard: PromptInjectionGuard | None = None,
        default_seed: int | None = 0,
        circuit_cooldown_seconds: float = 60.0,
        max_retries_per_provider: int = 2,
    ) -> None:
        if not providers:
            raise ValueError("at least one AIProvider is required")
        self._providers = providers
        self._model = model
        self._cost = cost_tracker or CostTracker()
        self._guard = injection_guard or PromptInjectionGuard()
        self._seed = default_seed
        self._cache_path = cache_path
        self._circuit = {p.name: CircuitBreakerState() for p in providers}
        self._cooldown = circuit_cooldown_seconds
        self._max_retries = max_retries_per_provider
        if cache_path is not None:
            self._init_cache(cache_path)

    # ---- configuration ---------------------------------------------------

    def set_model(self, model: str) -> None:
        self._model = model

    def set_seed(self, seed: int | None) -> None:
        self._seed = seed

    def cost_tracker(self) -> CostTracker:
        return self._cost

    # ---- cache -----------------------------------------------------------

    def _init_cache(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    content TEXT NOT NULL,
                    tokens_in INTEGER NOT NULL,
                    tokens_out INTEGER NOT NULL,
                    cost_usd REAL NOT NULL,
                    ts REAL NOT NULL
                )
            """)
            conn.commit()

    def _cache_key(self, messages: list[ChatMessage], *, model: str,
                   temperature: float, max_tokens: int, seed: int | None) -> str:
        h = hashlib.sha256()
        h.update(model.encode())
        h.update(f"|t={temperature}|m={max_tokens}|s={seed}".encode())
        for m in messages:
            h.update(f"|{m.role}|".encode())
            h.update(m.content.encode())
        return h.hexdigest()

    def _cache_get(self, key: str) -> ChatResponse | None:
        if self._cache_path is None:
            return None
        with sqlite3.connect(str(self._cache_path)) as conn:
            row = conn.execute(
                "SELECT content, tokens_in, tokens_out, cost_usd FROM cache WHERE key=?",
                (key,),
            ).fetchone()
        if row is None:
            return None
        return ChatResponse(
            content=row[0],
            model=self._model,
            prompt_tokens=row[1],
            completion_tokens=row[2],
            total_tokens=row[1] + row[2],
            finish_reason="cached",
            raw={"cached": True},
            provider="cache",
            latency_ms=0,
            cost_usd=row[3],
        )

    def _cache_put(self, key: str, response: ChatResponse) -> None:
        if self._cache_path is None:
            return
        with sqlite3.connect(str(self._cache_path)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cache (key, content, tokens_in, tokens_out, cost_usd, ts) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (key, response.content, response.prompt_tokens,
                 response.completion_tokens, response.cost_usd, time.time()),
            )
            conn.commit()

    # ---- public API ------------------------------------------------------

    def chat(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int = 1500,
        temperature: float = 0.0,
        role: str = "analysis",
        response_format: Mapping[str, object] | None = None,
        bypass_injection_check: bool = False,
    ) -> ChatResponse:
        """Send a system+user prompt and return a normalized response.

        Steps:
        1. Sanitize the user prompt for prompt-injection patterns.
        2. Wrap the user content in a quarantine tag.
        3. Check the response cache.
        4. Walk through providers in order; skip any whose circuit
           breaker is open; retry transient errors; fall through on
           non-retryable errors.
        5. Validate the response for signs of a successful injection.
        6. Record the cost and cache the response.
        """
        # 1. Sanitize
        if not bypass_injection_check:
            scan = self._guard.scan(user, source_label="user_prompt")
            if scan.verdict.value == "rejected":
                raise RuntimeError(
                    f"prompt rejected by injection guard: {scan.notes}"
                )
            user = scan.sanitized_text
        # 2. Quarantine wrap. We always wrap the user content; this is
        #    cheap insurance.
        system = system + "\n\n" + self._guard.quarantine("", source_label="placeholder")
        user_quarantined = self._guard.quarantine(user, source_label="target_chunk")

        messages = [
            ChatMessage(role="system", content=system),
            ChatMessage(role="user", content=user_quarantined),
        ]
        # 3. Cache check
        key = self._cache_key(messages, model=self._model, temperature=temperature,
                              max_tokens=max_tokens, seed=self._seed)
        cached = self._cache_get(key)
        if cached is not None:
            LOGGER.info("cache hit: %s", key[:12])
            return cached

        # 4. Walk providers
        last_error: ProviderError | None = None
        for provider in self._providers:
            state = self._circuit[provider.name]
            if state.is_open(cooldown=self._cooldown):
                LOGGER.warning("circuit open for %s, skipping", provider.name)
                continue
            for attempt in range(1, self._max_retries + 1):
                try:
                    response = provider.chat(
                        messages,
                        model=self._model,
                        max_tokens=max_tokens,
                        temperature=temperature,
                        seed=self._seed,
                        response_format=response_format,
                    )
                    state.record_success()
                except ProviderError as e:
                    last_error = e
                    state.record_error()
                    if e.status_code == 429 and attempt < self._max_retries:
                        backoff = 2 ** attempt
                        LOGGER.info("rate limited on %s, backing off %ds",
                                    provider.name, backoff)
                        time.sleep(backoff)
                        continue
                    if not e.retryable:
                        LOGGER.warning("non-retryable error on %s, falling through: %s",
                                       provider.name, e)
                        break
                    if attempt < self._max_retries:
                        backoff = 2 ** attempt
                        time.sleep(backoff)
                        continue
                    LOGGER.warning("exhausted retries on %s, falling through: %s",
                                   provider.name, e)
                    break
                else:
                    # 5. Validate response
                    clean, reason = self._guard.validate_response(response.content)
                    if not clean:
                        LOGGER.warning("response from %s looks injected: %s",
                                       provider.name, reason)
                        # Drop the response and try the next provider.
                        break
                    # 6. Record cost
                    self._cost.record(
                        provider=provider.name,
                        model=response.model or self._model,
                        prompt_tokens=response.prompt_tokens,
                        completion_tokens=response.completion_tokens,
                        role=role,
                    )
                    # Cache
                    self._cache_put(key, response)
                    return response
        # If we got here, every provider failed.
        raise RuntimeError(
            f"all AI providers failed: last error = {last_error!r}"
        )

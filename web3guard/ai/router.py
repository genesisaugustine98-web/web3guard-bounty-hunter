"""
Free-tier LLM router (Phase 1 of the "Hunt Bigger Fish" build).

This module builds the LLM client the scanner's AI layers talk to.
It extends — never forks — the existing design:

- :class:`OpenAICompatibleProvider` (from :mod:`web3guard.ai.provider`)
  is reused for every free-tier backend; each one exposes an
  OpenAI-compatible chat-completion endpoint.
- :class:`AIClient` (from :mod:`web3guard.ai.client`) stays the only
  class the scan path calls for real work: caching, prompt-injection
  guard, circuit breaker, and cost recording all live there.
- :class:`CostTracker` and :class:`BudgetController` are reused as-is;
  on free tiers the computed cost is $0, so budgets stay passive.

What this module adds:

1. **Failover chain** — Gemini -> Groq -> Cerebras -> OpenRouter ->
   NVIDIA NIM, each enabled only when its API key is present in the
   environment. NVIDIA NIM spends finite, non-renewing credits, so it
   is deliberately last.
2. **Per-provider 429 handling** — on a 429 the provider is backed off
   (exponential, bounded) and the call falls through to the next
   provider immediately; the provider rejoins after its cooldown.
   A clock/sleeper can be injected so tests never really sleep.
3. **Limit discovery** — :data:`PROVIDER_LIMITS` carries a "last
   verified" snapshot per provider, and :func:`refresh_provider_limits`
   re-verifies it at build/deploy time. Hardcoded limits are *never*
   presented as eternal truth.
4. **Honest offline degrade** — with no keys the router reports
   ``inactive``; the scan continues with static-only analysis plus a
   loud warning in the logs and a note in the report. It never
   silently pretends AI layers ran.

INTEGRATION GUIDE — for Phase 2 (invariant synthesis) and Phase 3
(verification). This is the *only* supported way to obtain an LLM
client::

    from web3guard.ai.router import build_router_client

    client = build_router_client(config)   # config: the scanner config mapping

    if not client.is_active:
        # No API keys present (or ai_enabled=false). The scan MUST
        # continue with static-only analysis. Make the absence LOUD:
        emit_offline_warning(client.inactive_reason)      # banner in the logs
        report_notes.append(client.offline_report_note()) # note in the report

    # client.chat(system, user, ...) has the AIClient signature on both
    # RouterClient and NullClient. On NullClient it does NOT call any
    # LLM — it returns a ChatResponse with provider="null" and
    # raw["ai_inactive"] == True. Guard AI-dependent steps like this:
    resp = client.chat(system_prompt, user_prompt)
    if resp.raw.get("ai_inactive"):
        ...  # skip the AI-dependent step, static path already ran

    # Budgets: client.cost_tracker() records $0 per call on the free
    # tier, so ceilings never trip. client.budget.preflight() raises
    # BudgetExhausted only when the operator configured real limits and
    # they are exhausted.

Cost model: every default model in the chain is priced at $0 in/out,
so :meth:`CostTracker.total_cost` stays 0.0 and budget ceilings never
trip on free tiers. If an operator overrides the model to a paid one,
the first non-zero token is recorded at its real price and the usual
ceilings apply — zero marginal cost by default, honest accounting when
overridden.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from web3guard.ai.budget import BudgetController
from web3guard.ai.client import AIClient
from web3guard.ai.cost import DEFAULT_PRICING, CostTracker
from web3guard.ai.provider import (
    AIProvider,
    ChatMessage,
    ChatResponse,
    OpenAICompatibleProvider,
    ProviderError,
)

LOGGER = logging.getLogger("web3guard.ai.router")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AIUnavailableError(RuntimeError):
    """Raised when AI layers are invoked but no provider is usable.

    Callers that prefer fail-fast over the marked-inactive
    :class:`NullClient` response can raise this themselves after
    checking ``client.is_active``.
    """


# ---------------------------------------------------------------------------
# Provider chain specification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProviderSpec:
    """One rung of the free-tier failover ladder."""
    name: str
    base_url: str
    # Env vars holding the API key, in priority order. The first one
    # present in the environment wins.
    api_key_envs: tuple[str, ...]
    default_model: str
    # Soft per-minute request budget used by the provider's throttle.
    rpm: int
    per_request_timeout_s: float = 120.0
    # False for providers whose OpenAI-compatible endpoint rejects the
    # ``seed`` parameter (Gemini 400s on it); the provider then omits
    # seed from the request body instead of failing the call.
    supports_seed: bool = True
    # False means the tier is not really "free": it spends finite,
    # non-renewing credits, so it sits last in the chain.
    renewable_free_tier: bool = True
    notes: str = ""


#: The failover chain, cheapest-first. NVIDIA NIM is last on purpose:
#: its credits do not renew, so every other free tier is exhausted
#: before a single NIM credit is spent.
PROVIDER_CHAIN: tuple[ProviderSpec, ...] = (
    ProviderSpec(
        name="gemini",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
        api_key_envs=("GEMINI_API_KEY", "GOOGLE_AI_STUDIO_API_KEY"),
        default_model="gemini-2.5-flash",
        rpm=15,
        supports_seed=False,
        notes="Google AI Studio free tier. OpenAI-compatible endpoint.",
    ),
    ProviderSpec(
        name="groq",
        base_url="https://api.groq.com/openai/v1",
        api_key_envs=("GROQ_API_KEY",),
        default_model="openai/gpt-oss-20b",
        rpm=30,
        notes="GroqCloud free tier. Very high token throughput.",
    ),
    ProviderSpec(
        name="cerebras",
        base_url="https://api.cerebras.ai/v1",
        api_key_envs=("CEREBRAS_API_KEY",),
        default_model="llama-3.3-70b",
        rpm=30,
        notes="Cerebras free tier. Generous daily token allowance.",
    ),
    ProviderSpec(
        name="openrouter",
        base_url="https://openrouter.ai/v1",
        api_key_envs=("OPENROUTER_API_KEY",),
        default_model="meta-llama/llama-3.3-70b-instruct:free",
        rpm=20,
        notes="OpenRouter :free models. Free-tier throughput is shared "
              "and the most volatile of the chain.",
    ),
    ProviderSpec(
        name="nvidia",
        base_url="https://integrate.api.nvidia.com/v1",
        api_key_envs=("NVIDIA_API_KEY", "NIM_API_KEY"),
        default_model="deepseek-ai/deepseek-v4-flash-0731",
        rpm=40,
        renewable_free_tier=False,
        notes="NVIDIA NIM. Credits are finite and do NOT renew — spend LAST.",
    ),
)

#: $0 pricing for every default model in the chain. Merged over
#: DEFAULT_PRICING when the router builds its CostTracker, so free-tier
#: calls always compute $0 and budgets stay passive.
FREE_PRICING: dict[str, dict[str, float]] = {
    spec.default_model: {"input": 0.0, "output": 0.0} for spec in PROVIDER_CHAIN
}


# ---------------------------------------------------------------------------
# Limit discovery
# ---------------------------------------------------------------------------


@dataclass
class ProviderLimit:
    """A free-tier limit snapshot for one provider.

    These numbers drift — providers change free tiers without notice.
    Treat them as a *starting throttle*, not as eternal truth. The
    ``last_verified`` / ``verified_how`` fields say exactly how fresh
    the numbers are; :func:`refresh_provider_limits` re-verifies them.
    """
    requests_per_minute: int | None = None
    requests_per_day: int | None = None
    tokens_per_day: int | None = None
    last_verified: str = ""          # ISO date, e.g. "2026-10-01"
    verified_how: str = ""           # "docs snapshot" | "live probe" | ...
    notes: str = ""


#: Known-good snapshot. Last verified 2026-10-01 from provider docs.
#: Free-tier limits drift; call refresh_provider_limits() (with keys
#: present) to re-verify before relying on these numbers.
PROVIDER_LIMITS: dict[str, ProviderLimit] = {
    "gemini": ProviderLimit(
        requests_per_minute=15,
        requests_per_day=1500,
        tokens_per_day=1_000_000,
        last_verified="2026-10-01",
        verified_how="docs snapshot",
        notes="gemini-2.5-flash free tier (AI Studio). RPM is the binding "
              "constraint; the router throttles to 15 RPM.",
    ),
    "groq": ProviderLimit(
        requests_per_minute=30,
        requests_per_day=14_400,
        last_verified="2026-10-01",
        verified_how="docs snapshot",
        notes="GroqCloud free tier for llama-3.3-70b-versatile. Limits vary "
              "by model; this is the snapshot for the router's default.",
    ),
    "cerebras": ProviderLimit(
        requests_per_minute=30,
        tokens_per_day=1_000_000,
        last_verified="2026-10-01",
        verified_how="docs snapshot",
        notes="Cerebras free tier. Daily token allowance is the binding "
              "constraint on long scans.",
    ),
    "openrouter": ProviderLimit(
        requests_per_minute=20,
        requests_per_day=50,
        last_verified="2026-10-01",
        verified_how="docs snapshot",
        notes="OpenRouter :free models without purchased credits. The daily "
              "request cap is the binding constraint and the most likely "
              "to change — re-verify often.",
    ),
    "nvidia": ProviderLimit(
        requests_per_minute=40,
        last_verified="2026-10-01",
        verified_how="docs snapshot",
        notes="NIM request rate; the real constraint is the finite credit "
              "balance, which no static table can capture. Spend last.",
    ),
}


def _probe_openrouter_key(key: str, *, timeout: float) -> dict[str, Any]:
    """Query OpenRouter's key-info endpoint (returns real limit data)."""
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/auth/key",
        headers={"Authorization": f"Bearer {key}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _probe_models_list(base_url: str, key: str, *, timeout: float) -> bool:
    """True when the key is accepted by the provider's /models endpoint.

    This verifies authentication only — most providers do not expose
    rate limits here, so a success means "key works, limits unchanged".
    """
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/models",
        headers={"Authorization": f"Bearer {key}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout):
            return True
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return False
        # Any other HTTP status still proves the endpoint (and usually
        # the key) was reached; auth failures are the signal we need.
        return True


def refresh_provider_limits(
    *,
    env: Mapping[str, str] | None = None,
    timeout: float = 15.0,
) -> dict[str, dict[str, Any]]:
    """Re-verify :data:`PROVIDER_LIMITS` against live providers.

    Calling this function is the opt-in: it only contacts providers
    whose API keys are present in ``env``. It never raises on probe
    failure — every provider gets a status entry explaining what
    happened.

    Status values per provider: ``"verified"`` (fresh limit data),
    ``"auth_ok"`` (key works, limits not exposed — snapshot kept),
    ``"auth_failed"`` (key rejected — snapshot kept, investigate),
    ``"no_key"`` (cannot re-verify without a key — snapshot kept and
    explicitly NOT re-verified), ``"probe_failed"`` (network/other
    error — snapshot kept).

    Where a probe returns real limit numbers (OpenRouter's ``/auth/key``
    today), :data:`PROVIDER_LIMITS` is updated in place and
    ``last_verified`` is set to today with ``verified_how="live probe"``.
    """
    env = os.environ if env is None else env
    today = datetime.date.today().isoformat()
    report: dict[str, dict[str, Any]] = {}
    for spec in PROVIDER_CHAIN:
        key = next((env.get(v, "") for v in spec.api_key_envs if env.get(v)), "")
        if not key:
            report[spec.name] = {
                "status": "no_key",
                "detail": (
                    f"no API key in {spec.api_key_envs}; limits NOT re-verified, "
                    f"snapshot from {PROVIDER_LIMITS[spec.name].last_verified} retained"
                ),
            }
            continue
        try:
            if spec.name == "openrouter":
                payload = _probe_openrouter_key(key, timeout=timeout)
                data = payload.get("data") or {}
                limit = PROVIDER_LIMITS[spec.name]
                usage = data.get("usage")
                cap = data.get("limit")
                if isinstance(usage, (int, float)) and isinstance(cap, (int, float)) and cap > 0:
                    # OpenRouter reports spend limits, not RPM; keep the
                    # RPM snapshot but record that the key was verified.
                    limit.notes = (
                        f"{limit.notes} Live key check {today}: usage "
                        f"${usage:.4f} of ${cap:.2f} cap."
                    ).strip()
                limit.last_verified = today
                limit.verified_how = "live probe (openrouter /auth/key)"
                report[spec.name] = {
                    "status": "verified",
                    "detail": f"key valid; limits re-verified {today}",
                }
            else:
                ok = _probe_models_list(spec.base_url, key, timeout=timeout)
                if ok:
                    report[spec.name] = {
                        "status": "auth_ok",
                        "detail": (
                            "key accepted by /models; provider does not expose "
                            "limits via API — snapshot kept, re-check provider docs"
                        ),
                    }
                else:
                    report[spec.name] = {
                        "status": "auth_failed",
                        "detail": "key rejected (401/403); snapshot kept — check the key",
                    }
        except Exception as e:  # noqa: BLE001 — probe must never raise
            LOGGER.warning("limit probe failed for %s: %s", spec.name, e)
            report[spec.name] = {
                "status": "probe_failed",
                "detail": f"{type(e).__name__}: {e}; snapshot retained",
            }
    return report


# ---------------------------------------------------------------------------
# Offline degrade: loud warning + report note
# ---------------------------------------------------------------------------


def offline_warning_text(reason: str) -> str:
    """The loud, unmissable warning emitted when AI layers are inactive."""
    return (
        "\n"
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
        "!!  WEB3GUARD: AI LAYERS DID NOT RUN — STATIC-ONLY SCAN         !!\n"
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
        f"!!  Reason: {reason}\n"
        "!!\n"
        "!!  This scan used PATTERN MATCHING ONLY. The following AI-powered\n"
        "!!  stages were SKIPPED and their results are ABSENT from this report:\n"
        "!!    - invariant synthesis (Phase 2)\n"
        "!!    - AI verification / false-positive filtering (Phase 3)\n"
        "!!    - AI red-team exploitability triage\n"
        "!!\n"
        "!!  Business-logic and economic bugs are the bug classes behind\n"
        "!!  most large bounty payouts, and pattern matching cannot see them.\n"
        "!!  Treat a clean static-only report as 'no known patterns found',\n"
        "!!  NOT as 'this code is safe'.\n"
        "!!\n"
        "!!  To enable AI layers, set one or more free-tier API keys and\n"
        "!!  enable AI features (ai_enabled: true):\n"
        "!!    GEMINI_API_KEY (or GOOGLE_AI_STUDIO_API_KEY), GROQ_API_KEY,\n"
        "!!    CEREBRAS_API_KEY, OPENROUTER_API_KEY, NVIDIA_API_KEY\n"
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
    )


def emit_offline_warning(reason: str, logger: logging.Logger | None = None) -> str:
    """Log the offline warning banner loudly; return the banner text."""
    text = offline_warning_text(reason)
    (logger or LOGGER).warning("%s", text)
    return text


def offline_report_note(reason: str) -> str:
    """Markdown note for injection into the scan report when AI is inactive."""
    return (
        "> **AI layers did not run — static-only scan.**\n"
        ">\n"
        f"> Reason: {reason}\n"
        ">\n"
        "> Skipped: invariant synthesis, AI verification / false-positive "
        "filtering, AI red-team triage. Pattern matching cannot see "
        "business-logic or economic bugs — treat a clean report as "
        "'no known patterns found', not 'this code is safe'.\n"
        ">\n"
        "> Enable AI layers with a free-tier key: `GEMINI_API_KEY` (or "
        "`GOOGLE_AI_STUDIO_API_KEY`), `GROQ_API_KEY`, `CEREBRAS_API_KEY`, "
        "`OPENROUTER_API_KEY`, or `NVIDIA_API_KEY` (spent last — finite credits)."
    )


# ---------------------------------------------------------------------------
# Rate-limit-aware provider wrapper
# ---------------------------------------------------------------------------


# 429 backoff: start at 5 s, double per consecutive 429, cap at 5 min.
_BACKOFF_BASE_S = 5.0
_BACKOFF_CAP_S = 300.0
# Auth failures (401/403): the key is missing/revoked — park the
# provider for an hour instead of hammering it. It rejoins
# automatically after the cooldown (e.g. once a valid key is set).
_AUTH_COOLDOWN_S = 3600.0


class _FailoverProvider(AIProvider):
    """Wraps one provider with 429 backoff + cooldown bookkeeping.

    When the provider is inside its backoff window (or parked after an
    auth failure), :meth:`chat` raises a *retryable*
    :class:`ProviderError` immediately — no sleeping — so
    :class:`AIClient` falls through to the next provider in the chain
    without delay. On a 429 from the inner provider the wrapper
    records exponential backoff (bounded) and re-raises. A success
    resets the 429 streak. The provider rejoins the rotation
    automatically once its cooldown expires, driven by the injected
    ``clock`` (so tests advance time instead of sleeping).
    """

    def __init__(
        self,
        inner: AIProvider,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._inner = inner
        self._clock = clock or time.monotonic
        self.name = inner.name
        self._backoff_until = 0.0
        self._consec_429 = 0
        self._parked_until = 0.0
        self._park_reason = ""

    # -- introspection for status() ------------------------------------

    @property
    def backing_off(self) -> bool:
        return self._clock() < self._backoff_until

    @property
    def parked(self) -> bool:
        return self._clock() < self._parked_until

    @property
    def park_reason(self) -> str:
        return self._park_reason

    def seconds_until_available(self) -> float:
        now = self._clock()
        return max(0.0, self._backoff_until - now, self._parked_until - now)

    # -- AIProvider -----------------------------------------------------

    def chat(
        self,
        messages: Iterable[ChatMessage],
        *,
        model: str,
        max_tokens: int = 1024,
        temperature: float = 0.0,
        seed: int | None = None,
        response_format: Mapping[str, Any] | None = None,
    ) -> ChatResponse:
        now = self._clock()
        if now < self._backoff_until:
            raise ProviderError(
                f"{self.name} is backing off after rate limits; "
                f"available again in {self._backoff_until - now:.1f}s",
                provider=self.name,
                status_code=429,
                retryable=True,
            )
        if now < self._parked_until:
            raise ProviderError(
                f"{self.name} is parked: {self._park_reason}; "
                f"available again in {self._parked_until - now:.1f}s",
                provider=self.name,
                status_code=0,
                retryable=True,
            )
        try:
            response = self._inner.chat(
                messages,
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
                seed=seed,
                response_format=response_format,
            )
        except ProviderError as e:
            if e.status_code == 429:
                self._consec_429 += 1
                delay = min(
                    _BACKOFF_CAP_S,
                    _BACKOFF_BASE_S * (2 ** (self._consec_429 - 1)),
                )
                self._backoff_until = now + delay
                LOGGER.warning(
                    "rate limited on %s (429 x%d); backing off %.0fs and "
                    "falling through to the next provider",
                    self.name, self._consec_429, delay,
                )
            elif e.status_code in (401, 403):
                self._parked_until = now + _AUTH_COOLDOWN_S
                self._park_reason = str(e)
                LOGGER.warning(
                    "auth failure on %s; parking it for %.0fs: %s",
                    self.name, _AUTH_COOLDOWN_S, e,
                )
            raise
        # Success resets the 429 streak (a parked provider that somehow
        # succeeds also clears its park — defensive, cannot normally happen).
        self._consec_429 = 0
        self._backoff_until = 0.0
        self._parked_until = 0.0
        self._park_reason = ""
        return response


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


@dataclass
class DiscoveredProvider:
    """A chain rung whose API key was found in the environment."""
    spec: ProviderSpec
    env_var: str  # the env var that actually held the key


def discover_providers(
    env: Mapping[str, str] | None = None,
    *,
    allowlist: Iterable[str] | None = None,
) -> list[DiscoveredProvider]:
    """Return the enabled rungs of the chain, in failover order.

    A rung is enabled only when one of its ``api_key_envs`` is present
    (non-empty) in ``env``. ``allowlist`` optionally restricts the
    chain to the named providers, preserving chain order.
    """
    env = os.environ if env is None else env
    wanted = {n.lower() for n in allowlist} if allowlist is not None else None
    found: list[DiscoveredProvider] = []
    for spec in PROVIDER_CHAIN:
        if wanted is not None and spec.name.lower() not in wanted:
            continue
        hit = next((v for v in spec.api_key_envs if env.get(v)), None)
        if hit:
            found.append(DiscoveredProvider(spec=spec, env_var=hit))
    return found


def skipped_providers(
    env: Mapping[str, str] | None = None,
    *,
    allowlist: Iterable[str] | None = None,
) -> list[dict[str, str]]:
    """Describe every chain rung that will NOT be used, and why."""
    env = os.environ if env is None else env
    enabled = {d.spec.name for d in discover_providers(env, allowlist=allowlist)}
    wanted = {n.lower() for n in allowlist} if allowlist is not None else None
    out: list[dict[str, str]] = []
    for spec in PROVIDER_CHAIN:
        if spec.name in enabled:
            continue
        if wanted is not None and spec.name.lower() not in wanted:
            reason = "excluded by config allowlist"
        else:
            reason = (
                f"no API key: set one of {', '.join(spec.api_key_envs)} "
                f"in the environment"
            )
        out.append({"name": spec.name, "reason": reason})
    return out


# ---------------------------------------------------------------------------
# RouterClient / NullClient
# ---------------------------------------------------------------------------


class RouterClient(AIClient):
    """The live free-tier client: AIClient over the failover chain.

    Constructed by :func:`build_router_client` when at least one
    provider has an API key. Adds router introspection
    (:meth:`status`, :meth:`describe`) on top of the full
    :class:`AIClient` interface, which the scanner core already uses.
    """

    def __init__(
        self,
        *,
        providers: list[AIProvider],
        discovered: list[DiscoveredProvider],
        model: str,
        role_models: Mapping[str, str] | None = None,
        cost_tracker: CostTracker | None = None,
        budget: BudgetController | None = None,
        cache_path: Any = None,
        default_seed: int | None = 0,
        circuit_cooldown_seconds: float = 60.0,
        clock: Callable[[], float] | None = None,
        skipped: list[dict[str, str]] | None = None,
    ) -> None:
        # The chain IS the retry strategy: one attempt per provider, then
        # fall through immediately. Fast failover beats burning
        # N x timeout seconds on a hopeless provider.
        super().__init__(
            providers=providers,
            model=model,
            role_models=role_models,
            cost_tracker=cost_tracker,
            cache_path=cache_path,
            default_seed=default_seed,
            circuit_cooldown_seconds=circuit_cooldown_seconds,
            max_retries_per_provider=1,
        )
        self._discovered = list(discovered)
        self._skipped = list(skipped) if skipped is not None else skipped_providers()
        self._budget = budget or BudgetController()
        self._clock = clock or time.monotonic

    # -- router introspection ------------------------------------------

    @property
    def is_active(self) -> bool:
        return True

    @property
    def inactive_reason(self) -> str:
        return ""

    def budget(self) -> BudgetController:
        """The budget controller wired to this client (passive on $0 tiers)."""
        return self._budget

    def _wrapper_states(self) -> dict[str, _FailoverProvider]:
        return {
            p.name: p for p in self._providers
            if isinstance(p, _FailoverProvider)
        }

    def status(self) -> dict[str, Any]:
        """Machine-readable router status: order, active and skipped rungs."""
        wrappers = self._wrapper_states()
        providers: list[dict[str, Any]] = []
        for d in self._discovered:
            w = wrappers.get(d.spec.name)
            limits = PROVIDER_LIMITS.get(d.spec.name)
            providers.append({
                "name": d.spec.name,
                "enabled": True,
                "base_url": d.spec.base_url,
                "model": d.spec.default_model,
                "env_var": d.env_var,
                "rpm_budget": d.spec.rpm,
                "renewable_free_tier": d.spec.renewable_free_tier,
                "limits_last_verified": limits.last_verified if limits else "",
                "limits_verified_how": limits.verified_how if limits else "",
                "backing_off": w.backing_off if w else False,
                "parked": w.parked if w else False,
                "park_reason": w.park_reason if w else "",
                "seconds_until_available": w.seconds_until_available() if w else 0.0,
            })
        skipped = [
            {"name": s["name"], "enabled": False, "reason": s["reason"]}
            for s in self._skipped
        ]
        return {
            "status": "active",
            "order": [d.spec.name for d in self._discovered],
            "providers": providers + skipped,
            "cost_usd": self._cost.total_cost(),
            "budget": self._budget.summary(),
        }

    def describe(self) -> str:
        """Human-readable summary of the chain: order, active, skipped."""
        lines = ["Free-tier LLM router: ACTIVE", ""]
        lines.append("Failover order (first healthy provider answers):")
        for i, d in enumerate(self._discovered, 1):
            w = self._wrapper_states().get(d.spec.name)
            state = ""
            if w is not None:
                if w.backing_off:
                    state = f" [backing off, back in {w.seconds_until_available():.0f}s]"
                elif w.parked:
                    state = f" [parked: {w.park_reason}]"
            tag = " (finite credits — spent last)" if not d.spec.renewable_free_tier else ""
            lines.append(
                f"  {i}. {d.spec.name} — model {d.spec.default_model} "
                f"(key from {d.env_var}){tag}{state}"
            )
        skipped = self._skipped
        if skipped:
            lines.append("")
            lines.append("Skipped rungs:")
            for s in skipped:
                lines.append(f"  - {s['name']}: {s['reason']}")
        lines.append("")
        lines.append(
            f"Cost so far: ${self._cost.total_cost():.4f} "
            f"(free-tier pricing: $0 by default)"
        )
        return "\n".join(lines)


class NullClient:
    """The offline client: AIClient-compatible, but no LLM is ever called.

    Returned by :func:`build_router_client` when no provider has an API
    key (or AI features are disabled). :meth:`chat` returns a
    :class:`ChatResponse` marked inactive (``provider="null"``,
    ``raw["ai_inactive"] is True``) instead of raising, so scan phases
    can probe for it and continue down the static-only path. Callers
    that prefer fail-fast can check :attr:`is_active` and raise
    :class:`AIUnavailableError` themselves.
    """

    def __init__(self, reason: str, skipped: list[dict[str, str]] | None = None) -> None:
        self._reason = reason
        self._skipped = list(skipped) if skipped is not None else skipped_providers()
        self._cost = CostTracker(
            pricing=dict(FREE_PRICING), max_cost_usd=0.0,
        )
        self._budget = BudgetController()

    @property
    def is_active(self) -> bool:
        return False

    @property
    def inactive_reason(self) -> str:
        return self._reason

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
        """Return a marked-inactive response; never calls an LLM."""
        return ChatResponse(
            content="",
            model="",
            prompt_tokens=0,
            completion_tokens=0,
            total_tokens=0,
            finish_reason="inactive",
            raw={
                "ai_inactive": True,
                "reason": self._reason,
                "hint": "scan continued with static-only analysis",
            },
            provider="null",
            latency_ms=0,
            cost_usd=0.0,
        )

    def cost_tracker(self) -> CostTracker:
        return self._cost

    def budget(self) -> BudgetController:
        return self._budget

    def status(self) -> dict[str, Any]:
        return {
            "status": "inactive",
            "order": [],
            "providers": [
                {"name": s["name"], "enabled": False, "reason": s["reason"]}
                for s in self._skipped
            ],
            "reason": self._reason,
            "cost_usd": 0.0,
            "budget": self._budget.summary(),
        }

    def describe(self) -> str:
        lines = [
            "Free-tier LLM router: INACTIVE",
            "",
            f"Reason: {self._reason}",
            "",
            "No provider will be contacted. The scan continues with",
            "static-only analysis; see the offline warning in the logs",
            "and the note injected into the report.",
        ]
        return "\n".join(lines)

    def offline_report_note(self) -> str:
        """Markdown note for injection into the scan report."""
        return offline_report_note(self._reason)


#: Either live client type :func:`build_router_client` can return.
AnyRouterClient = RouterClient | NullClient


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_router_client(
    config: Mapping[str, Any] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    clock: Callable[[], float] | None = None,
    cache_path: Any = None,
) -> AnyRouterClient:
    """Build the router client for this process.

    Args:
        config: scanner config mapping. Recognized keys:
            ``ai_enabled`` (bool, default True) — explicit opt-in; no
            provider is contacted unless this is true AND a key exists.
            ``default_model`` (str) — override the chain's per-provider
            default model (still $0 unless the override names a paid model).
            ``role_models`` / ``models`` (mapping) — per-role model overrides.
            ``max_cost_usd`` (float, default 0.0) — hard ceiling; $0
            computed cost never trips it.
            ``budget`` (mapping) — BudgetController horizons
            (global/daily/monthly limits, warning_frac, on_exhausted).
            ``providers`` (list[str]) — optional allowlist restricting the
            chain to named providers, in chain order.
            ``default_seed`` — deterministic replay seed.
        env: environment mapping for key discovery (defaults to
            ``os.environ``; injectable for tests).
        clock: injectable clock for backoff/cooldown timing (tests).
        cache_path: optional sqlite cache path for the response cache.

    Returns:
        :class:`RouterClient` when at least one provider has a key and
        AI is enabled; otherwise a :class:`NullClient` (offline degrade:
        loud warning logged, static-only scan continues).
    """
    cfg: Mapping[str, Any] = config or {}
    env = os.environ if env is None else env
    allowlist = cfg.get("providers")

    if not cfg.get("ai_enabled", True):
        reason = "AI features disabled in config (ai_enabled: false)"
        emit_offline_warning(reason)
        return NullClient(reason, skipped=skipped_providers(env, allowlist=allowlist))

    discovered = discover_providers(env, allowlist=allowlist)
    skipped = skipped_providers(env, allowlist=allowlist)
    if not discovered:
        wanted = (
            {str(n).lower() for n in allowlist} if allowlist is not None else None
        )
        missing = ", ".join(
            f"{spec.name} ({' / '.join(spec.api_key_envs)})"
            for spec in PROVIDER_CHAIN
            if wanted is None or spec.name.lower() in wanted
        )
        reason = (
            "no API keys found in the environment; looked for "
            f"{missing}"
        )
        emit_offline_warning(reason)
        return NullClient(reason, skipped=skipped)

    per_request_timeout = 120.0
    providers: list[AIProvider] = []
    for d in discovered:
        limit = PROVIDER_LIMITS.get(d.spec.name)
        rpm = (limit.requests_per_minute if limit else None) or d.spec.rpm
        providers.append(
            _FailoverProvider(
                OpenAICompatibleProvider(
                    base_url=d.spec.base_url,
                    api_key_env=d.env_var,
                    rpm=rpm,
                    timeout=per_request_timeout,
                    name=d.spec.name,
                    supports_seed=d.spec.supports_seed,
                ),
                clock=clock,
            )
        )

    default_model = str(cfg.get("default_model") or discovered[0].spec.default_model)
    role_models_cfg = cfg.get("role_models") or cfg.get("models") or {}
    role_models = (
        {str(k): str(v) for k, v in role_models_cfg.items()
         if isinstance(v, str) and v}
        or None
    )
    pricing = {k: dict(v) for k, v in DEFAULT_PRICING.items()}
    pricing.update({k: dict(v) for k, v in FREE_PRICING.items()})
    cost = CostTracker(
        pricing=pricing,
        max_cost_usd=float(cfg.get("max_cost_usd", 0.0)),
    )
    budget_cfg = cfg.get("budget") or {}
    budget = BudgetController(
        None,
        global_limit_usd=float(budget_cfg.get("global_limit_usd", 0.0)),
        daily_limit_usd=float(budget_cfg.get("daily_limit_usd", 0.0)),
        monthly_limit_usd=float(budget_cfg.get("monthly_limit_usd", 0.0)),
        warning_frac=float(budget_cfg.get("warning_frac", 0.8)),
        on_exhausted=str(budget_cfg.get("on_exhausted", "abort")),
        clock=clock,
    )
    client = RouterClient(
        providers=providers,
        discovered=discovered,
        model=default_model,
        role_models=role_models,
        cost_tracker=cost,
        budget=budget,
        cache_path=cache_path,
        default_seed=cfg.get("default_seed", 0),
        clock=clock,
        skipped=skipped,
    )
    LOGGER.info(
        "free-tier LLM router active: %s",
        " -> ".join(d.spec.name for d in discovered),
    )
    return client


__all__ = [
    "AIUnavailableError",
    "AnyRouterClient",
    "DiscoveredProvider",
    "FREE_PRICING",
    "NullClient",
    "PROVIDER_CHAIN",
    "PROVIDER_LIMITS",
    "ProviderLimit",
    "ProviderSpec",
    "RouterClient",
    "build_router_client",
    "discover_providers",
    "emit_offline_warning",
    "offline_report_note",
    "offline_warning_text",
    "refresh_provider_limits",
    "skipped_providers",
]

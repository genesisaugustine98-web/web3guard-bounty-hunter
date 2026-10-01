"""Tests for the free-tier LLM router (Phase 1).

Uses scripted FakeProviders (429s, timeouts, auth errors) and a fake
clock — no real keys, no network calls, no real sleeping.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest  # noqa: E402

from web3guard.ai.budget import BudgetController  # noqa: E402
from web3guard.ai.cost import CostTracker  # noqa: E402
from web3guard.ai.provider import (  # noqa: E402
    AIProvider,
    ChatMessage,
    ChatResponse,
    ProviderError,
)
from web3guard.ai.router import (  # noqa: E402
    FREE_PRICING,
    PROVIDER_CHAIN,
    PROVIDER_LIMITS,
    DiscoveredProvider,
    NullClient,
    RouterClient,
    _FailoverProvider,
    build_router_client,
    discover_providers,
    refresh_provider_limits,
    skipped_providers,
)

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeProvider(AIProvider):
    """Scripted provider. Script entries are ChatResponse (returned) or
    ProviderError (raised). An exhausted script repeats its last entry."""

    def __init__(self, name: str, script: list[Any]) -> None:
        self.name = name
        self._script = list(script)
        self.calls = 0

    def chat(
        self,
        messages: Iterable[ChatMessage],
        *,
        model: str,
        max_tokens: int = 1024,
        temperature: float = 0.0,
        seed: int | None = None,
        response_format: dict[str, Any] | None = None,
    ) -> ChatResponse:
        self.calls += 1
        entry = self._script[min(self.calls - 1, len(self._script) - 1)]
        if isinstance(entry, ProviderError):
            raise entry
        assert isinstance(entry, ChatResponse)
        entry.provider = self.name
        return entry


class FakeClock:
    """Injectable clock + sleeper. advance() moves time; no real sleeping."""

    def __init__(self) -> None:
        self.now_s = 1_000.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now_s

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)

    def advance(self, seconds: float) -> None:
        self.now_s += seconds


def _ok(content: str = "done", model: str = "llama-3.3-70b-versatile") -> ChatResponse:
    return ChatResponse(
        content=content,
        model=model,
        prompt_tokens=100,
        completion_tokens=50,
        total_tokens=150,
        finish_reason="stop",
    )


def _err429(name: str) -> ProviderError:
    return ProviderError("rate limited", provider=name, status_code=429, retryable=True)


def _err401(name: str) -> ProviderError:
    return ProviderError("bad key", provider=name, status_code=401, retryable=False)


def _err_timeout(name: str) -> ProviderError:
    return ProviderError("timed out", provider=name, status_code=408, retryable=True)


def _make_router(
    scripts: list[tuple[str, list[Any]]],
    clock: FakeClock,
    *,
    config: dict[str, Any] | None = None,
) -> tuple[RouterClient, dict[str, FakeProvider]]:
    """Build a RouterClient over wrapped FakeProviders (no network)."""
    by_name = {s.name: s for s in PROVIDER_CHAIN}
    fakes: dict[str, FakeProvider] = {}
    providers: list[AIProvider] = []
    discovered: list[DiscoveredProvider] = []
    for name, script in scripts:
        fake = FakeProvider(name, script)
        fakes[name] = fake
        providers.append(_FailoverProvider(fake, clock=clock))
        discovered.append(
            DiscoveredProvider(spec=by_name[name], env_var="TEST_API_KEY")
        )
    cfg = dict(config or {})
    skipped = [
        {"name": s.name, "reason": "test"}
        for s in PROVIDER_CHAIN
        if s.name not in fakes
    ]
    client = RouterClient(
        providers=providers,
        discovered=discovered,
        model=str(cfg.get("default_model", "test-model")),
        cost_tracker=CostTracker(
            pricing=dict(FREE_PRICING),
            max_cost_usd=float(cfg.get("max_cost_usd", 0.0)),
        ),
        budget=BudgetController(),
        default_seed=0,
        clock=clock,
        skipped=skipped,
    )
    return client, fakes


# ---------------------------------------------------------------------------
# Chain discovery / key gating
# ---------------------------------------------------------------------------


def test_failover_order_is_cheapest_first_nvidia_last():
    names = [s.name for s in PROVIDER_CHAIN]
    assert names == ["gemini", "groq", "cerebras", "openrouter", "nvidia"]
    assert not PROVIDER_CHAIN[-1].renewable_free_tier  # finite credits: spent last


def test_all_keyed_providers_enabled_in_order():
    env = {
        "GEMINI_API_KEY": "a",
        "GROQ_API_KEY": "b",
        "CEREBRAS_API_KEY": "c",
        "OPENROUTER_API_KEY": "d",
        "NVIDIA_API_KEY": "e",
    }
    client = build_router_client({}, env=env)
    assert isinstance(client, RouterClient)
    assert client.is_active
    assert client.status()["order"] == ["gemini", "groq", "cerebras", "openrouter", "nvidia"]


def test_providers_without_keys_are_skipped():
    env = {"GROQ_API_KEY": "b"}
    client = build_router_client({}, env=env)
    assert isinstance(client, RouterClient)
    status = client.status()
    assert status["order"] == ["groq"]
    skipped = {p["name"]: p for p in status["providers"] if not p["enabled"]}
    assert "gemini" in skipped
    assert "GEMINI_API_KEY" in skipped["gemini"]["reason"]
    assert "nvidia" in skipped
    # gemini also accepts the GOOGLE_AI_STUDIO_API_KEY alias
    client2 = build_router_client({}, env={"GOOGLE_AI_STUDIO_API_KEY": "x"})
    assert isinstance(client2, RouterClient)
    assert client2.status()["order"] == ["gemini"]


def test_nvidia_accepts_legacy_nim_api_key_alias():
    client = build_router_client({}, env={"NIM_API_KEY": "x"})
    assert isinstance(client, RouterClient)
    assert client.status()["order"] == ["nvidia"]


def test_discover_providers_allowlist_restricts_chain():
    env = {"GEMINI_API_KEY": "a", "GROQ_API_KEY": "b", "CEREBRAS_API_KEY": "c"}
    found = discover_providers(env, allowlist=["cerebras", "groq"])
    assert [d.spec.name for d in found] == ["groq", "cerebras"]  # chain order kept
    skipped = skipped_providers(env, allowlist=["groq"])
    by_name = {s["name"]: s for s in skipped}
    assert "allowlist" in by_name["gemini"]["reason"]


def test_ai_disabled_returns_null_client_even_with_keys():
    client = build_router_client({"ai_enabled": False}, env={"GROQ_API_KEY": "x"})
    assert isinstance(client, NullClient)
    assert not client.is_active


# ---------------------------------------------------------------------------
# 429 backoff + fallthrough (fake clock, no real sleeping)
# ---------------------------------------------------------------------------


def test_429_backs_off_and_falls_through():
    clock = FakeClock()
    client, fakes = _make_router(
        [("groq", [_err429("groq"), _ok("groq-ok")]), ("cerebras", [_ok("cerebras-ok")])],
        clock,
    )
    # First call: groq 429s -> backed off -> falls through to cerebras.
    resp = client.chat("sys", "hello")
    assert resp.content == "cerebras-ok"
    assert fakes["groq"].calls == 1
    assert fakes["cerebras"].calls == 1
    assert clock.sleeps == []  # never really slept

    # Second call: groq still in backoff -> straight to cerebras, no groq call.
    resp = client.chat("sys", "hello")
    assert resp.content == "cerebras-ok"
    assert fakes["groq"].calls == 1
    assert fakes["cerebras"].calls == 2

    # Status reports the backoff.
    providers = {p["name"]: p for p in client.status()["providers"] if p["enabled"]}
    assert providers["groq"]["backing_off"] is True
    assert providers["groq"]["seconds_until_available"] > 0

    # After the cooldown, groq rejoins the rotation automatically.
    clock.advance(6.0)
    resp = client.chat("sys", "hello")
    assert resp.content == "groq-ok"
    assert fakes["groq"].calls == 2


def test_429_backoff_is_exponential_and_bounded():
    clock = FakeClock()
    wrapper = _FailoverProvider(FakeProvider("groq", [_err429("groq")]), clock=clock)
    msgs = [ChatMessage(role="user", content="hi")]
    with pytest.raises(ProviderError):
        wrapper.chat(msgs, model="m")
    first_wait = wrapper.seconds_until_available()
    assert 4.9 < first_wait <= 5.0
    clock.advance(first_wait + 0.1)
    with pytest.raises(ProviderError):
        wrapper.chat(msgs, model="m")
    second_wait = wrapper.seconds_until_available()
    assert 9.9 < second_wait <= 10.0  # doubled
    # Hammer it: the cap (5 min) is never exceeded.
    for _ in range(10):
        clock.advance(wrapper.seconds_until_available() + 0.1)
        with pytest.raises(ProviderError):
            wrapper.chat(msgs, model="m")
    assert wrapper.seconds_until_available() <= 300.0


def test_auth_error_parks_provider_then_recovers_after_cooldown():
    clock = FakeClock()
    client, fakes = _make_router(
        [("groq", [_err401("groq"), _ok("groq-ok")]), ("cerebras", [_ok("cerebras-ok")])],
        clock,
    )
    resp = client.chat("sys", "hello")
    assert resp.content == "cerebras-ok"  # 401 falls through
    assert fakes["groq"].calls == 1

    clock.advance(600.0)  # 10 min < 1h park
    client.chat("sys", "hello")
    assert fakes["groq"].calls == 1  # still parked

    clock.advance(3600.0)  # past the park
    resp = client.chat("sys", "hello")
    assert resp.content == "groq-ok"
    assert fakes["groq"].calls == 2


def test_timeout_falls_through_to_next_provider():
    clock = FakeClock()
    client, fakes = _make_router(
        [("groq", [_err_timeout("groq")]), ("cerebras", [_ok("ok")])],
        clock,
    )
    resp = client.chat("sys", "hello")
    assert resp.content == "ok"
    assert fakes["groq"].calls == 1
    assert fakes["cerebras"].calls == 1


def test_all_providers_429_raises_without_hard_loop_or_sleep():
    clock = FakeClock()
    client, fakes = _make_router(
        [("groq", [_err429("groq")]), ("cerebras", [_err429("cerebras")])],
        clock,
    )
    with pytest.raises(RuntimeError, match="all AI providers failed"):
        client.chat("sys", "hello")
    # Each provider tried exactly once; backing off short-circuits the rest.
    assert fakes["groq"].calls == 1
    assert fakes["cerebras"].calls == 1
    assert clock.sleeps == []
    # A second attempt while everything backs off also terminates promptly.
    with pytest.raises(RuntimeError, match="all AI providers failed"):
        client.chat("sys", "hello")
    assert fakes["groq"].calls == 1
    assert fakes["cerebras"].calls == 1


# ---------------------------------------------------------------------------
# Offline degrade
# ---------------------------------------------------------------------------


def test_offline_degrade_loud_warning_and_marked_inactive(caplog):
    with caplog.at_level(logging.WARNING, logger="web3guard.ai.router"):
        client = build_router_client({}, env={})
    assert isinstance(client, NullClient)
    assert not client.is_active
    assert "no API keys" in client.inactive_reason
    # The warning is loud and unmissable.
    assert "AI LAYERS DID NOT RUN" in caplog.text
    assert "STATIC-ONLY SCAN" in caplog.text
    # Status API reports inactive with every rung skipped and why.
    status = client.status()
    assert status["status"] == "inactive"
    assert status["order"] == []
    assert len([p for p in status["providers"] if not p["enabled"]]) == 5
    # chat() never raises and never phones home: marked-inactive response.
    resp = client.chat("sys", "hello")
    assert resp.provider == "null"
    assert resp.raw.get("ai_inactive") is True
    assert resp.cost_usd == 0.0
    # The report note names what was skipped.
    note = client.offline_report_note()
    assert "static-only" in note
    assert "invariant synthesis" in note
    assert "business-logic" in note


def test_null_client_describe_is_honest():
    client = NullClient("test reason")
    text = client.describe()
    assert "INACTIVE" in text
    assert "test reason" in text
    assert "static-only" in text


# ---------------------------------------------------------------------------
# $0 cost never trips budgets
# ---------------------------------------------------------------------------


def test_zero_computed_cost_never_trips_budgets():
    clock = FakeClock()
    client, fakes = _make_router([("groq", [_ok()])], clock)
    for _ in range(25):
        client.chat("sys", "hello")
    assert fakes["groq"].calls == 25
    assert client.cost_tracker().total_cost() == 0.0
    # Even a tiny configured budget stays passive on $0 spend.
    budget = BudgetController(None, global_limit_usd=0.01)
    for _ in range(100):
        budget.record_spend(0.0)
    assert budget.check().state == "ok"
    assert client.budget().check().state == "ok"


def test_free_pricing_covers_every_default_model():
    for spec in PROVIDER_CHAIN:
        assert FREE_PRICING[spec.default_model] == {"input": 0.0, "output": 0.0}


# ---------------------------------------------------------------------------
# Limit discovery / refresh
# ---------------------------------------------------------------------------


def test_provider_limits_snapshot_is_dated_and_honest():
    for spec in PROVIDER_CHAIN:
        limit = PROVIDER_LIMITS[spec.name]
        assert limit.last_verified, f"{spec.name} has no last_verified date"
        assert limit.verified_how, f"{spec.name} has no verified_how"
        assert limit.notes


def test_refresh_provider_limits_without_keys_keeps_snapshot():
    before = {
        name: (lim.last_verified, lim.verified_how, lim.notes)
        for name, lim in PROVIDER_LIMITS.items()
    }
    report = refresh_provider_limits(env={})
    assert set(report) == {s.name for s in PROVIDER_CHAIN}
    for _name, entry in report.items():
        assert entry["status"] == "no_key"
        assert "NOT re-verified" in entry["detail"]
    after = {
        name: (lim.last_verified, lim.verified_how, lim.notes)
        for name, lim in PROVIDER_LIMITS.items()
    }
    assert before == after  # snapshot untouched without keys


# ---------------------------------------------------------------------------
# Introspection
# ---------------------------------------------------------------------------


def test_describe_reports_order_active_and_skipped():
    env = {"GROQ_API_KEY": "b", "NVIDIA_API_KEY": "e"}
    client = build_router_client({}, env=env)
    assert isinstance(client, RouterClient)
    text = client.describe()
    assert "ACTIVE" in text
    assert "1. groq" in text
    assert "2. nvidia" in text
    assert "finite credits" in text  # nvidia spent-last tag
    assert "gemini" in text and "no API key" in text
    assert "$0" in text


def test_status_reports_cost_and_budget():
    env = {"GROQ_API_KEY": "b"}
    client = build_router_client({}, env=env)
    assert isinstance(client, RouterClient)
    status = client.status()
    assert status["status"] == "active"
    assert status["cost_usd"] == 0.0
    assert status["budget"]["state"] == "ok"

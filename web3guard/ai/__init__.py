"""
AI client for Web3Guard.

This package implements the model-facing layer:

- :class:`AIProvider` — protocol every LLM provider implements.
- :class:`OpenAICompatibleProvider` — concrete implementation that
  targets any OpenAI-compatible chat-completion API (NIM, OpenRouter,
  Groq, DeepSeek direct, OpenAI, etc.).
- :class:`AIClient` — high-level wrapper with rate limiting, retry,
  circuit breaker, response caching, prompt-injection guard, and
  deterministic-replay support.
- :class:`CostTracker` — token and dollar cost accounting.

The original scanner only targeted NIM. This layer keeps NIM as the
default but adds OpenRouter, Groq, DeepSeek-direct, and OpenAI as
first-class providers, with a circuit breaker that automatically
falls back to a healthy provider when the primary fails.
"""

from web3guard.ai.client import AIClient
from web3guard.ai.cost import CostRecord, CostTracker
from web3guard.ai.provider import (
    AIProvider,
    ChatMessage,
    ChatResponse,
    OpenAICompatibleProvider,
    ProviderError,
)
from web3guard.ai.router import (
    FREE_PRICING,
    PROVIDER_CHAIN,
    PROVIDER_LIMITS,
    AIUnavailableError,
    AnyRouterClient,
    DiscoveredProvider,
    NullClient,
    ProviderLimit,
    ProviderSpec,
    RouterClient,
    build_router_client,
    discover_providers,
    emit_offline_warning,
    offline_report_note,
    offline_warning_text,
    refresh_provider_limits,
    skipped_providers,
)

__all__ = [
    "AIProvider",
    "OpenAICompatibleProvider",
    "ProviderError",
    "ChatMessage",
    "ChatResponse",
    "AIClient",
    "CostTracker",
    "CostRecord",
    # Phase 1: free-tier router
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

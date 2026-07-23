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

from web3guard.ai.provider import (
    AIProvider,
    OpenAICompatibleProvider,
    ProviderError,
    ChatMessage,
    ChatResponse,
)
from web3guard.ai.client import AIClient
from web3guard.ai.cost import CostTracker, CostRecord

__all__ = [
    "AIProvider",
    "OpenAICompatibleProvider",
    "ProviderError",
    "ChatMessage",
    "ChatResponse",
    "AIClient",
    "CostTracker",
    "CostRecord",
]

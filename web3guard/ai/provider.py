"""
LLM provider protocol and OpenAI-compatible implementation.

The :class:`AIProvider` protocol is the contract every backend
implements. The :class:`OpenAICompatibleProvider` is the only
concrete implementation today — it speaks the OpenAI chat-completion
API and works against any provider that exposes that surface
(NIM, OpenRouter, Groq, DeepSeek, OpenAI, Anthropic-via-proxy,
etc.).

Why OpenAI-compatible? Because every LLM provider worth using in
2026 has either an OpenAI-compatible endpoint or a thin adapter for
one. This keeps the scanner portable and prevents vendor lock-in.
"""

from __future__ import annotations

import abc
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

LOGGER = logging.getLogger("web3guard.ai.provider")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class ChatMessage:
    """One message in a chat-completion request."""
    role: str        # "system" | "user" | "assistant"
    content: str

    def to_dict(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass
class ChatResponse:
    """A chat-completion response, normalized across providers."""
    content: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    finish_reason: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    provider: str = ""
    latency_ms: int = 0
    cost_usd: float = 0.0


class ProviderError(RuntimeError):
    """Raised when a provider call fails irrecoverably.

    Attributes:
        provider: which provider raised
        status_code: HTTP status code if known, else 0
        retryable: whether the caller should retry against the same
            provider or fall back to the next one in the list
    """
    def __init__(self, message: str, *, provider: str = "",
                 status_code: int = 0, retryable: bool = True) -> None:
        super().__init__(message)
        self.provider = provider
        self.status_code = status_code
        self.retryable = retryable


# ---------------------------------------------------------------------------
# Provider protocol
# ---------------------------------------------------------------------------


class AIProvider(abc.ABC):
    """Protocol every LLM provider implements.

    The :class:`AIClient` consumes a list of providers; when a
    provider raises :class:`ProviderError` with ``retryable=False``
    (or after a circuit breaker opens), the client falls through to
    the next provider in the list.
    """

    name: str

    @abc.abstractmethod
    def chat(
        self,
        messages: Iterable[ChatMessage],
        *,
        model: str,
        max_tokens: int = 1024,
        temperature: float = 0.0,
        seed: int | None = None,
        response_format: Mapping[str, Any] | None = None,
    ) -> ChatResponse: ...


# ---------------------------------------------------------------------------
# OpenAI-compatible implementation
# ---------------------------------------------------------------------------


class OpenAICompatibleProvider(AIProvider):
    """An :class:`AIProvider` that speaks the OpenAI chat-completion API.

    Tested against: NVIDIA NIM, OpenRouter, Groq, DeepSeek direct,
    OpenAI, and any reverse proxy that follows the same wire format.

    Configuration:
        base_url: e.g. "https://integrate.api.nvidia.com/v1"
        api_key:  env var name that holds the key (e.g. "NIM_API_KEY")
        rpm:      requests per minute budget (used for soft rate limit)
        timeout:  per-request timeout in seconds
    """

    name = "openai-compatible"

    def __init__(
        self,
        *,
        base_url: str,
        api_key_env: str,
        rpm: int = 35,
        timeout: float = 120.0,
        name: str = "openai-compatible",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key_env = api_key_env
        self.rpm = rpm
        self.timeout = timeout
        self.name = name
        self._last_request_ts: float = 0.0
        # The OpenAI client library is optional; if it's not installed
        # we fall back to raw urllib.
        self._client = None
        try:
            import openai  # type: ignore
            self._client = openai.OpenAI(
                base_url=self.base_url,
                api_key="placeholder",  # we set it on each call from env
                timeout=self.timeout,
            )
        except Exception:  # noqa: BLE001
            self._client = None

    def _get_api_key(self) -> str:
        import os
        key = os.environ.get(self.api_key_env, "")
        if not key:
            raise ProviderError(
                f"missing API key in env var {self.api_key_env}",
                provider=self.name,
                status_code=0,
                retryable=False,
            )
        return key

    def _throttle(self) -> None:
        """Soft rate limit: at most ``rpm`` requests per minute."""
        if self.rpm <= 0:
            return
        min_interval = 60.0 / self.rpm
        elapsed = time.monotonic() - self._last_request_ts
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_request_ts = time.monotonic()

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
        self._throttle()
        msg_list = [m.to_dict() for m in messages]
        # Re-build the OpenAI client with the freshest key each call.
        api_key = self._get_api_key()
        if self._client is not None:
            return self._chat_openai(msg_list, model, max_tokens,
                                     temperature, seed, response_format, api_key)
        return self._chat_urllib(msg_list, model, max_tokens,
                                 temperature, seed, response_format, api_key)

    def _chat_openai(self, messages, model, max_tokens, temperature,
                     seed, response_format, api_key) -> ChatResponse:
        start = time.monotonic()
        try:
            import openai  # type: ignore
            self._client.api_key = api_key
            kwargs: dict[str, Any] = dict(
                model=model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            if seed is not None:
                kwargs["seed"] = seed
            if response_format is not None:
                kwargs["response_format"] = dict(response_format)
            completion = self._client.chat.completions.create(**kwargs)
        except Exception as e:  # noqa: BLE001
            self._raise_for_openai_error(e)
            raise  # unreachable, but mypy-friendly
        elapsed_ms = int((time.monotonic() - start) * 1000)
        choice = completion.choices[0]
        usage = completion.usage
        return ChatResponse(
            content=choice.message.content or "",
            model=completion.model,
            prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
            total_tokens=getattr(usage, "total_tokens", 0) or 0,
            finish_reason=getattr(choice, "finish_reason", "") or "",
            raw=completion.model_dump() if hasattr(completion, "model_dump") else {},
            provider=self.name,
            latency_ms=elapsed_ms,
        )

    def _chat_urllib(self, messages, model, max_tokens, temperature,
                     seed, response_format, api_key) -> ChatResponse:
        import urllib.request
        import urllib.error
        start = time.monotonic()
        url = f"{self.base_url}/chat/completions"
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if seed is not None:
            body["seed"] = seed
        if response_format is not None:
            body["response_format"] = dict(response_format)
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            self._raise_for_http_error(e)
        except urllib.error.URLError as e:
            raise ProviderError(
                f"network error: {e}", provider=self.name,
                status_code=0, retryable=True,
            ) from e
        elapsed_ms = int((time.monotonic() - start) * 1000)
        choice = (payload.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        usage = payload.get("usage") or {}
        return ChatResponse(
            content=message.get("content") or "",
            model=payload.get("model", model),
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
            total_tokens=usage.get("total_tokens", 0),
            finish_reason=choice.get("finish_reason", "") or "",
            raw=payload,
            provider=self.name,
            latency_ms=elapsed_ms,
        )

    # ---- error mapping ---------------------------------------------------

    def _raise_for_openai_error(self, exc: Exception) -> None:
        import openai  # type: ignore
        status = 0
        retryable = True
        if isinstance(exc, openai.RateLimitError):
            status = 429
        elif isinstance(exc, openai.AuthenticationError):
            status = 401
            retryable = False
        elif isinstance(exc, openai.PermissionDeniedError):
            status = 403
            retryable = False
        elif isinstance(exc, openai.NotFoundError):
            status = 404
            retryable = False
        elif isinstance(exc, openai.BadRequestError):
            status = 400
            retryable = False
        elif isinstance(exc, openai.APITimeoutError):
            status = 408
        elif isinstance(exc, openai.APIConnectionError):
            status = 0
        elif isinstance(exc, openai.InternalServerError):
            status = 500
        raise ProviderError(
            f"{type(exc).__name__}: {exc}",
            provider=self.name,
            status_code=status,
            retryable=retryable,
        ) from exc

    def _raise_for_http_error(self, exc: Exception) -> None:
        status = getattr(exc, "code", 0) or 0
        retryable = status in (408, 409, 429, 500, 502, 503, 504)
        raise ProviderError(
            f"HTTP {status}: {exc.reason if hasattr(exc, 'reason') else exc}",
            provider=self.name,
            status_code=status,
            retryable=retryable,
        ) from exc

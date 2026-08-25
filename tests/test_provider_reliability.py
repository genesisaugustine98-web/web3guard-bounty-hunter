"""Tests for NIM provider reliability.

The live bot was timing out at the 120s per-request cap, burning 3
retries x 120s = ~6 minutes per chunk before falling through. These
tests cover the two reliability upgrades:

1. Streaming responses (tokens arrive incrementally, so a slow-but-
   progressing generation is not killed by the wall-clock timeout).
2. Per-provider retry cap exposed as config, so a flaky provider can
   be configured to fall through faster instead of burning N attempts.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest  # noqa: E402

from web3guard.ai.provider import OpenAICompatibleProvider  # noqa: E402
from web3guard.scanner import load_config  # noqa: E402


class _Delta:
    def __init__(self, content: str = ""):
        self.content = content


class _Choice:
    def __init__(self, content: str = ""):
        self.delta = _Delta(content)


class _Chunk:
    """A single streamed ChatCompletionChunk."""

    def __init__(self, content: str = "", *, model: str = "m", finish: str = ""):
        self.choices = [_Choice(content)]
        self.model = model
        self.finish_reason = finish


class _Usage:
    prompt_tokens = 5
    completion_tokens = 3
    total_tokens = 8


class _FullCompletion:
    """Non-streamed ChatCompletion (fallback path)."""

    model = "m"
    usage = _Usage()

    class _choice:
        finish_reason = "stop"

        class _message:
            content = "hello"

        message = _message()

    choices = [_choice]


class FakeStream:
    """Iterable of stream chunks, mimicking the OpenAI Stream object."""

    def __init__(self, chunks):
        self._chunks = list(chunks)
        self._i = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self._i >= len(self._chunks):
            raise StopIteration
        c = self._chunks[self._i]
        self._i += 1
        return c


@pytest.fixture
def provider(monkeypatch) -> OpenAICompatibleProvider:
    monkeypatch.setenv("NIM_API_KEY", "test-key")
    return OpenAICompatibleProvider(
        base_url="https://integrate.api.nvidia.com/v1",
        api_key_env="NIM_API_KEY",
        rpm=1000,
        timeout=120.0,
        name="nim-test",
    )


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------


def test_streaming_accumulates_tokens(provider, monkeypatch):
    """chat() with stream=True must concatenate deltas into content."""
    stream = FakeStream([
        _Chunk("The "),
        _Chunk("vuln"),
        _Chunk(" is reentrancy", finish="stop"),
    ])

    def fake_create(**kwargs):
        assert kwargs.get("stream") is True
        return stream

    client = _FakeClient(fake_create)
    monkeypatch.setattr(provider, "_client", client)

    resp = provider._chat_openai(
        [{"role": "user", "content": "hi"}], "m", 10, 0.0, None, None, "key")
    assert resp.content == "The vuln is reentrancy"
    assert resp.model == "m"


def test_streaming_tokens_counted(provider, monkeypatch):
    stream = FakeStream([_Chunk("abc", finish="stop")])
    client = _FakeClient(lambda **k: stream)
    monkeypatch.setattr(provider, "_client", client)
    resp = provider._chat_openai(
        [{"role": "user", "content": "hi"}], "m", 10, 0.0, None, None, "key")
    assert resp.content == "abc"
    assert resp.latency_ms >= 0


def test_non_streaming_path_kept(provider, monkeypatch):
    """use_streaming=False must use the completion path with usage."""
    provider.use_streaming = False

    def fake_create(**kwargs):
        assert kwargs.get("stream") is not True
        return _FullCompletion()

    client = _FakeClient(fake_create)
    monkeypatch.setattr(provider, "_client", client)
    resp = provider._chat_openai(
        [{"role": "user", "content": "hi"}], "m", 10, 0.0, None, None, "key")
    assert resp.content == "hello"
    assert resp.total_tokens == 8


def test_use_streaming_wired_from_scanner_config(tmp_path):
    import yaml
    from web3guard.scanner import Scanner

    cfg = load_config(None)
    cfg["ai_providers"] = [
        {
            "type": "nim",
            "name": "nim-stream",
            "base_url": "https://integrate.api.nvidia.com/v1",
            "api_key_env": "NIM_API_KEY",
            "rpm": 35,
            "use_streaming": False,
        }
    ]
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    scanner = Scanner.from_config(cfg_path, workdir=tmp_path)
    providers = scanner._build_ai_client()._providers
    p = next(iter(providers))
    assert isinstance(p, OpenAICompatibleProvider)
    assert p.use_streaming is False


# ---------------------------------------------------------------------------
# Per-provider retry config
# ---------------------------------------------------------------------------


def test_max_retries_wired_from_scanner_config(tmp_path):
    import yaml
    from web3guard.ai import AIClient
    from web3guard.scanner import Scanner

    cfg = load_config(None)
    cfg["ai_providers"] = [
        {
            "type": "nim",
            "name": "nim-retry",
            "base_url": "https://integrate.api.nvidia.com/v1",
            "api_key_env": "NIM_API_KEY",
            "rpm": 35,
            "timeout": 180.0,
            "max_retries": 1,
        }
    ]
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    scanner = Scanner.from_config(cfg_path, workdir=tmp_path)
    client = scanner._build_ai_client()
    assert isinstance(client, AIClient)
    assert client._max_retries == 1


def test_default_max_retries_is_two():
    from web3guard.ai.client import AIClient
    from web3guard.ai import OpenAICompatibleProvider
    p = OpenAICompatibleProvider(
        base_url="https://x/v1", api_key_env="NIM_API_KEY")
    client = AIClient(providers=[p])
    assert client._max_retries == 2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeClient:
    """Stand-in for the openai.OpenAI object."""

    def __init__(self, create_fn):
        self._create = create_fn
        self.api_key = "key"
        self.chat = _FakeChat(self._create)


class _FakeChat:
    def __init__(self, create_fn):
        self.completions = _FakeCompletions(create_fn)


class _FakeCompletions:
    def __init__(self, create_fn):
        self._create = create_fn

    def create(self, **kwargs):
        return self._create(**kwargs)

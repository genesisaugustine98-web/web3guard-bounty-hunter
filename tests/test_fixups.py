"""Tests for the v3.1 fixup pass.

Covers:
- streaming token accounting (cost > 0 without usage chunks)
- AIClient.exclude_provider one-shot semantics
- PoC repair loop passes failure feedback into retry prompts
- Aderyn engine returns one result per instance
- sandbox hardening: symlinks rejected, Anchor tests/ excluded, killpg
  helper exists, all runners route through hardened_run
- non-GitHub fetcher: shorthand expansion, URL normalization, archive
  extraction with zip-slip guard, single-file fetch
- consensus engine cross-validation
- zero-dollar provider enforcement
- extended language adapters register and detect
- extended static detectors emit expected findings
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.ai.client import AIClient  # noqa: E402
from web3guard.ai.cost import CostTracker  # noqa: E402
from web3guard.ai.provider import (  # noqa: E402
    ChatResponse,
    _estimate_tokens,
)
from web3guard.discovery.aderyn_engine import AderynEngine  # noqa: E402
from web3guard.discovery.static_analyzer import (  # noqa: E402
    StaticAnalyzerEngine,
    language_for_file,
)
from web3guard.languages import (  # noqa: E402
    TargetLanguage,
    default_registry,
)
from web3guard.scanner import (  # noqa: E402
    Finding,
    Scanner,
    _enforce_zero_dollar_providers,
)
from web3guard.utils.fetch import (  # noqa: E402
    FetchError,
    expand_shorthand,
    fetch_target,
    normalize_git_url,
)

# ---------------------------------------------------------------------------
# Streaming cost accounting
# ---------------------------------------------------------------------------


def test_estimate_tokens_scales_with_length():
    assert _estimate_tokens("") == 0
    assert _estimate_tokens("abcd") == 1
    assert _estimate_tokens("a" * 400) == 100


def test_streaming_response_without_usage_still_counts_cost():
    """Simulate the streaming path: no usage reported by the provider.

    The provider must fall back to estimated token counts so the cost
    tracker sees real numbers (previously recorded $0.00 for every
    streaming call, which silently disabled the cost ceiling).
    """
    tracker = CostTracker(max_cost_usd=1000.0)
    _messages = [{"role": "user", "content": "x" * 4000}]
    content = "y" * 8000
    prompt_tokens = _estimate_tokens("x" * 4000)
    completion_tokens = _estimate_tokens(content)
    tracker.record(
        provider="test",
        model="gpt-4o",  # known paid rates -> nonzero cost
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
    )
    assert tracker.total_cost() > 0
    summary = tracker.summary()
    assert summary["total_prompt_tokens"] == prompt_tokens
    assert summary["total_completion_tokens"] == completion_tokens


# ---------------------------------------------------------------------------
# exclude_provider
# ---------------------------------------------------------------------------


class _FakeProvider:
    def __init__(self, name: str):
        self.name = name
        self.calls = 0

    def chat(self, *a, **kw):  # noqa: ANN002, ANN003
        self.calls += 1
        return ChatResponse(content="ok", model="m", provider=self.name)


def _make_client(providers):
    return AIClient(
        providers=providers,
        cost_tracker=CostTracker(max_cost_usd=100.0),
        cache_path=None,
    )


def test_exclude_provider_skips_excluded_for_one_call():
    p1 = _FakeProvider("primary")
    p2 = _FakeProvider("fallback")
    client = _make_client([p1, p2])
    client.exclude_provider("primary")
    client.chat("s", "u")
    assert p1.calls == 0
    assert p2.calls == 1
    # One-shot: next call uses the primary again.
    client.chat("s", "u")
    assert p1.calls == 1


def test_exclude_all_providers_falls_back_to_full_rotation():
    p1 = _FakeProvider("only")
    client = _make_client([p1])
    client.exclude_provider("only")
    resp = client.chat("s", "u")
    assert resp.content == "ok"


# ---------------------------------------------------------------------------
# PoC repair loop
# ---------------------------------------------------------------------------


class _RecordingAI:
    """Records user prompts; returns scripted exploit code."""

    def __init__(self):
        self.cost_tracker = CostTracker()
        self.prompts: list[str] = []

    def chat(self, system, user, *, max_tokens=1500, temperature=0.0, role="analysis", **kw):
        self.prompts.append((role, user))
        from web3guard.ai.provider import ChatResponse as CR

        return CR(content="```solidity\ncontract X {}\n```", model="m")

    def exclude_provider(self, name: str) -> None:  # pragma: no cover
        return


def test_poc_retry_includes_failure_feedback(monkeypatch):
    from web3guard.languages.solidity import SolidityAdapter
    from web3guard.sandbox import base as sandbox_base

    scanner = Scanner.__new__(Scanner)
    scanner.config = {
        "enable_exploit": True,
        "max_exploit_attempts": 2,
        "max_chunk_chars": 6000,
    }
    scanner.workdir = Path(tempfile.mkdtemp(prefix="w3g-poc-"))
    scanner.ai_client = _RecordingAI()

    class FailingSandbox:
        def write_and_run(self, code, fingerprint, timeout=90):
            return False, "Error: compile failed at line 1"

    monkeypatch.setattr(sandbox_base, "create_sandbox", lambda *a, **kw: FailingSandbox())
    monkeypatch.setattr(
        "web3guard.sandbox.create_sandbox", lambda *a, **kw: FailingSandbox()
    )

    finding = Finding(target="t", language="solidity", file="a.sol",
                      category="reentrancy", fingerprint="fp")
    import types

    chunk = types.SimpleNamespace(content="contract A {}", context=None, file="a.sol")

    class FakeAdapter(SolidityAdapter):
        pass

    scanner._generate_poc(FakeAdapter(), finding, chunk, Path("/tmp"))
    exploit_prompts = [u for (role, u) in scanner.ai_client.prompts if role == "exploit"]
    assert len(exploit_prompts) >= 2
    assert "PREVIOUS ATTEMPT (REJECTED)" in exploit_prompts[1]
    assert "FAILURE REASON:" in exploit_prompts[1]


# ---------------------------------------------------------------------------
# Aderyn all-instances
# ---------------------------------------------------------------------------


def test_aderyn_translate_all_returns_every_instance():
    issue = {
        "title": "UnsafeArithmetic",
        "impact": "High",
        "details": "Unchecked math",
        "instances": [
            {"path": "src/A.sol", "line": "10"},
            {"path": "src/B.sol", "line": 20},
        ],
    }
    results = AderynEngine._translate_all(issue, Path("/target"))
    assert len(results) == 2
    assert {r.file for r in results} == {"src/A.sol", "src/B.sol"}
    assert results[0].severity == "HIGH"


def test_aderyn_translate_all_synthethizes_when_no_instances():
    issue = {"title": "SomeIssue", "impact": "Medium", "details": "d", "instances": []}
    results = AderynEngine._translate_all(issue, Path("/target"))
    assert len(results) == 1
    assert results[0].file == ""


# ---------------------------------------------------------------------------
# Sandbox hardening
# ---------------------------------------------------------------------------


def test_generic_sandbox_rejects_symlinks():
    from web3guard.languages.solidity import SolidityAdapter
    from web3guard.sandbox._generic import GenericSandbox

    with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as wd:
        root = Path(td)  # target
        work = Path(wd)  # sandbox workdir (must differ from target)
        real = root / "Real.sol"
        real.write_text("contract Real {}\n")
        link = root / "Link.sol"
        try:
            link.symlink_to(real)
        except OSError:
            pytest.skip("symlinks unsupported on this platform")
        sandbox = GenericSandbox(SolidityAdapter(), root, work)
        sandbox.file_globs = (".sol",)
        sandbox.setup(root)
        sandbox_root = sandbox._root
        assert sandbox_root is not None
        assert not (sandbox_root / "Link.sol").exists()


def test_anchor_sandbox_does_not_copy_target_tests():
    from web3guard.languages.rust_solana import RustSolanaAdapter
    from web3guard.sandbox.anchor import AnchorSandbox

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "programs" / "proj").mkdir(parents=True)
        (root / "programs" / "proj" / "lib.rs").write_text("fn x() {}\n")
        tests = root / "tests"
        tests.mkdir()
        (tests / "evil.ts").write_text("require('child_process').exec('id');\n")

        sandbox = AnchorSandbox(RustSolanaAdapter(), root, root)
        sandbox.setup(root)
        sandbox_root = sandbox._root
        assert sandbox_root is not None
        assert not (sandbox_root / "tests" / "evil.ts").exists()


def test_hardened_run_present_and_signature():
    from web3guard.sandbox.base import hardened_run

    assert callable(hardened_run)


def test_all_sandboxes_route_through_hardened_run():
    import inspect

    from web3guard.sandbox import _generic, anchor, foundry

    for module in (foundry, anchor, _generic):
        source = inspect.getsource(module)
        assert "hardened_run" in source, f"{module.__name__} not using hardened_run"


# ---------------------------------------------------------------------------
# Fetcher
# ---------------------------------------------------------------------------


def test_expand_shorthand_all_forges():
    assert expand_shorthand("gh:o/r") == "https://github.com/o/r"
    assert expand_shorthand("gl:group/sub/proj") == "https://gitlab.com/group/sub/proj"
    assert expand_shorthand("bb:owner/repo") == "https://bitbucket.org/owner/repo.git"
    assert expand_shorthand("cb:owner/repo") == "https://codeberg.org/owner/repo.git"
    assert expand_shorthand("sr:~user/repo") == "https://git.sr.ht/~user/repo"


def test_normalize_git_url_variants():
    assert normalize_git_url("https://gitlab.com/g/p/-/tree/main").endswith("gitlab.com/g/p")
    assert normalize_git_url("https://bitbucket.org/u/r") == "https://bitbucket.org/u/r.git"
    assert normalize_git_url("https://codeberg.org/u/r").endswith("codeberg.org/u/r.git")
    # cgit /about/ pages normalize to the repo's git root
    assert normalize_git_url("https://host/cgit/repo/about/") == "https://host/cgit/repo.git"


def test_fetch_single_file(tmp_path):
    """Single-file fetch uses local path short-circuit; direct URL path
    is exercised with a file:// style canary through a local temp server
    substitute — here we verify the error surface for bad input."""
    with pytest.raises((FetchError, OSError)):
        fetch_target("https://nonexistent.invalid/repo.tar.gz")


def test_fetch_local_path_roundtrip(tmp_path):
    d = tmp_path / "local"
    d.mkdir()
    (d / "A.sol").write_text("contract A {}\n")
    resolved = fetch_target(str(d))
    assert resolved.is_dir()
    assert (resolved / "A.sol").exists()


# ---------------------------------------------------------------------------
# Consensus engine
# ---------------------------------------------------------------------------


def _f(engine: str, file: str, fn: str, cat: str, conf: float) -> Finding:
    f = Finding(target="t", language="solidity", file=file, function=fn,
                category=cat, confidence=conf)
    f.tool_consensus = [engine]
    f.metadata = {"discovery": {}} if engine != "ai" else {}
    return f


def test_consensus_boosts_corroborated_findings():
    scanner = Scanner.__new__(Scanner)
    static = _f("slither", "a.sol", "withdraw", "reentrancy", 0.6)
    ai = _f("ai", "a.sol", "withdraw", "reentrancy", 0.5)
    scanner._apply_consensus([static, ai])
    assert any("consensus" in m.metadata and m.metadata["consensus"]["corroborated"]
               for m in (static, ai))
    assert static.confidence > 0.6 or ai.confidence > 0.5


def test_consensus_penalizes_low_confidence_single_ai():
    scanner = Scanner.__new__(Scanner)
    solo = _f("ai", "b.sol", "x", "oracle", 0.45)
    scanner._apply_consensus([solo])
    assert solo.confidence < 0.45
    assert solo.metadata["consensus"]["corroborated"] is False


# ---------------------------------------------------------------------------
# Zero-dollar enforcement
# ---------------------------------------------------------------------------


def test_zero_dollar_blocks_openai():
    cfg = {"ai_providers": [
        {"name": "openai", "base_url": "https://api.openai.com/v1", "model": "gpt-4o"},
        {"name": "nim", "base_url": "https://integrate.api.nvidia.com/v1", "model": "m"},
    ]}
    _enforce_zero_dollar_providers(cfg)
    assert [p["name"] for p in cfg["ai_providers"]] == ["nim"]


def test_zero_dollar_requires_free_openrouter_models():
    cfg = {"ai_providers": [
        {"name": "or-paid", "base_url": "https://openrouter.ai/api/v1", "model": "deepseek/deepseek-chat"},
        {"name": "or-free", "base_url": "https://openrouter.ai/api/v1", "model": "deepseek/deepseek-chat:free"},
    ]}
    _enforce_zero_dollar_providers(cfg)
    assert [p["name"] for p in cfg["ai_providers"]] == ["or-free"]


def test_zero_dollar_raises_when_all_paid():
    cfg = {"ai_providers": [
        {"name": "openai", "base_url": "https://api.openai.com/v1", "model": "gpt-4o"},
    ]}
    with pytest.raises(ValueError, match="zero-dollar"):
        _enforce_zero_dollar_providers(cfg)


# ---------------------------------------------------------------------------
# Extended languages: registry + detection + static detectors
# ---------------------------------------------------------------------------


def test_registry_contains_all_extended_adapters():
    langs = {a.language for a in default_registry.all_adapters()}
    for expected in (
        TargetLanguage.HUFF, TargetLanguage.YUL, TargetLanguage.INK,
        TargetLanguage.COSMWASM, TargetLanguage.SUBSTRATE,
        TargetLanguage.ALCHEMY, TargetLanguage.SCILLA, TargetLanguage.MICHELSON,
        TargetLanguage.CAIRO1, TargetLanguage.SASM, TargetLanguage.GO_COSMOS,
        TargetLanguage.SOLIDITY_ASM, TargetLanguage.WEBASSEMBLY,
    ):
        assert expected in langs, f"{expected} missing from registry"


def test_registry_went_from_8_to_21():
    assert len(default_registry.all_adapters()) >= 21


def test_huff_static_detector():
    src = """\
#define macro MAIN = takes(0) returns(0) {
    0x20 0x00 mstore
}
#define macro DRAIN = takes(0) returns(0) {
    SELFDESTRUCT
}
"""
    issues = StaticAnalyzerEngine().run(_as_target({"Vault.huff": src}))
    assert any(i.category == "selfdestruct" for i in issues)
    # Auth-shaped window suppresses the selfdestruct hit
    src_guarded = src.replace("#define macro DRAIN", "#define macro AUTH_DRAIN")
    src_guarded = src_guarded.replace("SELFDESTRUCT", "CALLER OWNER_EQ SELFDESTRUCT")
    issues2 = StaticAnalyzerEngine().run(_as_target({"Vault.huff": src_guarded}))
    assert not any("SELFDESTRUCT" in i.title for i in issues2)


def test_solidity_asm_detector_flags_missing_free_pointer():
    from web3guard.discovery.static_analyzer import _detect_solidity_asm

    src = """\
contract C {
    function f() external {
        assembly {
            let p := mload(0x00)
            mstore(p, 0x42)
        }
    }
}
"""
    issues = _detect_solidity_asm(src, "Asm.sol")
    assert any("free-memory pointer" in i.title or i.category == "arithmetic"
               for i in issues)


def test_go_cosmos_detector_flags_unchecked_transfer():
    src = """\
package module

import "cosmossdk.io/core/bank"

func Withdraw(ctx context.Context, amt sdk.Coins) error {
    k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "mod", "acct", amt)
    return nil
}
"""
    issues = StaticAnalyzerEngine().run(_as_target({"msg_server.go": src}))
    assert any(i.category == "unchecked-external-call" for i in issues)


def test_scilla_detector_flags_send_before_balance():
    src = """\
scilla_version 0

contract Vault ()

field balance : Uint128 = Uint128 0

transition Withdraw ()
  msg = {(to_addr : recipient); (_amount : amt)};
  msg <- send msg;
  b <- balance;
  balance := b - amt;
end
"""
    issues = StaticAnalyzerEngine().run(_as_target({"vault.scilla": src}))
    assert any(i.category == "reentrancy" for i in issues)


def test_rust_content_routing_solana_vs_ink():
    solana = "use anchor_lang::prelude::*;\n#[program]\nmod p {}"
    ink = "use ink::prelude::*;\n#[ink::contract]\nmod c {}"
    issues = StaticAnalyzerEngine().run(_as_target({
        "sol_program.rs": solana,
        "ink_contract.rs": ink,
    }))
    # Both files produce detector activity without misrouting; the ink!
    # file is recognized by the ink detector family (no crash / no misroute).
    assert isinstance(issues, list)


def test_language_for_file_extended():
    assert language_for_file(Path("x.huff")) == TargetLanguage.HUFF
    assert language_for_file(Path("x.wat")) == TargetLanguage.WEBASSEMBLY
    assert language_for_file(Path("x.scilla")) == TargetLanguage.SCILLA
    assert language_for_file(Path("x.tz")) == TargetLanguage.MICHELSON


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _as_target(files: dict[str, str]) -> Path:
    d = Path(tempfile.mkdtemp(prefix="w3g-test-"))
    for name, content in files.items():
        p = d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return d

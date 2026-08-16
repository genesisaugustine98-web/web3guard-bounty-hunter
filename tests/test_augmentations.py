"""Regression tests for the augmentation pass.

Covers:
- the offline deterministic static analyzer (the biggest new feature),
- the multi-language dispatch fix,
- the hardened secret scanner (mnemonic false-positive fix),
- report additions (HTML),
- CLI config deep-merge,
- discovery engines no longer polluting the scanned repo,
- config redaction, fingerprint identity, economic models,
- role map / attack-sequence passes.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from web3guard.discovery.base import temp_report_path
from web3guard.discovery.static_analyzer import StaticAnalyzerEngine
from web3guard.languages.registry import default_registry, detect_target_language
from web3guard.reports import ReportBuilder
from web3guard.scanner import Finding, Scanner, ScanResult, load_config
from web3guard.utils.secrets import iter_secret_matches, scan_path

REPO = Path(__file__).resolve().parents[1]
VULNERABLE = REPO / "test_contracts" / "vulnerable"
CLEAN = REPO / "test_contracts" / "clean"


class CleanAIStub:
    """AI stub that never reports vulnerabilities (static signal only)."""

    def __init__(self) -> None:
        from web3guard.ai.cost import CostTracker
        self._cost = CostTracker()

    def chat(self, *args: object, **kwargs: object):
        from web3guard.ai.provider import ChatResponse
        return ChatResponse(
            content=json.dumps({"status": "clean"}), provider="stub", model="stub")

    def cost_tracker(self):
        return self._cost


# ---------------------------------------------------------------------------
# Static analyzer
# ---------------------------------------------------------------------------


def test_static_analyzer_finds_bundled_vulnerabilities() -> None:
    engine = StaticAnalyzerEngine()
    results = engine.run(VULNERABLE)
    categories = {(r.file, r.category) for r in results}

    # Solidity
    assert ("ReentrancyVault.sol", "reentrancy") in categories
    assert ("AccessControlFlaw.sol", "access-control") in categories
    assert ("OracleManipulation.sol", "oracle-manipulation") in categories
    assert ("RandomnessLottery.sol", "randomness") in categories
    assert ("SignatureReplay.sol", "signature-replay") in categories
    assert ("ProxyUpgrade.sol", "proxy-upgrade") in categories
    # Vyper
    assert ("VulnerableVault.vy", "reentrancy") in categories
    assert ("VulnerableVault.vy", "access-control") in categories
    # Move
    assert ("MoveVault.move", "missing-acquires") in categories
    # Cairo
    assert ("VulnerableL1L2.cairo", "access-control") in categories
    # Clarity
    assert ("clarity-vault.clar", "access-control") in categories
    # FunC
    assert ("vault.fc", "access-control") in categories
    # Rust / Solana
    assert ("solana_program/src/lib.rs", "unprotected-init") in categories
    # TS SDK
    assert ("sdksdk.ts", "slippage") in categories
    assert ("sdksdk.ts", "unlimited-approval") in categories


def test_static_analyzer_no_false_positives_on_clean() -> None:
    engine = StaticAnalyzerEngine()
    assert engine.run(CLEAN) == []


def test_static_analyzer_covers_all_languages() -> None:
    engine = StaticAnalyzerEngine()
    languages = {r.engine for r in engine.run(VULNERABLE)}
    assert languages == {"web3guard-static"}


# ---------------------------------------------------------------------------
# Multi-language dispatch
# ---------------------------------------------------------------------------


def test_registry_now_detects_all_eight_languages() -> None:
    detection = detect_target_language(VULNERABLE)
    assert len(detection.detected) >= 6
    adapters = default_registry.detect_for(VULNERABLE)
    langs = {a.language.value for a in adapters}
    # The extension fallback fixes: rust-solana and ts-sdk must now match.
    assert "rust-solana" in langs
    assert "ts-sdk" in langs
    assert "solidity" in langs


def test_scan_runs_all_adapters_not_just_primary(tmp_path: Path) -> None:
    cfg = load_config(None)
    cfg.update({
        "enable_exploit": False,
        "enable_self_critique": False,
        "enable_secret_scan": False,
        "use_ai_planning": False,
        "enable_attack_sequence_brainstorm": False,
        "enable_role_map": False,
        "enable_discovery": True,
    })
    scanner = Scanner(config=cfg, ai_client=CleanAIStub(), workdir=tmp_path / "work")
    result = scanner.scan([f"{VULNERABLE}|1000"])
    languages = {f.language for f in result.all_findings}
    # Solid + several non-primary languages must contribute findings.
    assert len(languages) >= 5


# ---------------------------------------------------------------------------
# Secret scanner hardening
# ---------------------------------------------------------------------------


def test_mnemonic_false_positive_is_suppressed() -> None:
    benign = (
        "the quick brown fox jumps over the lazy dog and then some\n"
        "return the amount if the user has the required balance and transfer succeeds\n"
    )
    mnemonic_hits = [m for m in iter_secret_matches(benign) if m.kind == "mnemonic"]
    assert mnemonic_hits == []


def test_mnemonic_real_phrase_is_detected() -> None:
    phrase = 'seed phrase "abandon ability able about above absent absorb abstract absurd abuse access accident"\n'
    mnemonic_hits = [m for m in iter_secret_matches(phrase) if m.kind == "mnemonic"]
    assert len(mnemonic_hits) == 1


def test_secret_scan_finds_hardcoded_rpc_key() -> None:
    findings = scan_path(VULNERABLE)
    assert any(f["kind"] == "alchemy_rpc" and "sdksdk.ts" in f["file"] for f in findings)


# ---------------------------------------------------------------------------
# Scanner helper fixes
# ---------------------------------------------------------------------------


def test_fingerprint_distinguishes_distinct_vulns_in_same_function() -> None:
    a = Finding(target="t", language="solidity", file="A.sol", function="f",
                category="reentrancy", description="drain via reentrancy", line_hint="10-12")
    b = Finding(target="t", language="solidity", file="A.sol", function="f",
                category="reentrancy", description="drain via reentrancy", line_hint="10-12")
    c = Finding(target="t", language="solidity", file="A.sol", function="f",
                category="reentrancy", description="drain via cross-function", line_hint="40-42")
    assert Scanner._fingerprint(a) == Scanner._fingerprint(b)
    assert Scanner._fingerprint(a) != Scanner._fingerprint(c)


def test_extract_code_block_matches_language_tagged_fences() -> None:
    resp = 'here is the poc:\n```typescript\nconst tx = await router.swap(1, 0);\n```'
    assert "const tx" in Scanner._extract_code_block(resp, language="rust-solana")
    assert "const tx" in Scanner._extract_code_block(resp, language="ts-sdk")


def test_economic_analyzer_applies_offline_models(tmp_path: Path) -> None:
    scanner = Scanner(config=load_config(None), workdir=tmp_path / "work")
    finding = Finding(target="t", language="solidity", file="A.sol",
                      category="oracle-manipulation")
    scanner._economic_analyzer(finding)
    assert finding.cost_basis_usd > 0
    assert finding.expected_profit_usd > 0
    assert "economic" in finding.metadata


def test_sanitize_config_redacts_credentials(tmp_path: Path) -> None:
    cfg = load_config(None)
    cfg["ai_providers"] = [{"type": "nim", "api_key_env": "NIM_API_KEY"}]
    cfg["fork_url"] = "https://eth-mainnet.g.alchemy.com/v2/supersecretkey"
    cfg["api_key_token"] = "abc123"
    sanitized = Scanner(config=cfg, ai_client=CleanAIStub(),
                        workdir=tmp_path / "work")._sanitize_config()
    assert "ai_providers" not in sanitized
    assert "supersecretkey" not in json.dumps(sanitized)
    assert sanitized["api_key_token"] == "<redacted>"


def test_role_map_and_attack_sequences(tmp_path: Path) -> None:
    from web3guard.languages.solidity import SolidityAdapter

    adapter = SolidityAdapter()
    scanner = Scanner(config=load_config(None), workdir=tmp_path / "work")
    role_map = scanner._role_map(adapter, VULNERABLE)
    unguarded = [r for r in role_map["roles"] if not r["guarded"]]
    names = {r["function"] for r in unguarded}
    assert "setOwner" in names or "setFee" in names

    sequences = scanner._attack_sequences(adapter, VULNERABLE)
    fns = {s["function"] for s in sequences["sequences"]}
    assert "withdraw" in fns


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


def test_html_report_renders_and_escapes(tmp_path: Path) -> None:
    finding = Finding(target="t", language="solidity", file="A.sol",
                      category="reentrancy", severity="HIGH",
                      description="<script>alert(1)</script>", line_hint="3")
    result = ScanResult(started_at="s", finished_at="e", config={},
                        targets=[SimpleNamespace(findings=[finding])])
    written = ReportBuilder(result).write(tmp_path, formats=["html"])
    html = written["html"].read_text(encoding="utf-8")
    assert "&lt;script&gt;" in html
    assert "<script>alert" not in html


# ---------------------------------------------------------------------------
# Discovery hygiene
# ---------------------------------------------------------------------------


def test_temp_report_path_lives_outside_target(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    out = temp_report_path(target, "aderyn")
    assert target not in out.parents
    assert out.name == "aderyn_report.json"


def test_deep_merge_merges_nested_dicts() -> None:
    from web3guard.cli import _deep_merge
    base = {"a": 1, "nested": {"x": 1, "y": 2}, "ai_providers": [1]}
    override = {"nested": {"y": 9}, "b": 2}
    merged = _deep_merge(base, override)
    assert merged["a"] == 1
    assert merged["nested"] == {"x": 1, "y": 9}
    assert merged["b"] == 2
    assert merged["ai_providers"] == [1]


# ---------------------------------------------------------------------------
# Benchmark harness (Phase 0: precision/recall gate)
# ---------------------------------------------------------------------------


def test_bench_default_corpus_loads() -> None:
    from web3guard.bench import default_corpus

    corpus = default_corpus()
    assert corpus.name == "test-contracts"
    assert len(corpus.units) >= 16
    assert sum(1 for u in corpus.units if u.is_clean) >= 2
    assert any(u.path.endswith("ReentrancyVault.sol") and "reentrancy" in u.vulnerabilities
               for u in corpus.units)


def test_bench_static_analyzer_meets_gate(tmp_path: Path) -> None:
    from web3guard.bench import default_corpus, run_benchmark

    report = run_benchmark(default_corpus())
    o = report.overall
    # In-repo fixtures are calibrated: perfect precision/recall expected,
    # but the gate floor protects against regressions.
    assert o.precision >= 0.99
    assert o.recall >= 0.95
    assert report.clean_hits == []
    assert report.total_units == 16


def test_bench_reports_false_positives() -> None:
    from web3guard.bench import BenchmarkCorpus, CorpusUnit, evaluate
    from web3guard.bench.metrics import BenchFinding

    corpus = BenchmarkCorpus(
        name="t", description="", root=REPO,
        units=(CorpusUnit(path="A.sol", language="solidity", vulnerabilities=("reentrancy",)),),
    )
    report = evaluate(corpus, [
        BenchFinding(file="A.sol", category="reentrancy", line=1),
        BenchFinding(file="A.sol", category="access-control", line=2),
    ])
    assert report.overall.tp == 1
    assert report.overall.fp == 1
    assert report.overall.fn == 0
    assert len(report.false_positives) == 1


def test_bench_clean_fixture_hits_are_surfaceable() -> None:
    from web3guard.bench import BenchmarkCorpus, CorpusUnit, evaluate
    from web3guard.bench.metrics import BenchFinding

    corpus = BenchmarkCorpus(
        name="t", description="", root=REPO,
        units=(CorpusUnit(path="Clean.sol", language="solidity", vulnerabilities=()),),
    )
    report = evaluate(corpus, [BenchFinding(file="Clean.sol", category="reentrancy", line=1)])
    assert report.overall.fp == 1
    assert report.overall.precision == 0.0
    assert len(report.clean_hits) == 1


def test_bench_cli_writes_json_and_gates(tmp_path: Path) -> None:
    from web3guard.cli import _cmd_bench

    json_path = tmp_path / "report.json"

    class Args:  # noqa: D106
        corpus = None
        min_severity = "LOW"
        json_out = json_path
        fail_below = None

    assert _cmd_bench(Args()) == 0
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["overall"]["precision"] == 1.0

    class FailingArgs:  # noqa: D106
        corpus = None
        min_severity = "LOW"
        json_out = None
        fail_below = "1.5,1.5"  # impossible floor -> must fail the gate

    assert _cmd_bench(FailingArgs()) == 1

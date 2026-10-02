"""Tests for the Phase 6 multi-language invariant harnesses (Vyper + Cairo).

Everything here runs WITHOUT real AI keys and WITHOUT network:
- rendering / translation / template tests are pure-string;
- toolchain detection is tested both ways (absent -> honest None via
  monkeypatched paths; present -> found, guarded by skipif);
- the two live end-to-end campaigns are guarded by skipif so CI never
  fails where titanoboa / snforge are absent.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.invariants import (  # noqa: E402
    CAIRO_TEMPLATES,
    VYPER_TEMPLATES,
    FuzzBounds,
    Invariant,
    detect_language,
    discover_cairo_toolchain,
    discover_vyper_runner,
    parse_snforge_output,
    parse_vyper_output,
    render_project,
    run_invariant_pipeline,
    synthesize_invariants,
    template_invariants,
)
from web3guard.invariants.cairo_harness import (  # noqa: E402
    UntranslatableAssertion,
    extract_contract_mod,
    extract_functions,
    translate_assertion_to_cairo,
)
from web3guard.invariants.vyper_harness import (  # noqa: E402
    translate_assertion_to_python,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_VYPER_VAULT = """\
total_supply: public(uint256)
total_assets: public(uint256)

@external
def deposit(amount: uint256):
    self.total_supply += amount
    self.total_assets += amount

@external
def withdraw(amount: uint256):
    assert self.total_supply >= amount, "insufficient"
    self.total_supply -= amount
    # PLANTED BUG: total_assets is never reduced -> solvency breaks
"""

_CAIRO_VAULT = """\
use starknet::ContractAddress;

#[starknet::interface]
pub trait IVault<TContractState> {
    fn deposit(ref self: TContractState, amount: u256);
    fn withdraw(ref self: TContractState, amount: u256);
    fn total_supply(self: @TContractState) -> u256;
    fn total_assets(self: @TContractState) -> u256;
}

#[starknet::contract]
pub mod Vault {
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess, StoragePathEntry, Map,
    };
    use starknet::{ContractAddress, get_caller_address};

    #[storage]
    pub struct Storage {
        pub total_supply: u256,
        pub total_assets: u256,
        pub balances: Map<ContractAddress, u256>,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    pub impl VaultImpl of super::IVault<ContractState> {
        fn deposit(ref self: ContractState, amount: u256) {
            let who = get_caller_address();
            self.balances.entry(who).write(
                self.balances.entry(who).read() + amount);
            self.total_supply.write(self.total_supply.read() + amount);
            self.total_assets.write(self.total_assets.read() + amount);
        }
        fn withdraw(ref self: ContractState, amount: u256) {
            let who = get_caller_address();
            let bal = self.balances.entry(who).read();
            assert(bal >= amount, 'insufficient');
            self.balances.entry(who).write(bal - amount);
            // PLANTED BUG: total_assets is never reduced -> solvency breaks
            self.total_supply.write(self.total_supply.read() - amount);
        }
        fn total_supply(self: @ContractState) -> u256 {
            self.total_supply.read()
        }
        fn total_assets(self: @ContractState) -> u256 {
            self.total_assets.read()
        }
    }
}
"""

_SOLIDITY_VAULT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Vault {
    uint256 public totalSupply;
    uint256 public totalAssets;
}
"""


def _inv(
    id: str = "tmpl-solvency-1-1",
    assertion: str = "target.total_supply() == target.total_assets()",
) -> Invariant:
    return Invariant(
        id=id,
        statement="solvency",
        assertion=assertion,
        bug_class="accounting-desync",
        severity="HIGH",
    )


def _bounds(**kw) -> FuzzBounds:
    return FuzzBounds(runs=kw.get("runs", 32), depth=kw.get("depth", 6),
                      timeout_seconds=kw.get("timeout_seconds", 570))


# ---------------------------------------------------------------------------
# Renderer registry: registration = language support
# ---------------------------------------------------------------------------


def test_render_project_supports_all_three_languages() -> None:
    bounds = _bounds()
    vyper_files = render_project("vyper", _VYPER_VAULT, "vault", [_inv()], bounds)
    assert "contract/vault.vy" in vyper_files
    assert "run_invariants.py" in vyper_files

    cairo_files = render_project("cairo", _CAIRO_VAULT, "vault", [_inv()], bounds)
    assert "Scarb.toml" in cairo_files
    assert "Scarb.lock" in cairo_files
    assert "src/lib.cairo" in cairo_files
    assert "tests/invariants.cairo" in cairo_files

    sol_files = render_project("solidity", _SOLIDITY_VAULT, "Vault", [_inv(
        assertion="target.totalSupply() == target.totalAssets()")], bounds)
    assert sol_files  # non-empty


def test_render_project_unknown_language_raises() -> None:
    with pytest.raises(ValueError, match="no invariant harness renderer"):
        render_project("move", "module m {}", "m", [_inv()], _bounds())


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("suffix", "expected"), [
    (".sol", "solidity"),
    (".vy", "vyper"),
    (".cairo", "cairo"),
    (".SOL", "solidity"),
    (".move", ""),
    (".clar", ""),
    (".fc", ""),
    (".rs", ""),
    (".ts", ""),
    (".txt", ""),
])
def test_detect_language(suffix: str, expected: str) -> None:
    assert detect_language(Path(f"contract{suffix}")) == expected


# ---------------------------------------------------------------------------
# Template applicability per language
# ---------------------------------------------------------------------------


def test_vyper_templates_match_vyper_not_solidity() -> None:
    vyper_invs = template_invariants(_VYPER_VAULT, language="vyper")
    assert [i.id for i in vyper_invs] == ["tmpl-solvency-1-1"]
    assert vyper_invs[0].assertion == "target.total_supply() == target.total_assets()"
    # Vyper snake_case getters must NOT match the Solidity template regexes.
    assert template_invariants(_VYPER_VAULT, language="solidity") == []


def test_cairo_templates_match_cairo_not_solidity() -> None:
    cairo_invs = template_invariants(_CAIRO_VAULT, language="cairo")
    assert [i.id for i in cairo_invs] == ["tmpl-solvency-1-1"]
    assert cairo_invs[0].assertion == "target.total_supply() == target.total_assets()"
    assert template_invariants(_CAIRO_VAULT, language="solidity") == []


def test_solidity_templates_unchanged() -> None:
    sol_invs = template_invariants(_SOLIDITY_VAULT, language="solidity")
    assert [i.id for i in sol_invs] == ["tmpl-solvency-1-1"]
    assert sol_invs[0].assertion == "target.totalSupply() == target.totalAssets()"
    # And the new lists did not disturb the shared template ids.
    assert {t.id for t in VYPER_TEMPLATES} == {t.id for t in CAIRO_TEMPLATES}


def test_synthesize_invariants_language_param_keyless() -> None:
    # No AI keys here: templates only, but in the right dialect per language.
    res_vy = synthesize_invariants(
        _VYPER_VAULT, None, {"ai_enabled": False}, language="vyper")
    assert [i.id for i in res_vy.invariants] == ["tmpl-solvency-1-1"]
    res_cairo = synthesize_invariants(
        _CAIRO_VAULT, None, {"ai_enabled": False}, language="cairo")
    assert [i.id for i in res_cairo.invariants] == ["tmpl-solvency-1-1"]
    assert any("SKIPPED" in n for n in res_vy.notes)


# ---------------------------------------------------------------------------
# Vyper assertion translation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("src", "expected"), [
    ("target.total_supply() == target.total_assets()",
     "target.total_supply() == target.total_assets()"),
    ("target.a() > 0 and target.b() != address(0)",
     "target.a() > 0 and target.b() != '0x0000000000000000000000000000000000000000'"),
    ("target.owner() == address(0)",
     "target.owner() == '0x0000000000000000000000000000000000000000'"),
    ("target.x() >= 10 or not target.paused()",
     "target.x() >= 10 or not target.paused()"),
])
def test_translate_assertion_to_python(src: str, expected: str) -> None:
    assert translate_assertion_to_python(src) == expected


# ---------------------------------------------------------------------------
# Cairo assertion translation (strict grammar)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("src", "expected"), [
    ("target.total_supply() == target.total_assets()",
     "dispatcher.total_supply() == dispatcher.total_assets()"),
    ("target.owner() != address(0)",
     "dispatcher.owner() != contract_address_const::<0>()"),
    ("target.share_price() > 0", "dispatcher.share_price() > 0"),
    ("target.a() == 5 && target.b() != target.c()",
     "dispatcher.a() == 5 && dispatcher.b() != dispatcher.c()"),
    ("target.a() <= 100 || target.owner() != address(0)",
     "dispatcher.a() <= 100 || dispatcher.owner() != contract_address_const::<0>()"),
])
def test_translate_assertion_to_cairo_ok(src: str, expected: str) -> None:
    assert translate_assertion_to_cairo(src) == expected


@pytest.mark.parametrize("src", [
    "target.total_supply() + 1 == target.total_assets()",  # arithmetic
    "target.balance_of(x) == 0",                            # getter with args
    "foo() == 1",                                           # not target.
    "target.a() == 1; target.b() == 2",                     # two statements
    "target.a() == unknown_thing",                          # bare identifier
    "",                                                     # empty
])
def test_translate_assertion_to_cairo_rejects(src: str) -> None:
    with pytest.raises(UntranslatableAssertion):
        translate_assertion_to_cairo(src)


# ---------------------------------------------------------------------------
# Cairo source introspection
# ---------------------------------------------------------------------------


def test_extract_contract_mod() -> None:
    assert extract_contract_mod(_CAIRO_VAULT) == "Vault"
    with pytest.raises(ValueError):
        extract_contract_mod("fn main() {}")


def test_extract_functions_skips_constructor() -> None:
    fns = extract_functions(_CAIRO_VAULT)
    names = [f.name for f in fns]
    assert "constructor" not in names
    assert {"deposit", "withdraw", "total_supply", "total_assets"} <= set(names)
    by_name = {f.name: f for f in fns}
    assert by_name["deposit"].state_changing is True
    assert by_name["total_supply"].state_changing is False
    assert by_name["total_supply"].return_type == "u256"


def test_rendered_cairo_test_uses_seeded_fuzzer() -> None:
    files = render_project("cairo", _CAIRO_VAULT, "vault", [_inv()], _bounds(runs=32))
    test_src = files["tests/invariants.cairo"]
    assert "#[fuzzer(runs: 32, seed: 20261001)]" in test_src
    assert "call_contract_syscall" in test_src  # revert-absorbing calls
    assert "Scarb.lock" in files
    assert 'name = "vault"' in files["Scarb.lock"]


# ---------------------------------------------------------------------------
# Toolchain detection honesty
# ---------------------------------------------------------------------------


def test_discover_vyper_runner_absent_is_honest(monkeypatch) -> None:
    monkeypatch.delenv("WEB3GUARD_VYPER_PYTHON", raising=False)
    monkeypatch.setattr(
        "web3guard.invariants.fuzz_vyper.VYPER_VENV_PYTHON",
        Path("/nonexistent/venv/bin/python"),
    )
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert discover_vyper_runner({}) is None


def test_discover_cairo_toolchain_absent_is_honest(monkeypatch) -> None:
    monkeypatch.delenv("WEB3GUARD_SNFORE_BIN", raising=False)
    monkeypatch.setattr(
        "web3guard.invariants.fuzz_cairo.SNFORE_BIN", Path("/nonexistent/snforge"))
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert discover_cairo_toolchain({}) is None


_VYPER_AVAILABLE = discover_vyper_runner({}) is not None
_CAIRO_AVAILABLE = discover_cairo_toolchain({}) is not None


@pytest.mark.skipif(not _VYPER_AVAILABLE, reason="titanoboa not installed")
def test_discover_vyper_runner_present() -> None:
    assert discover_vyper_runner({}) is not None


@pytest.mark.skipif(not _CAIRO_AVAILABLE, reason="cairo toolchain not installed")
def test_discover_cairo_toolchain_present() -> None:
    tc = discover_cairo_toolchain({})
    assert tc is not None and "snforge" in tc and "scarb" in tc


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------


def test_parse_vyper_output_violation() -> None:
    inv = _inv()
    stdout = "\n".join([
        json.dumps({"type": "violation", "id": inv.id,
                    "sequence": ["0xabc deposit(100)", "0xabc withdraw(60)"],
                    "detail": "10 != 70"}),
        json.dumps({"type": "summary", "runs": 50, "calls": 400,
                    "reverts": 12, "violations": 1,
                    "compile_ok": True, "clean": False, "notes": []}),
    ])
    findings, campaign = parse_vyper_output(
        stdout, [inv], contract_path="vault.vy", contract_name="vault")
    assert len(findings) == 1
    f = findings[0]
    assert f.language == "vyper"
    assert f.category == "invariant-violation"
    assert f.status == "POTENTIAL"
    assert f.tool_consensus == ["titanoboa-invariant"]
    assert f.dynamically_confirmed is True
    assert "deposit(100)" in f.poc_code
    assert campaign.compile_ok and not campaign.clean


def test_parse_vyper_output_clean() -> None:
    stdout = json.dumps({"type": "summary", "runs": 50, "calls": 400,
                         "reverts": 0, "violations": 0,
                         "compile_ok": True, "clean": True, "notes": []})
    findings, campaign = parse_vyper_output(stdout, [_inv()])
    assert findings == []
    assert campaign.clean and campaign.compile_ok


def test_parse_snforge_output_violation() -> None:
    inv = _inv(id="tmpl-solvency-1-1")
    stdout = """\
Running 1 test(s) from tests/
[FAIL] vault_integrationtest::invariants::invariant_tmpl_solvency_1_1 (runs: 3, arguments: ["42"])

Failure data:
    0x746d706c2d736f6c76656e63792d312d31 ('tmpl-solvency-1-1')

Tests: 0 passed, 1 failed, 0 ignored, 0 filtered out
"""
    findings, campaign = parse_snforge_output(
        stdout, [inv], contract_path="vault.cairo", contract_name="vault")
    assert len(findings) == 1
    f = findings[0]
    assert f.language == "cairo"
    assert f.category == "invariant-violation"
    assert f.status == "POTENTIAL"
    assert f.tool_consensus == ["snforge-invariant"]
    assert f.dynamically_confirmed is True
    assert not campaign.clean and campaign.compile_ok


def test_parse_snforge_output_clean() -> None:
    stdout = "Running 1 test(s) from tests/\nTests: 1 passed, 0 failed\n"
    findings, campaign = parse_snforge_output(stdout, [_inv()])
    assert findings == []
    assert campaign.clean and campaign.compile_ok


def test_parse_snforge_output_compile_failure_is_honest() -> None:
    stdout = "error[E0002]: something broke\nerror: could not compile `vault`"
    findings, campaign = parse_snforge_output(stdout, [_inv()])
    assert findings == []
    assert campaign.compile_ok is False


def test_parse_snforge_output_zero_tests_is_not_clean() -> None:
    # A harness that ran but executed 0 tests is INCONCLUSIVE — never clean.
    stdout = "Running 0 test(s) from tests/\nTests: 0 passed, 0 failed, 0 ignored, 0 filtered out\n"
    findings, campaign = parse_snforge_output(stdout, [_inv()])
    assert findings == []
    assert campaign.clean is False
    # compile_ok stays False so the pipeline marks this "cause unknown"
    # instead of silently passing it.
    assert campaign.compile_ok is False


def test_parse_vyper_output_zero_runs_is_not_clean() -> None:
    # A driver summary claiming clean with zero runs is an un-executed
    # campaign — never a clean verdict.
    stdout = json.dumps({"type": "summary", "runs": 0, "calls": 0,
                         "reverts": 0, "violations": 0,
                         "compile_ok": True, "clean": True, "notes": []})
    findings, campaign = parse_vyper_output(stdout, [_inv()])
    assert findings == []
    assert campaign.clean is False
    # compile_ok stays False so the pipeline marks this "cause unknown"
    # instead of silently passing it.
    assert campaign.compile_ok is False


# ---------------------------------------------------------------------------
# LANGUAGE_GAPS.md completeness: every language must be accounted for
# ---------------------------------------------------------------------------


def test_language_gaps_covers_all_languages() -> None:
    gaps = (PROJECT_ROOT / "web3guard" / "invariants" / "LANGUAGE_GAPS.md").read_text()
    for lang in ("Solidity", "Vyper", "Cairo", "Move", "Clarity", "FunC", "Rust", "TypeScript"):
        assert lang in gaps, f"{lang} missing from LANGUAGE_GAPS.md"


# ---------------------------------------------------------------------------
# Live end-to-end campaigns (only where the toolchains are installed)
# ---------------------------------------------------------------------------


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


@pytest.mark.skipif(not _VYPER_AVAILABLE, reason="titanoboa not installed")
def test_e2e_vyper_buggy_vault_violation_is_caught(tmp_path: Path) -> None:
    target = _write(tmp_path, "vault.vy", _VYPER_VAULT)
    notes: list[str] = []
    findings = run_invariant_pipeline(
        target,
        {"ai_enabled": False,
         "invariants": {"runs": 200, "depth": 8, "timeout_seconds": 300}},
        notes=notes,
    )
    assert not any("fuzz campaign SKIPPED" in n for n in notes), notes
    assert len(findings) == 1
    f = findings[0]
    assert f.language == "vyper"
    assert f.status == "POTENTIAL"
    assert f.category == "invariant-violation"
    assert f.dynamically_confirmed is True
    assert "withdraw" in f.poc_code  # the planted bug is the counterexample


@pytest.mark.skipif(not _CAIRO_AVAILABLE, reason="cairo toolchain not installed")
def test_e2e_cairo_buggy_vault_violation_is_caught(tmp_path: Path) -> None:
    target = _write(tmp_path, "vault.cairo", _CAIRO_VAULT)
    notes: list[str] = []
    findings = run_invariant_pipeline(
        target,
        {"ai_enabled": False,
         "invariants": {"runs": 64, "depth": 10, "timeout_seconds": 570}},
        notes=notes,
    )
    assert not any("fuzz campaign SKIPPED" in n for n in notes), notes
    assert len(findings) == 1
    f = findings[0]
    assert f.language == "cairo"
    assert f.status == "POTENTIAL"
    assert f.category == "invariant-violation"
    assert f.tool_consensus == ["snforge-invariant"]
    assert f.dynamically_confirmed is True

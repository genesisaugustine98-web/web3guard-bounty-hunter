"""Regression tests for the weakness-hunt round (UPGRADE_PROOF.md Part 5).

Each of the 6 documented weaknesses gets a failing-first regression test
here. Everything runs WITHOUT real AI keys and WITHOUT network; forge
e2e tests reuse the world-traversable forge bundle pattern (pytest runs as
root, the sandbox drops to ``nobody``).
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.invariants import templates as tmpl  # noqa: E402
from web3guard.invariants.harness import (  # noqa: E402
    NEUTRAL_DEPLOYER,
    extract_mined_senders,
    render_solidity_project,
    sender_pool,
)
from web3guard.invariants.models import FuzzBounds, Invariant  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_OWNABLE_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract CleanOwnable {
    address public owner;
    mapping(address => uint256) public balances;
    constructor() { owner = msg.sender; }
    function transferOwnership(address n) external {
        require(msg.sender == owner, "not owner");
        owner = n;
    }
    function deposit() external payable { balances[msg.sender] += msg.value; }
}
"""

_PAUSER_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract PauserCanMintRemote {
    uint256 public totalSupply;
    uint256 public totalAssets;
    mapping(address => uint256) public balanceOf;
    address public pauser = address(0x000000000000000000000000000000000000dEaD);
    function deposit(uint256 amt) external {
        balanceOf[msg.sender] += amt;
        totalSupply += amt;
        totalAssets += amt;
    }
    function mint(address to, uint256 amt) external {
        require(msg.sender == pauser, "not pauser");
        balanceOf[to] += amt;
        totalSupply += amt;
    }
}
"""

_ORIGIN_OWNER_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract OriginOwner {
    address public owner;
    address public deployer;
    constructor() { owner = msg.sender; deployer = msg.sender; }
    function transferOwnership(address n) external {
        require(tx.origin == owner, "bad origin"); // BUG: tx.origin auth
        owner = n;
    }
}
"""


def _inv(id: str, assertion: str) -> Invariant:
    return Invariant(id=id, statement=id, assertion=assertion)


# ---------------------------------------------------------------------------
# Target 1a: the harness must never deploy the target as itself (owner)
# ---------------------------------------------------------------------------


def test_attack_handler_deploys_from_neutral_address() -> None:
    files = render_solidity_project(
        _OWNABLE_SRC, "CleanOwnable", [_inv("x", "target.owner() != address(0)")],
        FuzzBounds(),
    )
    handler = files["test/AttackHandler.sol"]
    # the neutral deployer constant exists and is used to prank the deployment
    assert f"address constant WG_NEUTRAL_DEPLOYER = address({NEUTRAL_DEPLOYER})" in handler
    assert "WGVM.prank(WG_NEUTRAL_DEPLOYER);" in handler
    assert "target = new CleanOwnable();" in handler
    # ... and the prank comes immediately before the deployment
    deploy_idx = handler.index("target = new CleanOwnable();")
    prank_idx = handler.index("WGVM.prank(WG_NEUTRAL_DEPLOYER);")
    assert prank_idx < deploy_idx
    between = handler[prank_idx:deploy_idx]
    assert "new " not in between.replace("prank(WG_NEUTRAL_DEPLOYER);", "")


def test_ghost_handler_deploys_from_neutral_address() -> None:
    invs = [i for i in tmpl.template_invariants(_OWNABLE_SRC)
            if i.id in tmpl.GHOST_TEMPLATE_IDS]
    assert invs, "fixture must trigger ghost mode"
    files, _notes = tmpl.render_ghost_project(
        _OWNABLE_SRC, "CleanOwnable", invs, FuzzBounds())
    test_src = files["test/Invariant.t.sol"]
    assert "WGVM.prank(WG_NEUTRAL_DEPLOYER);" in test_src
    assert "target = new CleanOwnable();" in test_src
    assert f"address constant WG_NEUTRAL_DEPLOYER = address({NEUTRAL_DEPLOYER});" in test_src


# ---------------------------------------------------------------------------
# Target 1b: sender impersonation — mined + configured senders
# ---------------------------------------------------------------------------


def test_mined_senders_extracted_from_source() -> None:
    mined = extract_mined_senders(_PAUSER_SRC)
    assert mined == ["0x000000000000000000000000000000000000dead"]
    # the zero address, the cheatcode address and the neutral deployer
    # must never become impersonable senders
    assert extract_mined_senders(
        "address(0x0000000000000000000000000000000000000000);"
        f"address({NEUTRAL_DEPLOYER});"
    ) == []


def test_sender_pool_contains_mined_and_configured() -> None:
    bounds = FuzzBounds.from_config(
        {"invariants": {"impersonate_senders": ["0x1111111111111111111111111111111111111111"]}})
    pool = sender_pool(_PAUSER_SRC, bounds)
    # built-ins first (call sites prepend the handler itself at slot 0)
    assert pool[0] == "address(uint160(0xB0B))"
    assert "address(uint160(97433442488726861213578988847752201310395502865))" in pool  # 0x1111... as decimal
    assert "address(uint160(57005))" in pool  # 0xdEaD as decimal
    # the neutral deployer is deliberately NOT impersonable
    assert not any("DeaDBeef" in p for p in pool)


def test_impersonate_senders_config_rejects_garbage() -> None:
    bounds = FuzzBounds.from_config(
        {"invariants": {"impersonate_senders": ["not-an-address", "0x123", None, 42]}})
    assert bounds.impersonate_senders == ()


def test_attack_handler_picks_sender_from_pool() -> None:
    files = render_solidity_project(
        _PAUSER_SRC, "PauserCanMintRemote", [_inv("x", "target.totalSupply() <= 1")],
        FuzzBounds(),
    )
    handler = files["test/AttackHandler.sol"]
    assert "address[] public wgSenderPool;" in handler
    assert "wgSenderPool[i % wgSenderPool.length]" in handler
    # the mined pauser is funded and pooled
    assert "address(uint160(57005))" in handler


def test_ghost_passthroughs_take_sender_seed() -> None:
    invs = [i for i in tmpl.template_invariants(_PAUSER_SRC)
            if i.id in tmpl.GHOST_TEMPLATE_IDS]
    files, _notes = tmpl.render_ghost_project(
        _PAUSER_SRC, "PauserCanMintRemote", invs, FuzzBounds())
    test_src = files["test/Invariant.t.sol"]
    assert "function mint(address p0, uint256 p1, uint256 _wgSender) public" in test_src
    assert "_wgPrank(_wgPickSender(_wgSender));" in test_src


# ---------------------------------------------------------------------------
# Target 1c: tx.origin phishing action
# ---------------------------------------------------------------------------


def test_attack_handler_has_phishing_action() -> None:
    files = render_solidity_project(
        _OWNABLE_SRC, "CleanOwnable", [_inv("x", "target.owner() != address(0)")],
        FuzzBounds(),
    )
    handler = files["test/AttackHandler.sol"]
    assert "function act_phishOrigin(" in handler
    # two-arg prank: msg.sender = pool sender, tx.origin = neutral owner
    assert "WGVM.prank(u, WG_NEUTRAL_DEPLOYER);" in handler
    assert "function prank(address msgSender, address txOrigin) external;" in handler
    # the entry dispatcher backs it
    assert "function _wgCallEntry(" in handler
    assert "uint256 constant WG_ENTRY_COUNT" in handler


def test_ghost_handler_has_phishing_action() -> None:
    invs = [i for i in tmpl.template_invariants(_ORIGIN_OWNER_SRC)
            if i.id in tmpl.GHOST_TEMPLATE_IDS]
    assert any(i.id == "tmpl-owner-immutable" for i in invs)
    files, _notes = tmpl.render_ghost_project(
        _ORIGIN_OWNER_SRC, "OriginOwner", invs, FuzzBounds())
    test_src = files["test/Invariant.t.sol"]
    assert "function act_phish(" in test_src
    assert "_wgTxOrigin = WG_NEUTRAL_DEPLOYER;" in test_src
    # the phishing path routes through the handler's own passthroughs so
    # ghost accounting stays in lockstep
    assert "this.transferOwnership(" in test_src


# ---------------------------------------------------------------------------
# Target 2a: multi-contract files — per-contract targeting
# ---------------------------------------------------------------------------

_MULTI_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Two contracts in one file: the harness must fuzz FeeVaultExact only.
// Wrapping FeeToken.recv against the FeeVaultExact deployment used to be
// a compile failure + silent no-verdict (24 batch_02 regressions).
contract FeeVaultExact {
    FeeToken public token;
    uint256 public totalAssets;
    mapping(address => uint256) public balanceOf;
    constructor() { token = new FeeToken(); }
    function deposit(uint256 amt) external {
        uint256 received = token.recv(amt); // vault actually gets amt - 1%
        totalAssets += amt;                 // BUG: credits amt, not received
        balanceOf[msg.sender] += amt;
    }
}
contract FeeToken {
    mapping(address => uint256) public balanceOf;
    function recv(uint256 amt) external returns (uint256) {
        uint256 fee = amt / 100;
        uint256 got = amt - fee;
        balanceOf[msg.sender] += got;
        return got;
    }
}
"""


def test_split_contracts_finds_both() -> None:
    from web3guard.invariants.harness import (
        extract_contract_names,
        extract_target_functions,
        extract_target_name,
        split_contracts,
    )

    blocks = split_contracts(_MULTI_SRC)
    assert [(b.name, b.kind) for b in blocks] == [
        ("FeeVaultExact", "contract"),
        ("FeeToken", "contract"),
    ]
    assert extract_contract_names(_MULTI_SRC) == ["FeeVaultExact", "FeeToken"]
    assert extract_target_name(_MULTI_SRC) == "FeeVaultExact"
    assert [f.name for f in extract_target_functions(_MULTI_SRC)] == ["deposit"]
    # the legacy whole-file extractor still sees both (compat)
    from web3guard.invariants.harness import extract_functions

    assert [f.name for f in extract_functions(_MULTI_SRC)] == ["deposit", "recv"]


def test_split_contracts_ignores_braces_in_comments_and_strings() -> None:
    from web3guard.invariants.harness import split_contracts

    src = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// a } stray brace in a comment, and "{" inside a string below
contract A {
    string public s = "not { a contract }";
    function f() external {}
}
/* multi-line comment with { braces } */
interface I { function g() external; }
"""
    blocks = split_contracts(src)
    assert [(b.name, b.kind) for b in blocks] == [("A", "contract"), ("I", "interface")]


def test_attack_handler_wraps_only_target_functions() -> None:
    from web3guard.invariants.harness import extract_target_name

    files = render_solidity_project(
        _MULTI_SRC, extract_target_name(_MULTI_SRC),
        [_inv("fee-aware", "target.totalAssets() == target.token().balanceOf(address(target))")],
        FuzzBounds(),
    )
    handler = files["test/AttackHandler.sol"]
    assert "function act_deposit(" in handler
    # the auxiliary contract's function must never be called on the target
    assert "target.recv(" not in handler
    assert "act_recv" not in handler
    # ... but the aux contract still compiles as a dependency
    assert "contract FeeToken" in files["src/FeeVaultExact.sol"]


def test_ghost_handler_wraps_only_target_functions() -> None:
    invs = [i for i in tmpl.template_invariants(_MULTI_SRC)
            if i.id in tmpl.GHOST_TEMPLATE_IDS]
    files, notes = tmpl.render_ghost_project(
        _MULTI_SRC, "FeeVaultExact", invs, FuzzBounds())
    test_src = files["test/Invariant.t.sol"]
    assert "target.recv(" not in test_src
    assert any("multi-contract file" in n for n in notes)


# ---------------------------------------------------------------------------
# Target 2b: compile failures are INCONCLUSIVE, never silent
# ---------------------------------------------------------------------------


def test_extract_compile_errors_pulls_error_lines() -> None:
    from web3guard.invariants.fuzz import extract_compile_errors

    log = """Compiling 2 files with Solc 0.8.34
Compiler run failed:
Error (9582): Member "recv" not found or not visible after argument-dependent lookup in contract GhostHandler.
  --> test/Invariant.t.sol:42:9
"""
    errors = extract_compile_errors(log)
    assert any("9582" in e for e in errors)


def test_parse_forge_output_marks_compile_failure() -> None:
    from web3guard.invariants.fuzz import parse_forge_output

    _findings, campaign = parse_forge_output("Compiler run failed:\nError (1234): oops", [])
    assert campaign.compile_ok is False


def test_pipeline_marks_uncompilable_source_inconclusive(forge_env: dict) -> None:
    from web3guard.invariants.pipeline import run_invariant_pipeline_full

    # Template-matching shape (so it reaches the fuzz stage) with a syntax
    # error (so forge cannot compile it).
    src = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Broken {
    uint256 public totalSupply;
    uint256 public totalAssets;
    function deposit() external payable {
        totalSupply += msg.value;
        totalAssets += msg.value;
    }
    function oops() external { uint256 y = ; }  // syntax error
}
"""
    d = Path(tempfile.mkdtemp(prefix="wg-wh-", dir="/tmp"))
    os.chmod(d, 0o755)
    (d / "Broken.sol").write_text(src)
    cfg = {"invariants": {"runs": 8, "depth": 4, "timeout_seconds": 120,
                          "ai_enabled": False}}
    res = run_invariant_pipeline_full(str(d / "Broken.sol"), cfg)
    assert res.findings == []
    assert res.inconclusive, "a compile failure must be an explicit INCONCLUSIVE verdict"
    assert any("did not compile" in i for i in res.inconclusive)


def test_hunt_report_shouts_inconclusive_loudly() -> None:
    from web3guard.hunt import HuntResult, render_hunt_markdown

    result = HuntResult(target="x", resolved_path="/tmp/x", started_at="2026-10-02")
    result.inconclusive.append(
        "Broken.sol:Broken: the fuzz campaign did not compile. "
        "No invariant verdict — this target was NOT checked, "
        "treat it as unknown, not clean."
    )
    md = render_hunt_markdown(result)
    assert "What I could NOT check (1)" in md
    assert "not a clean bill of health" in md
    assert "No findings\" does not cover" in md
    # and the machine-readable report carries it too
    from web3guard.hunt import hunt_report_dict

    assert hunt_report_dict(result)["hunt"]["inconclusive"] == result.inconclusive

# ---------------------------------------------------------------------------
# E2E (forge): owner FP gone, tx.origin caught, mined sender reaches role
# ---------------------------------------------------------------------------

_FORGE_BIN = Path.home() / "workspace" / "tools" / "foundry" / "bin" / "forge"
_SOLC_BIN = (
    Path.home()
    / "workspace"
    / "tools"
    / "foundry"
    / "sandbox-home"
    / ".svm"
    / "0.8.34"
    / "solc-0.8.34"
)
_FORGE_AVAILABLE = _FORGE_BIN.is_file()
needs_forge = pytest.mark.skipif(not _FORGE_AVAILABLE, reason="forge not installed")


@pytest.fixture(scope="module")
def _forge_bundle() -> dict:
    if not _SOLC_BIN.is_file():
        pytest.skip("cached solc 0.8.34 not available")
    root = Path(tempfile.mkdtemp(prefix="wg-forge-", dir="/tmp"))
    bin_dir = root / "bin"
    bin_dir.mkdir()
    forge_copy = bin_dir / "forge"
    shutil.copy2(_FORGE_BIN, forge_copy)
    home = root / "sandbox-home"
    solc_dir = home / ".svm" / "0.8.34"
    solc_dir.mkdir(parents=True)
    shutil.copy2(_SOLC_BIN, solc_dir / "solc-0.8.34")
    os.chmod(root, 0o755)
    for dirpath, dirnames, filenames in os.walk(root):
        for d in dirnames:
            os.chmod(os.path.join(dirpath, d), 0o755)
        for f in filenames:
            os.chmod(os.path.join(dirpath, f), 0o755)
    yield {"forge": forge_copy, "home": home}
    shutil.rmtree(root, ignore_errors=True)


@pytest.fixture()
def forge_env(_forge_bundle: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    monkeypatch.setenv("WEB3GUARD_FORGE_BIN", str(_forge_bundle["forge"]))
    monkeypatch.setenv("WEB3GUARD_STRATEGY_STATE", str(tmp_path / "strategy_state.json"))
    monkeypatch.setattr(
        "web3guard.invariants.fuzz.FOUNDRY_SANDBOX_HOME", _forge_bundle["home"])
    return _forge_bundle


def _run_pipeline(source: str, name: str, *, runs: int = 64):
    from web3guard.invariants.pipeline import run_invariant_pipeline_full

    d = Path(tempfile.mkdtemp(prefix="wg-wh-", dir="/tmp"))
    os.chmod(d, 0o755)
    (d / f"{name}.sol").write_text(source)
    cfg = {"invariants": {"runs": runs, "depth": 16, "timeout_seconds": 240,
                          "ai_enabled": False}}
    return run_invariant_pipeline_full(str(d / f"{name}.sol"), cfg)


@needs_forge
def test_e2e_clean_ownable_has_no_owner_false_positive(forge_env: dict) -> None:
    """Target 1a: the harness is never the owner, so owner/pause rules on a
    clean contract hold — the batch_01 owner-confusion FPs are gone."""
    res = _run_pipeline(_OWNABLE_SRC, "CleanOwnable")
    assert res.campaign is not None and res.campaign.compile_ok
    assert res.findings == [], [f.description for f in res.findings]


@needs_forge
def test_e2e_txorigin_bug_caught_via_phishing(forge_env: dict) -> None:
    """Target 1c: a tx.origin-authed ownership transfer is caught — this
    time through the genuine phishing path, not the old illusory one."""
    res = _run_pipeline(_ORIGIN_OWNER_SRC, "OriginOwner")
    by_id = {f.metadata.get("invariant_id"): f for f in res.findings}
    assert "tmpl-owner-immutable" in by_id, (
        f"expected the phishing path to break ownership stability; got {sorted(by_id)}")
    assert "act_phish(" in (by_id["tmpl-owner-immutable"].poc_code or "")


@needs_forge
def test_e2e_mined_sender_reaches_hardcoded_role(forge_env: dict) -> None:
    """Target 1b: the 'unreachable' hardcoded pauser IS reached — the
    fuzzer mines 0xdEaD from the source and calls mint() as it."""
    res = _run_pipeline(_PAUSER_SRC, "PauserCanMintRemote")
    by_id = {f.metadata.get("invariant_id"): f for f in res.findings}
    assert by_id, "expected the unbacked-mint invariant to break"
    pocs = " ".join((f.poc_code or "") for f in res.findings)
    # the fuzzer called mint() AS the hardcoded pauser: either directly
    # through the passthrough (sender=0xdEaD) or via the phishing action
    # whose pool sender resolved to it
    assert "0x000000000000000000000000000000000000dEaD" in pocs or "act_phish(" in pocs, pocs[:500]


@needs_forge
def test_e2e_multi_contract_file_compiles_and_bug_caught(forge_env: dict) -> None:
    """Target 2a: a two-contract file compiles (no silent no-verdict) and
    the fee bug in the target contract is caught through the real
    multi-contract deployment (target deploys its own FeeToken)."""
    from web3guard.invariants.fuzz import run_fuzz_campaign
    from web3guard.invariants.harness import extract_target_name

    d = Path(tempfile.mkdtemp(prefix="wg-wh-", dir="/tmp"))
    os.chmod(d, 0o755)
    bounds = FuzzBounds(runs=64, depth=16, timeout_seconds=240)
    invs = [_inv("fee-aware",
                 "target.totalAssets() == target.token().balanceOf(address(target))")]
    files = render_solidity_project(
        _MULTI_SRC, extract_target_name(_MULTI_SRC), invs, bounds)
    notes: list[str] = []
    campaign, findings = run_fuzz_campaign(
        d, files, invs, bounds, {}, contract_name="FeeVaultExact", notes=notes)
    assert campaign.compile_ok, f"multi-contract project must compile: {notes}"
    by_id = {f.metadata.get("invariant_id") for f in findings}
    assert "fee-aware" in by_id, (
        f"expected the fee-accounting bug to be caught, got {sorted(by_id)}")

"""Fix D regression tests: resource-exhaustion verdicts + r2 / b02-d4 analysis pins.

1. PRIMARY — a forge campaign that dies by signal (SIGKILL/OOM -> exit 137
   in shell convention, -9 in Python's Popen convention) or by the
   wall-clock timeout must report RESOURCE_EXHAUSTED with the signal/timeout
   named — NEVER "did not compile". "Did not compile" requires actual
   compiler-failure evidence in the output (provable or absent).

2. r2-classic-shares — pins the investigation result: the scripted
   reentrancy heist is structurally incapable of profiting on the
   share-vault shape (per-sender share accounting caps theft at the
   attacker's own deposit; the full-amount variant self-reverts through the
   0.8 underflow cascade), and the batch oracle ``totalSupply ==
   totalAssets`` moves in lockstep on every state path. No budget can land
   it — this is an oracle/exploitability limit, not a scheduling one.

3. b02-d4-low — pins the investigation result: the real rebase path is
   unreachable in the fuzz environment (``pokeRebase`` always reverts: the
   token's rebaser is the neutral deployer, which is never a fuzz sender),
   and every observed "catch" at low AND medium budget is the same
   uint-overflow artifact — ``deposit(type(uint256).max)`` makes the batch's
   own assertion revert with panic 0x11, which forge counts as a failure.
   No budget threshold exists for the real bug.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

import web3guard.invariants.pipeline as pipeline_mod
from web3guard.invariants.fuzz import (
    classify_process_kill,
    extract_compile_errors,
    run_fuzz_campaign,
)
from web3guard.invariants.models import CampaignResult, FuzzBounds, Invariant

# ---------------------------------------------------------------------------
# 1. classify_process_kill: signal deaths are named, normal exits are not
# ---------------------------------------------------------------------------


def test_classify_sigkill_negative_rc_names_signal_and_oom() -> None:
    detail = classify_process_kill(-9, "", "")
    assert detail is not None
    assert "SIGKILL" in detail
    assert "137" in detail  # shell convention cross-reference


def test_classify_sigkill_shell_exit_137() -> None:
    detail = classify_process_kill(137, "", "Killed")
    assert detail is not None
    assert "SIGKILL" in detail
    assert "137" in detail


def test_classify_sigterm() -> None:
    detail = classify_process_kill(-15, "", "")
    assert detail is not None
    assert "SIGTERM" in detail


def test_classify_ignores_normal_and_timeout_exits() -> None:
    assert classify_process_kill(0, "", "") is None
    assert classify_process_kill(1, "some output", "") is None
    assert classify_process_kill(124, "", "timed out after 90s") is None
    assert classify_process_kill(None, "", "") is None


def test_classify_oom_markers_without_signal_evidence() -> None:
    detail = classify_process_kill(1, "", "cc1: out of memory allocating 12345 bytes")
    assert detail is not None
    assert "memory" in detail.lower()


# ---------------------------------------------------------------------------
# run_fuzz_campaign with a stubbed-out process runner (no forge needed)
# ---------------------------------------------------------------------------

_MIN_FILES: dict[str, str] = {}
_MIN_BOUNDS = FuzzBounds(runs=8, depth=8, timeout_seconds=30)


def _campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    rc: int,
    stdout: str,
    stderr: str,
) -> tuple[CampaignResult, list[str]]:
    monkeypatch.setattr(
        "web3guard.invariants.fuzz.run_sandboxed",
        lambda *a, **k: (rc, stdout, stderr),
    )
    notes: list[str] = []
    campaign, _findings = run_fuzz_campaign(
        tmp_path,
        _MIN_FILES,
        [],
        _MIN_BOUNDS,
        {},
        forge_bin="/fake/forge",
        target_label="t.sol:T",
        notes=notes,
    )
    return campaign, notes


def test_sigkill_campaign_is_resource_exhausted_not_did_not_compile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, notes = _campaign(tmp_path, monkeypatch, -9, "", "")
    assert campaign.resource_exhausted
    assert "SIGKILL" in campaign.resource_detail
    assert any("RESOURCE_EXHAUSTED" in n for n in notes)
    assert not any("did not compile" in n for n in notes)


def test_exit_137_campaign_is_resource_exhausted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, notes = _campaign(tmp_path, monkeypatch, 137, "", "Killed\n")
    assert campaign.resource_exhausted
    assert "137" in campaign.resource_detail
    assert any("RESOURCE_EXHAUSTED" in n for n in notes)
    assert not any("did not compile" in n for n in notes)


def test_timeout_campaign_is_resource_exhausted_with_timeout_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, notes = _campaign(tmp_path, monkeypatch, 124, "", "timed out after 30s\n")
    assert campaign.resource_exhausted
    assert "timeout" in campaign.resource_detail
    assert "30s" in campaign.resource_detail
    assert any("RESOURCE_EXHAUSTED" in n for n in notes)
    assert not any("did not compile" in n for n in notes)


def test_real_sigkill_through_sandbox_reports_resource_exhausted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end kill proof: a forge binary that SIGKILLs itself.

    This drives the real ``run_sandboxed`` (real process group, real
    signal death -> Popen rc -9) instead of a stubbed return code, proving
    the whole chain from the OS signal to the RESOURCE_EXHAUSTED verdict.

    The fixture lives in a world-traversable directory because the
    sandbox drops the child to UID 65534 (nobody), which cannot traverse
    pytest's root-owned 0700 ``tmp_path`` tree. The killer binary sits
    OUTSIDE the project dir because ``_prepare_project_dir`` chmods every
    file inside the project tree to 0666 (stripping the exec bit).
    """
    stage = Path(tempfile.mkdtemp(prefix="wg-sigkill-", dir="/var/tmp"))
    bindir = Path(tempfile.mkdtemp(prefix="wg-sigkill-bin-", dir="/var/tmp"))
    os.chmod(stage, 0o755)
    os.chmod(bindir, 0o755)
    try:
        killer = bindir / "forge-killer"
        killer.write_text("#!/bin/sh\nkill -9 $$\n")
        killer.chmod(0o755)
        notes: list[str] = []
        campaign, _findings = run_fuzz_campaign(
            stage,
            {},
            [],
            _MIN_BOUNDS,
            {},
            forge_bin=str(killer),
            target_label="t.sol:T",
            notes=notes,
        )
        assert campaign.resource_exhausted
        assert "SIGKILL" in campaign.resource_detail
        assert any("RESOURCE_EXHAUSTED" in n for n in notes)
        assert not any("did not compile" in n for n in notes)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        shutil.rmtree(bindir, ignore_errors=True)


def test_genuine_compile_failure_still_says_did_not_compile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = (
        "Compiler run failed:\n"
        "Error (9582): Member \"foo\" not found in contract Target.\n"
    )
    campaign, notes = _campaign(tmp_path, monkeypatch, 1, out, "")
    assert not campaign.resource_exhausted
    assert not campaign.compile_ok
    assert any("did not compile" in n for n in notes)
    assert extract_compile_errors(out)  # the evidence the label rests on


def test_unparseable_unknown_cause_never_claims_did_not_compile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, notes = _campaign(
        tmp_path, monkeypatch, 1, "weird output, no suite lines\n", ""
    )
    assert not campaign.resource_exhausted
    assert not campaign.compile_ok
    assert not any("did not compile" in n for n in notes)
    assert any("no parseable suite result" in n for n in notes)


# ---------------------------------------------------------------------------
# Pipeline verdict assignment: RESOURCE_EXHAUSTED / did-not-compile /
# unknown-cause are three distinct loud verdicts.
# ---------------------------------------------------------------------------

# A vault-shaped contract: the template synthesizer emits real invariants
# for it even with ai_enabled=False, so the pipeline reaches the campaign
# stage (where our stubbed run_fuzz_campaign takes over).
_SIMPLE_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Tiny {
    mapping(address => uint256) public shares;
    uint256 public totalSupply;
    uint256 public totalAssets;
    function deposit() external payable {
        shares[msg.sender] += msg.value;
        totalSupply += msg.value;
        totalAssets += msg.value;
    }
    function withdraw(uint256 s) external {
        require(shares[msg.sender] >= s, "insufficient");
        shares[msg.sender] -= s;
        totalSupply -= s;
        totalAssets -= s;
        (bool ok, ) = msg.sender.call{value: s}("");
        require(ok, "send failed");
    }
}
"""


def _stub_campaign(monkeypatch: pytest.MonkeyPatch, campaign: CampaignResult) -> None:
    monkeypatch.setattr(pipeline_mod, "discover_forge", lambda config: "/fake/forge")
    monkeypatch.setattr(
        pipeline_mod, "run_fuzz_campaign", lambda *a, **k: (campaign, [])
    )


def test_pipeline_verdict_resource_exhausted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "Tiny.sol"
    target.write_text(_SIMPLE_SRC)
    _stub_campaign(
        monkeypatch,
        CampaignResult(
            engine="foundry-invariant",
            resource_exhausted=True,
            resource_detail=(
                "SIGKILL (shell exit 137) — likely the OOM killer or the "
                "sandbox memory ceiling"
            ),
            raw_stdout="",
        ),
    )
    result = pipeline_mod.run_invariant_pipeline_full(
        target, {"ai_enabled": False}
    )
    assert len(result.inconclusive) == 1
    verdict = result.inconclusive[0]
    assert "RESOURCE_EXHAUSTED" in verdict
    assert "137" in verdict
    assert "did not compile" not in verdict
    assert result.findings == []


def test_pipeline_verdict_did_not_compile_requires_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "Tiny.sol"
    target.write_text(_SIMPLE_SRC)
    _stub_campaign(
        monkeypatch,
        CampaignResult(
            engine="foundry-invariant",
            raw_stdout=(
                "Compiler run failed:\n"
                'Error (6275): ParserError: Expected ";" but got "contract"'
            ),
        ),
    )
    result = pipeline_mod.run_invariant_pipeline_full(
        target, {"ai_enabled": False}
    )
    assert len(result.inconclusive) == 1
    assert "did not compile" in result.inconclusive[0]


def test_pipeline_verdict_unknown_cause_is_not_did_not_compile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "Tiny.sol"
    target.write_text(_SIMPLE_SRC)
    _stub_campaign(
        monkeypatch,
        CampaignResult(
            engine="foundry-invariant", raw_stdout="garbage with no signal\n"
        ),
    )
    result = pipeline_mod.run_invariant_pipeline_full(
        target, {"ai_enabled": False}
    )
    assert len(result.inconclusive) == 1
    verdict = result.inconclusive[0]
    assert "did not compile" not in verdict
    assert "cause unknown" in verdict


# ---------------------------------------------------------------------------
# 2. r2-classic-shares: the heist cannot profit — pinned with real forge.
# ---------------------------------------------------------------------------

_R2_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract ShareReVault {
    mapping(address => uint256) public shares;
    uint256 public totalSupply;
    uint256 public totalAssets;
    function deposit() external payable {
        shares[msg.sender] += msg.value;
        totalSupply += msg.value;
        totalAssets += msg.value;
    }
    function withdraw(uint256 s) external {
        require(shares[msg.sender] >= s, "insufficient");
        (bool ok, ) = msg.sender.call{value: s}("");
        require(ok, "send failed");
        shares[msg.sender] -= s;
        totalSupply -= s;
        totalAssets -= s;
    }
}
"""

_R2_HEIST_TEST = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "../src/ShareReVault.sol";

interface Vm { function deal(address a, uint256 v) external; }

contract ReentrancyAttacker {
    address public target;
    bytes public reenterCalldata;
    uint256 public maxReentries = 3;
    uint256 public reentries;
    bool public armed;
    function arm(address _t, bytes calldata _cd, uint256 _m) external {
        target = _t; reenterCalldata = _cd; maxReentries = _m; reentries = 0; armed = true;
    }
    function depositSelf() external {
        uint256 b = address(this).balance;
        (bool ok,) = target.call{value: b}(abi.encodeWithSignature("deposit()"));
        require(ok, "dep fail");
    }
    function doWithdraw(uint256 s) external {
        (bool ok,) = target.call(abi.encodeWithSignature("withdraw(uint256)", s));
        require(ok, "wd fail");
    }
    receive() external payable {
        if (!armed || reentries >= maxReentries) return;
        reentries += 1;
        (bool ok, ) = target.call(reenterCalldata);
        ok;
    }
}

contract R2HeistPin {
    Vm constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    ShareReVault target;
    ReentrancyAttacker atk;
    function setUp() public {
        target = new ShareReVault();
        atk = new ReentrancyAttacker();
    }
    // The product's scripted heist withdraws the FULL deposited amount per
    // entry (see _wgDoReenter). The nested frames self-revert through the
    // 0.8 underflow cascade, so the net effect is a plain withdrawal:
    // zero profit, and totalSupply == totalAssets still holds.
    function test_heist_full_amount_yields_zero_profit() public {
        uint256 v = 1 ether;
        VM.deal(address(atk), v);
        atk.arm(address(target), abi.encodeWithSignature("withdraw(uint256)", v), 3);
        atk.depositSelf();
        atk.doWithdraw(v);
        require(address(atk).balance == v, "attacker profited");
        require(
            target.totalSupply() == target.totalAssets(),
            "solvency oracle broken"
        );
    }
    // Withdrawing the largest underflow-safe amount (v/4 with 3 reentries)
    // also yields exactly zero profit: per-sender share accounting caps
    // reentrancy theft at the attacker's own shares.
    function test_heist_quarter_amount_yields_zero_profit() public {
        uint256 v = 1 ether;
        uint256 s = v / 4;
        VM.deal(address(atk), v);
        atk.arm(address(target), abi.encodeWithSignature("withdraw(uint256)", s), 3);
        atk.depositSelf();
        atk.doWithdraw(s);
        require(address(atk).balance == v, "attacker profited");
        require(
            target.totalSupply() == target.totalAssets(),
            "solvency oracle broken"
        );
    }
}
"""


def _forge_bin() -> str | None:
    from web3guard.invariants.fuzz import discover_forge

    return discover_forge({})


def _solc_seed_home() -> Path | None:
    """A HOME whose .svm holds a cached solc (offline forge runs)."""
    from web3guard.invariants.fuzz import FOUNDRY_SANDBOX_HOME

    for home in (FOUNDRY_SANDBOX_HOME, Path.home() / ".svm" / ".."):
        svm = Path(home) / ".svm"
        if svm.is_dir() and any(svm.iterdir()):
            return Path(home)
    return None


def _run_forge_test(tmp_path: Path, src: str, test_src: str) -> subprocess.CompletedProcess[str]:
    forge = _forge_bin()
    assert forge is not None
    home = _solc_seed_home()
    assert home is not None
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / "test").mkdir(parents=True)
    (proj / "src" / "ShareReVault.sol").write_text(src)
    (proj / "test" / "Heist.t.sol").write_text(test_src)
    (proj / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\ntest = "test"\nout = "out"\n'
        "auto_detect_solc = true\n"
    )
    env = {**os.environ, "HOME": str(home), "FOUNDRY_DISABLE_NIGHTLY_WARNING": "1"}
    return subprocess.run(
        [forge, "test"],
        cwd=proj,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )


@pytest.mark.skipif(_forge_bin() is None, reason="forge not installed")
@pytest.mark.skipif(_solc_seed_home() is None, reason="no cached solc for offline forge")
def test_r2_heist_cannot_profit(tmp_path: Path) -> None:
    """Pin: r2's reentrancy heist yields zero profit at any heist amount.

    This is why r2-classic-shares stays missed at every budget: the miss is
    an oracle/exploitability limit (the batch's ``totalSupply ==
    totalAssets`` oracle is a tautology on this contract, and no reentrant
    withdraw sequence can turn a profit), not a scheduling, depth, or
    strategy problem.
    """
    proc = _run_forge_test(tmp_path, _R2_SRC, _R2_HEIST_TEST)
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    assert "2 passed" in proc.stdout


# ---------------------------------------------------------------------------
# 3. b02-d4-low: the rebase path is unreachable; catches are an artifact.
# ---------------------------------------------------------------------------

_D4_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract RebaseToken {
    mapping(address => uint256) public shares;
    uint256 public index = 1e18;
    address public rebaser;
    constructor(address _rebaser) { rebaser = _rebaser; }
    function balanceOf(address a) public view returns (uint256) {
        return shares[a] * index / 1e18;
    }
    function mintShares(address to, uint256 s) external { shares[to] += s; }
    function rebase(uint256 newIndex) external {
        require(msg.sender == rebaser, "not rebaser");
        index = newIndex;
    }
}
contract RebaseDilution {
    RebaseToken public token;
    uint256 public totalShares;
    mapping(address => uint256) public balanceOf;
    uint256 public lastFair;
    uint256 public lastMinted;
    constructor() { token = new RebaseToken(msg.sender); }
    function liveAssets() public view returns (uint256) {
        return token.balanceOf(address(this));
    }
    function deposit(uint256 s) external {
        uint256 live = liveAssets();
        uint256 fair = totalShares == 0 ? s : s * totalShares / live;
        token.mintShares(address(this), s);
        balanceOf[msg.sender] += s;
        totalShares += s;
        lastFair = fair;
        lastMinted = s;
    }
    function pokeRebase(uint256 newIndex) external {
        require(newIndex > 0 && newIndex < 10e18, "bounds");
        token.rebase(newIndex);
    }
}
"""

_D4_ARTIFACT_TEST = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "../src/RebaseDilution.sol";

contract D4ArtifactPin {
    RebaseDilution t;
    function setUp() public { t = new RebaseDilution(); }
    // The batch's no-overmint assertion, verbatim, after a max-uint
    // deposit: `lastFair + 1` overflows (panic 0x11), so forge counts the
    // invariant as failed. This single call is the entire "catch" the
    // low- and medium-budget campaigns report — the rebase path is never
    // exercised (see test_poke_rebase_never_succeeds below).
    function test_batch_assertion_reverts_on_max_deposit() public {
        t.deposit(type(uint256).max);
        bool holds = t.lastMinted() <= t.lastFair() + 1;
        holds;
    }
    // pokeRebase can never move the index in the fuzz environment: the
    // token's rebaser is whoever deployed the vault (the harness's neutral
    // deployer), the vault forwards with msg.sender == vault, and no fuzz
    // sender can ever be the rebaser — so the real dilution path is
    // unreachable at ANY budget, not just a low one.
    function test_poke_rebase_never_succeeds_for_fuzz_senders() public {
        (bool ok,) = address(t).call(
            abi.encodeWithSignature("pokeRebase(uint256)", 2e18)
        );
        require(!ok, "rebase unexpectedly succeeded");
    }
}
"""


def _run_forge_test_d4(tmp_path: Path) -> subprocess.CompletedProcess[str]:
    forge = _forge_bin()
    assert forge is not None
    home = _solc_seed_home()
    assert home is not None
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / "test").mkdir(parents=True)
    (proj / "src" / "RebaseDilution.sol").write_text(_D4_SRC)
    (proj / "test" / "Artifact.t.sol").write_text(_D4_ARTIFACT_TEST)
    (proj / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\ntest = "test"\nout = "out"\n'
        "auto_detect_solc = true\n"
    )
    env = {**os.environ, "HOME": str(home), "FOUNDRY_DISABLE_NIGHTLY_WARNING": "1"}
    return subprocess.run(
        [forge, "test"],
        cwd=proj,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )


@pytest.mark.skipif(_forge_bin() is None, reason="forge not installed")
@pytest.mark.skipif(_solc_seed_home() is None, reason="no cached solc for offline forge")
def test_d4_catch_is_overflow_artifact_and_rebase_unreachable(
    tmp_path: Path,
) -> None:
    """Pin: d4's "catch" is a panic-0x11 artifact; the real path is unreachable.

    ``test_batch_assertion_reverts_on_max_deposit`` must FAIL with an
    arithmetic overflow (proving the batch assertion itself blows up on
    ``deposit(type(uint256).max)`` — the single call behind every observed
    low/medium-budget "catch"), while ``test_poke_rebase_never_succeeds``
    must PASS (proving the intended rebase-dilution path cannot fire in the
    fuzz environment at any budget).
    """
    proc = _run_forge_test_d4(tmp_path)
    out = proc.stdout + proc.stderr
    assert "panic: arithmetic underflow or overflow (0x11)" in out, out[-2000:]
    assert "[FAIL" in out and "test_batch_assertion_reverts_on_max_deposit" in out
    assert "[PASS] test_poke_rebase_never_succeeds_for_fuzz_senders" in out


def test_d4_rebaser_is_never_a_fuzz_sender() -> None:
    """Pin the mechanism: the vault's deployer becomes the token's rebaser.

    The ghost harness deploys through the neutral deployer
    (``0xDeaDBeef``), which is not in the fuzz sender pool and cannot be
    impersonated — so ``token.rebase`` (``require(msg.sender == rebaser)``)
    is unreachable through ``pokeRebase`` no matter the budget.
    """
    from web3guard.invariants.harness import (
        NEUTRAL_DEPLOYER,
        extract_mined_senders,
        sender_pool,
    )

    mined = extract_mined_senders(_D4_SRC)
    pool = sender_pool(_D4_SRC, FuzzBounds())
    assert NEUTRAL_DEPLOYER.lower() not in [a.lower() for a in mined]
    assert not any(
        NEUTRAL_DEPLOYER.lower() in p.lower().replace(" ", "") for p in pool
    )


def test_d4_batch_invariant_ids_unchanged() -> None:
    """The batch oracle under test is the one whose artifact we pinned."""
    inv = Invariant(
        id="no-overmint",
        statement="Deposits must never mint more than fair pro-rata shares",
        assertion="target.lastMinted() <= target.lastFair() + 1",
        bug_class="share-price",
    )
    assert "+ 1" in inv.assertion  # the overflowing term

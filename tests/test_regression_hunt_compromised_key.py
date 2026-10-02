"""Regression tests for Fix A (weakness 1's overcorrection): the
compromised-key leg.

The neutral-deployer fix made the harness unable to act as the owner at
all, so owner-gated functions became untestable: 8 batch_02
"compromised owner key" cases (b4/b7/c3/g1 x low/med) regressed from
caught to missed. The compromised-key leg impersonates the owner ON
DEMAND (prank as the neutral deployer) in a separate bounded campaign,
while deployment stays neutral.

Covered here (no real AI keys, no network; forge e2e uses the
world-traversable forge bundle pattern):

- owner-gate detection: msg.sender-vs-constructor-assigned-role checks
  and onlyOwner-style modifiers count; tx.origin gates and open
  functions do not;
- the invariant split: consequence bounds stay eligible, benign-owner
  assumptions (owner()/deployer() identity, "never changes" equalities)
  are excluded so n5/n7-style false alarms cannot return;
- render: the compromised project wraps only owner-gated functions as
  the owner and drops the neutral leg's external-attacker machinery;
- e2e: the leg catches an owner-gated price setter, stays silent on the
  n5 clean shape, and does not apply to tx.origin-gated functions.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.invariants.harness import (  # noqa: E402
    detect_owner_gated_functions,
    render_solidity_project,
    split_compromised_key_invariants,
)
from web3guard.invariants.models import FuzzBounds, Invariant  # noqa: E402
from web3guard.invariants.pipeline import _run_compromised_key_leg  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

#: b4 shape: owner-gated price setter; the invariant encodes the real
#: security property (price can't jump >10%) under a compromised key.
_OWNER_ORACLE_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract OwnerOracle {
    uint256 public price = 1e18;
    uint256 public initialPrice = 1e18;
    address public owner;
    constructor() { owner = msg.sender; }
    function setPrice(uint256 p) external {
        require(msg.sender == owner, "not owner");
        price = p;
    }
}
"""

#: c3 shape: owner-gated fee setter with no cap.
_FEE_SETTER_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract FeeSetter {
    uint256 public feeBps = 100;
    uint256 public constant MAX_FEE_BPS = 500;
    address public owner;
    constructor() { owner = msg.sender; }
    function setFee(uint256 f) external {
        require(msg.sender == owner, "not owner");
        feeBps = f;
    }
    function deposit() external payable {}
}
"""

#: n5 shape: clean ownable; the only rule is the benign-owner assumption.
_CLEAN_OWNABLE_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract CleanOwnable {
    address public owner;
    address public deployer;
    constructor() { owner = msg.sender; deployer = msg.sender; }
    function setOwner(address n) external {
        require(msg.sender == owner, "not owner");
        owner = n;
    }
}
"""

#: n7 shape: clean pausable; the only rule is "never paused".
_CLEAN_PAUSABLE_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract CleanPausable {
    address public owner;
    bool public paused;
    constructor() { owner = msg.sender; }
    function pause() external {
        require(msg.sender == owner, "not owner");
        paused = true;
    }
    function unpause() external {
        require(msg.sender == owner, "not owner");
        paused = false;
    }
}
"""

#: t3 shape: tx.origin-gated ownership transfer — phishing territory, not
#: compromised-key territory.
_ORIGIN_OWNER_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract OriginOwner {
    address public owner;
    address public deployer;
    constructor() { owner = msg.sender; deployer = msg.sender; }
    function transferOwnership(address n) external {
        require(tx.origin == owner, "bad origin");
        owner = n;
    }
}
"""

#: OpenZeppelin-style: private _owner + onlyOwner modifier.
_OZ_STYLE_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract OzLike {
    address private _owner;
    constructor() { _owner = msg.sender; }
    modifier onlyOwner() {
        require(msg.sender == _owner, "not owner");
        _;
    }
    function setX(uint256 x) external onlyOwner {}
    function openY() external {}
}
"""

#: Proxy-style: the owner is assigned in initialize(), not the constructor.
_INIT_STYLE_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract InitLike {
    address public owner;
    function initialize() external {
        owner = msg.sender;
    }
    function setX(uint256 x) external {
        require(msg.sender == owner, "not owner");
    }
}
"""


def _inv(iid: str, assertion: str) -> Invariant:
    return Invariant(id=iid, statement=iid, assertion=assertion)


# ---------------------------------------------------------------------------
# Unit: owner-gate detection
# ---------------------------------------------------------------------------


def test_detect_owner_gated_finds_constructor_assigned_role() -> None:
    gated = detect_owner_gated_functions(_OWNER_ORACLE_SRC)
    assert [f.name for f in gated] == ["setPrice"]


def test_detect_owner_gated_finds_fee_setter_not_open_deposit() -> None:
    gated = detect_owner_gated_functions(_FEE_SETTER_SRC)
    assert [f.name for f in gated] == ["setFee"]


def test_detect_owner_gated_supports_onlyowner_modifier() -> None:
    gated = detect_owner_gated_functions(_OZ_STYLE_SRC)
    assert [f.name for f in gated] == ["setX"]


def test_detect_owner_gated_supports_initializer_assignment() -> None:
    gated = detect_owner_gated_functions(_INIT_STYLE_SRC)
    assert [f.name for f in gated] == ["setX"]


def test_detect_owner_gated_ignores_txorigin_gates() -> None:
    # tx.origin authentication belongs to the phishing threat model
    # (tested in the neutral leg), not the compromised-key leg.
    assert detect_owner_gated_functions(_ORIGIN_OWNER_SRC) == []


def test_detect_owner_gated_ignores_view_functions() -> None:
    src = _OWNER_ORACLE_SRC.replace(
        "function setPrice", "function getPrice() external view returns (uint256) { return price; }\n    function setPrice"
    )
    gated = detect_owner_gated_functions(src)
    assert [f.name for f in gated] == ["setPrice"]


# ---------------------------------------------------------------------------
# Unit: the invariant split (the anti-false-alarm half of the fix)
# ---------------------------------------------------------------------------


def test_split_keeps_consequence_bounds_eligible() -> None:
    invs = [
        _inv("owner-price-cap", "target.price() <= target.initialPrice() * 11 / 10"),
        _inv("agg-band", "target.getPrice() >= target.initialPrice() * 9 / 10 && target.getPrice() <= target.initialPrice() * 11 / 10"),
        _inv("fee-cap", "target.feeBps() <= target.MAX_FEE_BPS()"),
        _inv("price-ceiling", "target.price() <= target.MAX_PRICE()"),
        _inv("solvency", "target.totalSupply() == target.totalAssets()"),
    ]
    eligible, excluded = split_compromised_key_invariants(invs)
    assert [i.id for i in eligible] == [i.id for i in invs]
    assert excluded == []


def test_split_excludes_benign_owner_assumptions() -> None:
    # n5: "ownership never changes without the owner" — vacuous when the
    # owner key itself is the attacker.
    # n7: "never paused" — a compromised owner legitimately pausing would
    # break it, manufacturing a false positive.
    invs = [
        _inv("owner-stable", "target.owner() == target.deployer()"),
        _inv("pause-intent", "target.paused() == false"),
        _inv("minter-set", "target.minter() != address(0)"),
    ]
    eligible, excluded = split_compromised_key_invariants(invs)
    assert eligible == []
    assert sorted(iid for iid, _ in excluded) == [
        "minter-set",
        "owner-stable",
        "pause-intent",
    ]


# ---------------------------------------------------------------------------
# Unit: compromised render
# ---------------------------------------------------------------------------


def test_compromised_render_wraps_only_owner_gated_as_owner() -> None:
    files = render_solidity_project(
        _FEE_SETTER_SRC,
        "FeeSetter",
        [_inv("fee-cap", "target.feeBps() <= target.MAX_FEE_BPS()")],
        FuzzBounds(runs=16, depth=8),
        attack=True,
        compromised_key=True,
    )
    handler = files["test/AttackHandler.sol"]
    # the owner-gated setter is callable AS the owner, on demand
    assert "function act_ck_setFee(" in handler
    assert "WGVM.prank(WG_NEUTRAL_DEPLOYER);" in handler
    # the open deposit() is NOT wrapped as the owner (neutral leg covers it)
    assert "function act_ck_deposit(" not in handler
    assert "function act_deposit(" not in handler
    # the neutral leg's external-attacker machinery is omitted
    for action in (
        "act_phishOrigin",
        "act_warpTime",
        "act_donateForcedEth",
        "act_heist",
        "act_adaptiveAssault",
        "act_approvalDrain",
    ):
        assert f"function {action}(" not in handler, action
    # deployment stays neutral; attacker contracts are not deployed
    assert "target = new FeeSetter();" in handler
    assert "new DonationAttacker()" not in handler
    # the entry dispatcher only contains the owner-gated function
    assert "WG_ENTRY_COUNT = 1" in handler
    assert "target.setFee(a)" in handler


def test_neutral_render_unchanged_by_compromised_flag() -> None:
    # compromised_key defaults off and changes nothing about the neutral leg
    files = render_solidity_project(
        _OWNER_ORACLE_SRC,
        "OwnerOracle",
        [_inv("owner-price-cap", "target.price() <= target.initialPrice() * 11 / 10")],
        FuzzBounds(runs=16, depth=8),
        attack=True,
    )
    handler = files["test/AttackHandler.sol"]
    assert "function act_setPrice(" in handler
    assert "function act_ck_setPrice(" not in handler
    assert "function act_phishOrigin(" in handler


def test_compromised_key_leg_config_defaults_on_and_disables() -> None:
    assert FuzzBounds().compromised_key_leg is True
    assert FuzzBounds.from_config({}).compromised_key_leg is True
    off = FuzzBounds.from_config({"invariants": {"compromised_key_leg": False}})
    assert off.compromised_key_leg is False
    on = FuzzBounds.from_config({"invariants": {"compromised_key_leg": True}})
    assert on.compromised_key_leg is True


# ---------------------------------------------------------------------------
# E2E (forge): the leg catches the bug, stays silent where it should
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
def _forge_bundle() -> Iterator[dict]:
    if not _SOLC_BIN.is_file():
        pytest.skip("cached solc 0.8.34 not available")
    root = Path(tempfile.mkdtemp(prefix="wg-ck-forge-", dir="/tmp"))
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


def _run_leg(
    source: str,
    contract_name: str,
    invariants: list[Invariant],
    tmp_path: Path,
    *,
    skip_ids: set[str] | None = None,
):
    # NOTE: the leg's project dir must live directly under /tmp (like
    # test_weakness_hunt._run_pipeline): the sandboxed forge child drops
    # to ``nobody`` and cannot traverse pytest's nested 0700 tmp_path
    # grandparents.
    notes: list[str] = []
    parent = Path(tempfile.mkdtemp(prefix="wg-ck-leg-", dir="/tmp"))
    os.chmod(parent, 0o755)
    try:
        return _run_compromised_key_leg(
            source=source,
            contract_name=contract_name,
            invariants=invariants,
            bounds=FuzzBounds(runs=64, depth=8, timeout_seconds=120),
            config={"invariants": {"ai_enabled": False}},
            parent_dir=parent,
            contract_path=f"{contract_name}.sol",
            target_label=f"{contract_name}.sol:{contract_name}",
            notes=notes,
            skip_invariant_ids=skip_ids or set(),
        ), notes
    finally:
        shutil.rmtree(parent, ignore_errors=True)


@needs_forge
def test_e2e_compromised_key_leg_catches_owner_gated_price_setter(
    forge_env: dict, tmp_path: Path
) -> None:
    """The b4 shape: a compromised owner key smashes the 10% price band."""
    (campaign, findings), notes = _run_leg(
        _OWNER_ORACLE_SRC,
        "OwnerOracle",
        [_inv("owner-price-cap", "target.price() <= target.initialPrice() * 11 / 10")],
        tmp_path,
    )
    assert campaign is not None and campaign.compile_ok, notes
    by_id = {f.metadata.get("invariant_id"): f for f in findings}
    assert "owner-price-cap" in by_id, (
        f"expected the compromised-key leg to break the price band; "
        f"got {sorted(by_id)}; notes={notes}"
    )
    finding = by_id["owner-price-cap"]
    assert finding.metadata.get("scenario") == "compromised-key"
    assert "[compromised-key scenario]" in finding.description
    assert "compromised-key" in finding.tool_consensus


@needs_forge
def test_e2e_compromised_key_leg_catches_uncapped_fee_setter(
    forge_env: dict, tmp_path: Path
) -> None:
    """The c3 shape: a compromised owner key blows past the fee cap."""
    (campaign, findings), notes = _run_leg(
        _FEE_SETTER_SRC,
        "FeeSetter",
        [_inv("fee-cap", "target.feeBps() <= target.MAX_FEE_BPS()")],
        tmp_path,
    )
    assert campaign is not None and campaign.compile_ok, notes
    by_id = {f.metadata.get("invariant_id"): f for f in findings}
    assert "fee-cap" in by_id, (
        f"expected the compromised-key leg to break the fee cap; "
        f"got {sorted(by_id)}; notes={notes}"
    )


@needs_forge
def test_e2e_compromised_key_leg_stays_clean_on_benign_owner_rules(
    forge_env: dict, tmp_path: Path
) -> None:
    """n5/n7 shapes: benign-owner assumptions are excluded, so the leg
    must not fire on these clean contracts (no owner-confusion FPs)."""
    for src, name, inv in (
        (_CLEAN_OWNABLE_SRC, "CleanOwnable",
         _inv("owner-stable", "target.owner() == target.deployer()")),
        (_CLEAN_PAUSABLE_SRC, "CleanPausable",
         _inv("pause-intent", "target.paused() == false")),
    ):
        (campaign, findings), notes = _run_leg(src, name, [inv], tmp_path)
        assert campaign is None, (
            f"expected the leg to not apply to {name} (no eligible "
            f"invariants); notes={notes}"
        )
        assert findings == []


@needs_forge
def test_e2e_compromised_key_leg_does_not_apply_to_txorigin(
    forge_env: dict, tmp_path: Path
) -> None:
    """t3 shape: tx.origin gates are phishing territory — the leg stays out."""
    (campaign, findings), notes = _run_leg(
        _ORIGIN_OWNER_SRC,
        "OriginOwner",
        [_inv("owner-stable", "target.owner() == target.deployer()")],
        tmp_path,
    )
    assert campaign is None, f"expected no leg for tx.origin gates; notes={notes}"
    assert findings == []


@needs_forge
def test_e2e_compromised_key_leg_disabled_by_config(
    forge_env: dict, tmp_path: Path
) -> None:
    """The operator can turn the leg off."""
    notes: list[str] = []
    campaign, findings = _run_compromised_key_leg(
        source=_OWNER_ORACLE_SRC,
        contract_name="OwnerOracle",
        invariants=[_inv("owner-price-cap", "target.price() <= target.initialPrice() * 11 / 10")],
        bounds=FuzzBounds(runs=64, depth=8, timeout_seconds=120,
                          compromised_key_leg=False),
        config={"invariants": {"ai_enabled": False}},
        parent_dir=tmp_path,
        contract_path="OwnerOracle.sol",
        target_label="OwnerOracle.sol:OwnerOracle",
        notes=notes,
        skip_invariant_ids=set(),
    )
    assert campaign is None
    assert findings == []


# ---------------------------------------------------------------------------
# Ghost-harness leg (the 8 misses ran through ghost mode: a ghost template
# id such as tmpl-owner-immutable forces the ghost renderer, so the
# compromised-key leg must work there too).
# ---------------------------------------------------------------------------

from web3guard.invariants.templates import render_ghost_project  # noqa: E402


def _ghost_bounds() -> FuzzBounds:
    return FuzzBounds(runs=64, depth=8, timeout_seconds=120)


def test_ghost_compromised_render_pranks_owner_and_drops_attack_machinery() -> None:
    """In compromised-key ghost mode, owner-gated passthroughs prank as
    the owner (neutral deployer); attacker contracts, attack actions and
    the phishing action are gone."""
    src = """\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract GatedWithOpen {
        uint256 public price = 1e18;
        uint256 public initialPrice = 1e18;
        address public owner;
        constructor() { owner = msg.sender; }
        function setPrice(uint256 p) external {
            require(msg.sender == owner, "not owner");
            price = p;
        }
        function poke() external {}
    }
    """
    inv = _inv("owner-price-cap", "target.price() <= target.initialPrice() * 11 / 10")
    files, notes = render_ghost_project(
        src, "GatedWithOpen", [inv], _ghost_bounds(),
        attack=False, compromised_key=True,
    )
    handler = files["test/Invariant.t.sol"]
    # The owner-gated setPrice passthrough pranks as the owner...
    seg = handler.split("function setPrice(")[1].split("\n    }\n")[0]
    assert "WGVM.prank(WG_NEUTRAL_DEPLOYER)" in seg
    assert "_wgPickSender" not in seg
    # ...while the open poke() passthrough keeps the sender pool.
    seg2 = handler.split("function poke(")[1].split("\n    }\n")[0]
    assert "_wgPrank(_wgPickSender(_wgSender))" in seg2
    # No external-attacker machinery in the scenario.
    assert "DonationAttacker" not in handler
    assert "function act_phish(" not in handler
    assert "function act_attack(" not in handler
    assert "act_donateForcedEth" not in handler
    assert any("COMPROMISED-KEY" in n for n in notes)


def test_ghost_compromised_render_allows_plain_invariants_only() -> None:
    """The leg asserts plain (non-ghost) invariants: no ghost template
    specs are required in compromised-key mode."""
    inv = _inv("owner-price-cap", "target.price() <= target.initialPrice() * 11 / 10")
    files, _ = render_ghost_project(
        _OWNER_ORACLE_SRC, "OwnerOracle", [inv], _ghost_bounds(),
        attack=False, compromised_key=True,
    )
    test_src = files["test/Invariant.t.sol"]
    assert "invariant_owner_price_cap" in test_src


def test_ghost_neutral_render_unchanged_by_compromised_flag() -> None:
    """Default ghost rendering is untouched: the owner-prank only
    happens when compromised_key=True is passed explicitly, and the
    plain-only ValueError gate still applies to the neutral path."""
    from web3guard.invariants.harness import extract_target_functions
    from web3guard.invariants.templates import _passthrough

    sig = next(
        s for s in extract_target_functions(_OWNER_ORACLE_SRC) if s.name == "setPrice"
    )
    neutral = _passthrough(sig, [])
    assert "_wgPrank(_wgPickSender(_wgSender))" in neutral
    assert "WGVM.prank(WG_NEUTRAL_DEPLOYER)" not in neutral
    ck = _passthrough(sig, [], compromised=True)
    assert "WGVM.prank(WG_NEUTRAL_DEPLOYER)" in ck
    assert "_wgPickSender" not in ck
    # The neutral path still requires a ghost template (unchanged gate).
    inv = _inv("owner-price-cap", "target.price() <= target.initialPrice() * 11 / 10")
    with pytest.raises(ValueError, match="no ghost templates to render"):
        render_ghost_project(
            _OWNER_ORACLE_SRC, "OwnerOracle", [inv], _ghost_bounds(), attack=False
        )


def _run_ghost_leg(
    source: str,
    contract_name: str,
    invariants: list[Invariant],
    tmp_path: Path,
):
    notes: list[str] = []
    parent = Path(tempfile.mkdtemp(prefix="wg-ck-ghost-leg-", dir="/tmp"))
    os.chmod(parent, 0o755)
    try:
        return _run_compromised_key_leg(
            source=source,
            contract_name=contract_name,
            invariants=invariants,
            bounds=_ghost_bounds(),
            config={"invariants": {"ai_enabled": False}},
            parent_dir=parent,
            contract_path=f"{contract_name}.sol",
            target_label=f"{contract_name}.sol:{contract_name}",
            notes=notes,
            skip_invariant_ids=set(),
            ghost_mode=True,
        ), notes
    finally:
        shutil.rmtree(parent, ignore_errors=True)


@needs_forge
def test_e2e_ghost_compromised_key_leg_catches_owner_gated_price_setter(
    forge_env: dict, tmp_path: Path
) -> None:
    """The b4 shape through the ghost renderer: the fuzzer acts as the
    owner (pranked neutral deployer) and smashes the 10% price band."""
    (campaign, findings), notes = _run_ghost_leg(
        _OWNER_ORACLE_SRC,
        "OwnerOracle",
        [_inv("owner-price-cap", "target.price() <= target.initialPrice() * 11 / 10")],
        tmp_path,
    )
    assert campaign is not None and campaign.compile_ok, notes
    by_id = {f.metadata.get("invariant_id"): f for f in findings}
    assert "owner-price-cap" in by_id, (
        f"expected the ghost compromised-key leg to break the price band; "
        f"got {sorted(by_id)}; notes={notes}"
    )
    assert by_id["owner-price-cap"].metadata.get("scenario") == "compromised-key"


@needs_forge
def test_e2e_ghost_compromised_key_leg_stays_clean_on_benign_owner_rules(
    forge_env: dict, tmp_path: Path
) -> None:
    """n5/n7 through the ghost leg: owner()/deployer() identity views and
    'never changes' equalities are excluded from the leg, so no findings."""
    (campaign, findings), notes = _run_ghost_leg(
        _CLEAN_OWNABLE_SRC,
        "CleanOwnable",
        [
            _inv("owner-stable", "target.owner() == target.deployer()"),
            _inv("tmpl-owner-nonzero", "target.owner() != address(0)"),
        ],
        tmp_path,
    )
    assert campaign is None, f"expected no leg for benign-owner rules; notes={notes}"
    assert findings == []

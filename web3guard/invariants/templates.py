"""Widened invariant template library + ghost-state harness rendering (Phase 3).

This module owns the hand-written invariant templates — the keyless baseline
layer of the pipeline. Two upgrades over the original 3-template set:

1. **A wide registry** (:data:`SOLIDITY_TEMPLATES`, ~17 templates) across the
   categories the adversarial review cares about: balance/total-supply
   conservation, access control, arithmetic bounds, pausing correctness, fee
   accounting, allowance handling, mint/burn symmetry, oracle staleness,
   share-price sanity (the Balancer class). Each template declares
   applicability conditions (``requires`` / ``requires_absent`` /
   ``name_choices`` / regex captures) so it only fires where it makes sense.

2. **Temporal properties via ghost state.** Some properties ("totalWithdrawn
   never exceeds totalDeposited", "ownership never changes", "allowance never
   exceeds what was approved") cannot be expressed from on-chain state alone.
   Templates with a :class:`GhostSpec` get a generated ``GhostHandler``
   contract (see :func:`render_ghost_project`) that wraps every fuzzable
   target function, keeps ghost variables in lockstep with real calls, and
   exposes them for assertions. The fuzzer is restricted to the handler via
   the forge-std-free ``targetContracts()`` hook (part of Foundry's invariant
   protocol — verified against the pinned Foundry build), so no call can
   bypass ghost accounting.

Honest limits (documented, not hidden):
- Ghost hooks only track calls the fuzzer can reach: public/external
  functions with primitive-typed parameters. Anything else is skipped with
  a loud note.
- ``{plast}`` amount tracking resolves to the last uint parameter, or to
  ``msg.value`` for payable no-arg functions; anything else skips the hook.
- Reentrancy-guard *presence* is not a state invariant and is not covered
  here — it belongs to static analysis, and dynamic re-entry needs an
  attacker contract (the simulator's job, not the invariant pipeline's).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from web3guard.invariants.harness import extract_pragma
from web3guard.invariants.models import FuzzBounds, Invariant

LOGGER = logging.getLogger("web3guard.invariants.templates")

# ---------------------------------------------------------------------------
# Template model
# ---------------------------------------------------------------------------


@dataclass
class TrackedCall:
    """One target function whose calls update ghost state.

    The rendered handler wraps the target function; on success it runs
    ``update`` (or ``custom_body``). Placeholders:

    - ``{p0}``..``{pn}`` — the wrapped call's parameters (always named
      ``p0``.. in the handler, regardless of source names),
    - ``{plast}`` — the last parameter, or ``msg.value`` for payable
      no-arg functions (resolved at render time; the hook is skipped when
      neither applies),
    - ``{args}`` — comma-joined parameter names,
    - ``{call}`` — the full call expression, e.g.
      ``target.deposit{value: msg.value}(p0)`` (custom bodies only),
    - ``{t}`` — the sanitized template id (for collision-free locals).
    """

    function: str
    update: str = ""
    custom_body: str = ""


@dataclass
class GhostSpec:
    """Ghost state a template needs in the handler contract."""

    vars: list[tuple[str, str]] = field(default_factory=list)
    #: (name, solidity type) — rendered as ``<type> public <name>;``
    setup: list[str] = field(default_factory=list)
    #: statements run in the handler constructor after target deployment
    tracked: list[TrackedCall] = field(default_factory=list)
    observe_after_all: list[str] = field(default_factory=list)
    #: statements appended (inside try) after EVERY wrapped call
    extra_fns: list[str] = field(default_factory=list)
    #: raw Solidity functions added to the handler
    handler_fn_names: list[str] = field(default_factory=list)
    #: public function names from extra_fns (for the proof gate's allowlist)


@dataclass
class TemplateSpec:
    """One hand-written invariant template with applicability conditions."""

    id: str
    statement: str
    requires: list[str] = field(default_factory=list)
    #: regexes; ALL must match the source
    requires_absent: list[str] = field(default_factory=list)
    #: regexes; NONE may match (e.g. fee markers that invalidate 1:1 rules)
    name_choices: dict[str, list[str]] = field(default_factory=dict)
    #: placeholder -> candidate getter names; first hit wins, else N/A
    assertion: str = ""
    #: single boolean expression over ``target`` / ``handler`` (formatted)
    body: str = ""
    #: full invariant-function body (for multi-statement properties)
    rationale: str = ""
    bug_class: str = "other"
    severity: str = "MEDIUM"
    ghost: GhostSpec | None = None
    temporal_scope: str = "permanent"
    #: Weakness-hunt round, target 5: "permanent" vs "time-limited".
    #: Time-limited rules (e.g. oracle freshness windows) must not be
    #: tested under time-warp — warping past the window is a false
    #: positive, not a bug.

    def match(self, source: str) -> dict[str, str] | None:
        """Return placeholder bindings if the template applies, else None."""
        bindings: dict[str, str] = {}
        for pat in self.requires:
            try:
                m = re.search(pat, source)
            except re.error:
                LOGGER.warning("template %s bad requires regex: %s", self.id, pat)
                return None
            if not m:
                return None
            for k, v in (m.groupdict() or {}).items():
                if v is not None:
                    bindings.setdefault(k, v)
        for pat in self.requires_absent:
            try:
                if re.search(pat, source):
                    return None
            except re.error:
                LOGGER.warning("template %s bad absent regex: %s", self.id, pat)
        for placeholder, candidates in self.name_choices.items():
            hit = None
            for cand in candidates or []:
                if re.search(_getter_pat(cand), source):
                    hit = cand
                    break
            if hit is None:
                return None
            bindings[placeholder] = hit
        return bindings

    def applies(self, source: str) -> bool:
        return self.match(source) is not None

    def to_invariant(self, bindings: Mapping[str, str] | None = None) -> Invariant:
        b = {"t": _sanitize(self.id)}
        if bindings:
            b.update(bindings)
        return Invariant(
            id=self.id,
            statement=self.statement,
            assertion=_sub(self.assertion, b),
            rationale=self.rationale,
            bug_class=self.bug_class,
            source="template",
            severity=self.severity,
            temporal_scope=self.temporal_scope,
        )


def _sanitize(name: str) -> str:
    return re.sub(r"\W", "_", name) or "x"


#: Weakness-hunt round, target 5: regexes that mark an invariant as
#: time-limited (only meaningful within a time window). Matched against
#: the statement + assertion of LLM/sharp-rule invariants.
_TIME_LIMITED_RE = re.compile(
    r"block\.timestamp|deadline|expir|fresh|stale|updatedAt|"
    r"no older than|within \d+ (day|hour|minute|second)",
    re.IGNORECASE,
)


def infer_temporal_scope(inv: Invariant) -> str:
    """Infer ``temporal_scope`` for a non-template invariant.

    Template invariants carry their scope from the spec; LLM- or
    sharp-rule-drafted invariants get it from regexes over the statement
    and assertion. Returns "time-limited" or "permanent".
    """
    if inv.temporal_scope != "permanent":
        return inv.temporal_scope
    haystack = f"{inv.statement} {inv.assertion}"
    if _TIME_LIMITED_RE.search(haystack):
        return "time-limited"
    return "permanent"


def _sub(text: str, bindings: Mapping[str, str]) -> str:
    """Replace ``{placeholder}`` tokens; leave other braces untouched."""

    def _rep(m: re.Match[str]) -> str:
        return bindings.get(m.group(1), m.group(0))

    return re.sub(r"\{([A-Za-z_]\w*)\}", _rep, text)


# Matches either an explicit getter (``totalSupply()``) or a public state
# variable declaration (``uint256 public totalSupply;``), which Solidity
# auto-exposes as a getter.
def _getter_pat(name: str) -> str:
    return rf"(?:\bpublic\b[^\n;{{}}]*\b{name}\b|\b{name}\s*\(\s*\))"


# Vyper: ``total_supply: public(uint256)`` or ``def total_supply(``.
def _vyper_getter_pat(name: str) -> str:
    return rf"(?:\b{name}\s*:\s*public\s*\(|\bdef\s+{name}\s*\()"


# Cairo: ``fn total_supply(`` inside the contract or its interface trait.
def _cairo_getter_pat(name: str) -> str:
    return rf"\bfn\s+{name}\s*\("


def _fn_pat(name: str) -> str:
    return rf"function\s+{name}\s*\("


# ---------------------------------------------------------------------------
# The widened Solidity template registry (~17 templates)
# ---------------------------------------------------------------------------

#: Markers that invalidate naive 1:1 accounting assumptions (the adversarial
#: review's limit #9: "totalSupply == totalAssets" is false by design for
#: fee/yield/rebasing vaults — so the solvency templates stay away).
_FEE_MARKERS = [
    r"\b[Ff]ees?\b",
    r"\b[Yy]ield\b",
    r"\b[Ii]nterest\b",
    r"\b[Rr]ebas\w*\b",
]

_BALMAP_PAT = (
    r"mapping\s*\(\s*address\s*=>\s*uint\d*\s*\)\s+public\s+(?P<balmap>\w+)"
)

SOLIDITY_TEMPLATES: list[TemplateSpec] = [
    # --- balance / total-supply conservation ---------------------------
    TemplateSpec(
        id="tmpl-solvency-1-1",
        statement="For a 1:1 vault, totalSupply must always equal totalAssets: "
                  "every share in existence is backed by exactly one unit of assets.",
        requires=[_getter_pat("totalSupply"), _getter_pat("totalAssets")],
        requires_absent=_FEE_MARKERS,
        assertion="target.totalSupply() == target.totalAssets()",
        rationale="A mismatch means shares were minted without backing "
                  "(free mint / donation-inflation hole) or assets left "
                  "without burning shares — the classic vault accounting "
                  "desync behind share-price manipulation exploits. "
                  "Skipped for fee/yield/rebasing vaults where 1:1 cannot hold.",
        bug_class="accounting-desync",
        severity="HIGH",
    ),
    TemplateSpec(
        id="tmpl-total-deposited-gte-withdrawn",
        statement="Cumulative withdrawals must never exceed cumulative deposits.",
        requires=[_getter_pat("totalDeposited"), _getter_pat("totalWithdrawn")],
        requires_absent=_FEE_MARKERS,
        assertion="target.totalWithdrawn() <= target.totalDeposited()",
        rationale="Withdrawals exceeding deposits means value left the contract "
                  "that never entered it — unbacked payouts, the money-flow "
                  "bug behind the largest historic payouts.",
        bug_class="accounting-desync",
        severity="HIGH",
    ),
    TemplateSpec(
        id="tmpl-no-unbacked-balance",
        statement="No account's recorded balance may exceed what was ever "
                  "deposited (ghost-tracked across all calls).",
        requires=[_BALMAP_PAT, _fn_pat("deposit")],
        ghost=GhostSpec(
            vars=[("ghost_cumDeposited", "uint256")],
            tracked=[TrackedCall(function="deposit",
                                 update="ghost_cumDeposited += {plast};")],
        ),
        assertion="target.{balmap}(address(handler)) <= handler.ghost_cumDeposited()",
        rationale="Catches free mints / unbacked balance inflation (the skim "
                  "class): any path that credits balances without a matching "
                  "deposit breaks this, even when totalSupply looks fine.",
        bug_class="accounting-desync",
        severity="HIGH",
    ),
    TemplateSpec(
        id="tmpl-mint-burn-balanced",
        statement="totalSupply must always equal initial supply + minted - burned "
                  "(ghost-tracked across all calls).",
        requires=[_getter_pat("totalSupply"), _fn_pat("mint"), _fn_pat("burn")],
        ghost=GhostSpec(
            vars=[("ghost_mb_minted", "uint256"),
                  ("ghost_mb_burned", "uint256"),
                  ("ghost_mb_initial", "uint256")],
            setup=["ghost_mb_initial = target.totalSupply();"],
            tracked=[
                TrackedCall(function="mint",
                            update="ghost_mb_minted += {plast};"),
                TrackedCall(function="burn",
                            update="ghost_mb_burned += {plast};"),
            ],
        ),
        assertion="target.totalSupply() + handler.ghost_mb_burned() "
                  "== handler.ghost_mb_initial() + handler.ghost_mb_minted()",
        rationale="Catches hidden mint paths (rewards/claims that mint without "
                  "going through mint()) and burns that forget to reduce "
                  "supply — supply manipulation invisible to single-variable checks.",
        bug_class="accounting-desync",
        severity="HIGH",
    ),
    # --- temporal: cumulative flows via ghost state ----------------------
    TemplateSpec(
        id="tmpl-cum-withdraw-lte-deposit",
        statement="The contract's cumulative withdrawal counter must never exceed "
                  "ghost-tracked cumulative deposits.",
        requires=[_getter_pat("totalWithdrawn"), _fn_pat("deposit"),
                  _fn_pat("withdraw")],
        ghost=GhostSpec(
            vars=[("ghost_cumDeposited", "uint256")],
            tracked=[TrackedCall(function="deposit",
                                 update="ghost_cumDeposited += {plast};")],
        ),
        assertion="target.totalWithdrawn() <= handler.ghost_cumDeposited()",
        rationale="Temporal property: compares the contract's own cumulative "
                  "counter against ground truth (every deposit call the fuzzer "
                  "made). Phantom accounting — multipliers, double counts, "
                  "rebate bugs — breaks it.",
        bug_class="accounting-desync",
        severity="HIGH",
    ),
    TemplateSpec(
        id="tmpl-cum-flow-conservation",
        statement="Ghost-tracked cumulative withdrawals must never exceed "
                  "ghost-tracked cumulative deposits (pure temporal property, "
                  "needs no contract getters).",
        requires=[_fn_pat("deposit"), _fn_pat("withdraw")],
        requires_absent=[r"\b[Bb]onus\w*\b", r"\b[Rr]eward\w*\b"],
        ghost=GhostSpec(
            vars=[("ghost_pureDep", "uint256"), ("ghost_pureWd", "uint256")],
            tracked=[
                TrackedCall(function="deposit",
                            update="ghost_pureDep += {plast};"),
                TrackedCall(function="withdraw",
                            update="ghost_pureWd += {plast};"),
            ],
        ),
        assertion="handler.ghost_pureWd() <= handler.ghost_pureDep()",
        rationale="The money-flow invariant behind the biggest payouts, stated "
                  "purely over call history: a sound vault cannot pay out more "
                  "than it took in, no matter what its getters expose. "
                  "Withdrawals are tracked in the units the withdraw function "
                  "takes, deposits in value/amount units; sound for plain "
                  "vaults where minted shares never exceed deposited assets. "
                  "Skipped for bonus/reward vaults where that assumption fails.",
        bug_class="accounting-desync",
        severity="HIGH",
    ),
    TemplateSpec(
        id="tmpl-cum-deposited-monotonic",
        statement="The cumulative deposit counter must never decrease between calls.",
        requires=[_getter_pat("totalDeposited")],
        ghost=GhostSpec(
            vars=[("ghost_prevTotalDeposited", "uint256"),
                  ("ghost_depDecreases", "uint256")],
            setup=["ghost_prevTotalDeposited = target.totalDeposited();"],
            observe_after_all=[
                "uint256 {t}nd = target.totalDeposited();",
                "if ({t}nd < ghost_prevTotalDeposited) { ghost_depDecreases += 1; }",
                "ghost_prevTotalDeposited = {t}nd;",
            ],
        ),
        assertion="handler.ghost_depDecreases() == 0",
        rationale="Cumulative counters only move one way; a decrease means a "
                  "code path rewrote history (faulty accounting reset), which "
                  "breaks every downstream solvency check.",
        bug_class="accounting-desync",
        severity="MEDIUM",
    ),
    TemplateSpec(
        id="tmpl-cum-withdrawn-monotonic",
        statement="The cumulative withdrawal counter must never decrease between calls.",
        requires=[_getter_pat("totalWithdrawn")],
        ghost=GhostSpec(
            vars=[("ghost_prevTotalWithdrawn", "uint256"),
                  ("ghost_wdDecreases", "uint256")],
            setup=["ghost_prevTotalWithdrawn = target.totalWithdrawn();"],
            observe_after_all=[
                "uint256 {t}nw = target.totalWithdrawn();",
                "if ({t}nw < ghost_prevTotalWithdrawn) { ghost_wdDecreases += 1; }",
                "ghost_prevTotalWithdrawn = {t}nw;",
            ],
        ),
        assertion="handler.ghost_wdDecreases() == 0",
        rationale="Same history-rewrite tripwire as deposits, for the "
                  "withdrawal side of the ledger.",
        bug_class="accounting-desync",
        severity="MEDIUM",
    ),
    # --- access control (as observable consequences) ---------------------
    TemplateSpec(
        id="tmpl-owner-nonzero",
        statement="The contract owner must never be the zero address.",
        requires=[_getter_pat("owner")],
        assertion="target.owner() != address(0)",
        rationale="Ownership silently landing on address(0) bricks admin "
                  "functions or signals a broken access-control handoff an "
                  "attacker can race.",
        bug_class="access-control",
        severity="MEDIUM",
    ),
    TemplateSpec(
        id="tmpl-owner-immutable",
        statement="Ownership must never change hands during fuzzing "
                  "(ghost-captured at deployment).",
        requires=[_getter_pat("owner")],
        ghost=GhostSpec(
            vars=[("ghost_owner0", "address")],
            setup=["ghost_owner0 = target.owner();"],
        ),
        assertion="target.owner() == handler.ghost_owner0()",
        rationale="Temporal access-control tripwire: any reachable path that "
                  "transfers ownership — missing onlyOwner, broken two-step "
                  "handoff — breaks it. Legitimate transfers need the owner, "
                  "which the fuzzer cannot impersonate.",
        bug_class="access-control",
        severity="HIGH",
    ),
    # --- arithmetic bounds ------------------------------------------------
    TemplateSpec(
        id="tmpl-share-price-positive",
        statement="The reported share price must always be strictly positive.",
        requires=[_getter_pat("sharePrice")],
        assertion="target.sharePrice() > 0",
        rationale="A zero (or underflowing) share price breaks every "
                  "deposit/withdraw quote; attackers abuse rounding to push "
                  "it to zero and mint shares for free.",
        bug_class="rounding",
        severity="MEDIUM",
    ),
    TemplateSpec(
        id="tmpl-share-price-nonzero-min",
        statement="The share price must never touch zero at any observed point "
                  "(ghost-tracked minimum).",
        requires=[_getter_pat("sharePrice")],
        ghost=GhostSpec(
            vars=[("ghost_sp_min", "uint256")],
            setup=["ghost_sp_min = type(uint256).max;"],
            observe_after_all=[
                "uint256 {t}sp = target.sharePrice();",
                "if ({t}sp < ghost_sp_min) { ghost_sp_min = {t}sp; }",
            ],
        ),
        assertion="handler.ghost_sp_min() > 0",
        rationale="The Balancer class: empty-vault inflation attacks drive the "
                  "share price to zero so the next depositor's shares round "
                  "away. Any observed zero is a critical finding.",
        bug_class="share-price",
        severity="HIGH",
    ),
    TemplateSpec(
        id="tmpl-fee-bounded",
        statement="The fee rate must never exceed 10000 basis points (100%).",
        name_choices={"fee": ["feeBps", "feePercent", "feeRate", "protocolFee"]},
        assertion="target.{fee}() <= 10000",
        rationale="A fee above 100% silently confiscates user funds; fee "
                  "parameters are a favorite rug vector. (Assumes basis-point "
                  "denomination — the common case.)",
        bug_class="fee-accounting",
        severity="MEDIUM",
    ),
    TemplateSpec(
        id="tmpl-fee-recipient-set",
        statement="The fee recipient must never be the zero address.",
        name_choices={"feeto": ["feeTo", "feeRecipient", "treasury"]},
        assertion="target.{feeto}() != address(0)",
        rationale="Fees sent to address(0) are burned by accident — or the "
                  "recipient setter is broken and value accrues nowhere.",
        bug_class="fee-accounting",
        severity="MEDIUM",
    ),
    # --- oracle staleness -------------------------------------------------
    TemplateSpec(
        id="tmpl-oracle-fresh",
        statement="Chainlink-style price answers must be positive, answered, "
                  "and no older than 1 day.",
        requires=[r"latestRoundData\s*\("],
        body="{ uint80 {t}roundId; int256 {t}answer; uint256 {t}updatedAt; "
             "uint80 {t}answeredInRound; "
             "({t}roundId, {t}answer, , {t}updatedAt, {t}answeredInRound) = "
             "target.latestRoundData(); "
             "assert({t}answer > 0); assert({t}updatedAt != 0); "
             "assert({t}answeredInRound >= {t}roundId); "
             "assert({t}updatedAt <= block.timestamp && "
             "block.timestamp - {t}updatedAt <= 86400); }",
        rationale="Stale/zero oracle answers are the classic price-manipulation "
                  "primitive: liquidations, mint quotes, and TWAP guards all "
                  "inherit the feed's freshness.",
        bug_class="oracle-price",
        severity="CRITICAL",
        # Weakness-hunt round, target 5: this rule is only meaningful
        # within its 1-day freshness window — warping the clock past it
        # would be a false positive, so warp actions are disabled when
        # this template is active.
        temporal_scope="time-limited",
    ),
    # --- pausing correctness ----------------------------------------------
    TemplateSpec(
        id="tmpl-pause-halts-deposits",
        statement="No deposit may succeed while the contract is paused "
                  "(ghost-tracked pause state, observed — not assumed).",
        requires=[_getter_pat("paused"), _fn_pat("pause"), _fn_pat("unpause"),
                  r"function\s+deposit\s*\(\s*uint\d*\s+\w+"],
        ghost=GhostSpec(
            vars=[("ghost_paused", "bool"),
                  ("ghost_pausedDepositSuccess", "uint256")],
            setup=["ghost_paused = target.paused();"],
            tracked=[
                TrackedCall(function="pause",
                            update="ghost_paused = target.paused();"),
                TrackedCall(function="unpause",
                            update="ghost_paused = target.paused();"),
                TrackedCall(
                    function="deposit",
                    custom_body="if (ghost_paused) { "
                                "try {call} { ghost_pausedDepositSuccess += 1; } catch {} "
                                "} else { "
                                "try {call} {} catch {} "
                                "}",
                ),
            ],
        ),
        assertion="handler.ghost_pausedDepositSuccess() == 0",
        rationale="The pause-correctness property: pause() that doesn't "
                  "actually gate deposits is a broken emergency brake. Ghost "
                  "pause state is re-read from the contract after every "
                  "pause()/unpause(), so a no-op pause() can't fool it.",
        bug_class="access-control",
        severity="HIGH",
    ),
    # --- allowance handling -------------------------------------------------
    TemplateSpec(
        id="tmpl-allowance-lte-approved",
        statement="Every spender's live allowance must never exceed the last "
                  "approved amount (ghost-tracked per spender).",
        requires=[r"function\s+allowance\s*\(\s*address",
                  r"function\s+approve\s*\(\s*address",
                  _fn_pat("transferFrom")],
        ghost=GhostSpec(
            vars=[("ghost_approvedTo", "mapping(address => uint256)"),
                  ("ghost_spenders", "address[]")],
            extra_fns=["function ghost_spenderCount() public view returns (uint256) "
                       "{ return ghost_spenders.length; }"],
            handler_fn_names=["ghost_spenderCount"],
            tracked=[
                TrackedCall(
                    function="approve",
                    custom_body="try {call} { "
                                "ghost_approvedTo[{p0}] = {p1}; "
                                "bool {t}seen = false; "
                                "for (uint256 {t}i = 0; {t}i < ghost_spenders.length; {t}i++) "
                                "{ if (ghost_spenders[{t}i] == {p0}) { {t}seen = true; break; } } "
                                "if (!{t}seen) { ghost_spenders.push({p0}); } "
                                "} catch {}",
                ),
            ],
        ),
        body="{ uint256 {t}n = handler.ghost_spenderCount(); "
             "for (uint256 {t}i = 0; {t}i < {t}n; {t}i++) { "
             "address {t}s = handler.ghost_spenders({t}i); "
             "assert(handler.ghost_approvedTo({t}s) >= "
             "target.allowance(address(handler), {t}s)); } }",
        rationale="Catches allowance inflation bugs (approve that adds instead "
                  "of sets, phantom approvals): any path that grants spending "
                  "power beyond the last approve() breaks it.",
        bug_class="allowance",
        severity="HIGH",
    ),
]

#: Ids of templates that need the ghost-state harness.
GHOST_TEMPLATE_IDS: frozenset[str] = frozenset(
    s.id for s in SOLIDITY_TEMPLATES if s.ghost is not None
)

#: Ids of templates whose invariant is a multi-statement body rather than a
#: single assertion expression (their ``assertion`` is intentionally empty).
BODY_TEMPLATE_IDS: frozenset[str] = frozenset(
    s.id for s in SOLIDITY_TEMPLATES if s.body
)

_GHOST_SPECS: dict[str, GhostSpec] = {
    s.id: s.ghost for s in SOLIDITY_TEMPLATES if s.ghost is not None
}

_TEMPLATE_BY_ID: dict[str, TemplateSpec] = {s.id: s for s in SOLIDITY_TEMPLATES}


def _vyper_cairo_common(
    *,
    supply: str,
    assets: str,
    price: str,
    owner: str,
    fee: str,
    feeto: str,
    solvency_assert: str,
    share_price_assert: str,
    owner_assert: str,
    fee_assert: str,
    feeto_assert: str,
    solvency_requires: list[str],
    share_price_requires: list[str],
    owner_requires: list[str],
    fee_requires: list[str],
    feeto_requires: list[str],
) -> list[TemplateSpec]:
    return [
        TemplateSpec(
            id="tmpl-solvency-1-1",
            statement=f"For a 1:1 vault, {supply} must always equal {assets}.",
            requires=solvency_requires,
            requires_absent=_FEE_MARKERS,
            assertion=solvency_assert,
            rationale="Share/asset desync = unbacked mint or stranded assets.",
            bug_class="accounting-desync",
            severity="HIGH",
        ),
        TemplateSpec(
            id="tmpl-share-price-positive",
            statement=f"The reported share price ({price}) must always be positive.",
            requires=share_price_requires,
            assertion=share_price_assert,
            rationale="Zero share price breaks quotes and enables free mints.",
            bug_class="rounding",
            severity="MEDIUM",
        ),
        TemplateSpec(
            id="tmpl-owner-nonzero",
            statement=f"The contract owner ({owner}) must never be the zero address.",
            requires=owner_requires,
            assertion=owner_assert,
            rationale="Zero-address ownership bricks admin or signals a raced handoff.",
            bug_class="access-control",
            severity="MEDIUM",
        ),
        TemplateSpec(
            id="tmpl-fee-bounded",
            statement=f"The fee rate ({fee}) must never exceed 10000 basis points.",
            requires=fee_requires,
            assertion=fee_assert,
            rationale="Fees above 100% confiscate user funds.",
            bug_class="fee-accounting",
            severity="MEDIUM",
        ),
        TemplateSpec(
            id="tmpl-fee-recipient-set",
            statement=f"The fee recipient ({feeto}) must never be the zero address.",
            requires=feeto_requires,
            assertion=feeto_assert,
            rationale="Fees to address(0) are burned by accident.",
            bug_class="fee-accounting",
            severity="MEDIUM",
        ),
    ]


VYPER_TEMPLATES: list[TemplateSpec] = _vyper_cairo_common(
    supply="total_supply", assets="total_assets", price="share_price",
    owner="owner", fee="fee_bps", feeto="fee_to",
    solvency_assert="target.total_supply() == target.total_assets()",
    share_price_assert="target.share_price() > 0",
    owner_assert="target.owner() != address(0)",
    fee_assert="target.fee_bps() <= 10000",
    feeto_assert="target.fee_to() != address(0)",
    solvency_requires=[_vyper_getter_pat("total_supply"),
                       _vyper_getter_pat("total_assets")],
    share_price_requires=[_vyper_getter_pat("share_price")],
    owner_requires=[_vyper_getter_pat("owner")],
    fee_requires=[_vyper_getter_pat("fee_bps")],
    feeto_requires=[_vyper_getter_pat("fee_to")],
)

CAIRO_TEMPLATES: list[TemplateSpec] = _vyper_cairo_common(
    supply="total_supply", assets="total_assets", price="share_price",
    owner="owner", fee="fee_bps", feeto="fee_to",
    solvency_assert="target.total_supply() == target.total_assets()",
    share_price_assert="target.share_price() > 0",
    owner_assert="target.owner() != address(0)",
    fee_assert="target.fee_bps() <= 10000",
    feeto_assert="target.fee_to() != address(0)",
    solvency_requires=[_cairo_getter_pat("total_supply"),
                       _cairo_getter_pat("total_assets")],
    share_price_requires=[_cairo_getter_pat("share_price")],
    owner_requires=[_cairo_getter_pat("owner")],
    fee_requires=[_cairo_getter_pat("fee_bps")],
    feeto_requires=[_cairo_getter_pat("fee_to")],
)

TEMPLATES_BY_LANGUAGE: dict[str, list[TemplateSpec]] = {
    "solidity": SOLIDITY_TEMPLATES,
    "vyper": VYPER_TEMPLATES,
    "cairo": CAIRO_TEMPLATES,
}

#: Backward-compatible alias: the original name for the Solidity registry.
GENERIC_TEMPLATES: list[TemplateSpec] = SOLIDITY_TEMPLATES


def template_invariants(
    source: str, language: str = "solidity",
) -> list[Invariant]:
    """Return every template whose applicability conditions hold in ``source``."""
    out: list[Invariant] = []
    for spec in TEMPLATES_BY_LANGUAGE.get(language, []):
        try:
            bindings = spec.match(source)
        except re.error as exc:  # a bad hand-written regex must not kill a scan
            LOGGER.warning("invariant template %s regex failed: %s", spec.id, exc)
            continue
        if bindings is not None:
            out.append(spec.to_invariant(bindings))
    return out


def all_templates() -> list[TemplateSpec]:
    """Every registered template across languages (for the registry test)."""
    seen: dict[str, TemplateSpec] = {}
    for specs in TEMPLATES_BY_LANGUAGE.values():
        for spec in specs:
            seen.setdefault(spec.id, spec)
    return list(seen.values())


def handler_reference_names() -> frozenset[str]:
    """All ``handler.<name>`` references ghost templates may legally use."""
    names = {"target"}
    for spec in _GHOST_SPECS.values():
        for var_name, _ in spec.vars:
            names.add(var_name)
        names.update(spec.handler_fn_names)
    return frozenset(names)


# ---------------------------------------------------------------------------
# Ghost-state harness rendering
#
# Pure string building — unit-testable without forge. The handler wraps
# every fuzzable target function; tracked calls update ghost state inside
# try/catch so a reverted target call can never desync ghost accounting.
# ---------------------------------------------------------------------------

_DANGEROUS_PASSTHROUGH = {
    "target",
    "handler",
    "targetContracts",
    "setUp",
    # weakness-hunt round, target 1: handler-owned members the fuzzer must
    # not shadow with a passthrough.
    "act_phish",
    "wgSenderPool",
    "wgNeutralDeployer",
}


def needs_ghost_mode(invariants: list[Invariant]) -> bool:
    """True when any invariant needs the ghost-state harness."""
    return any(inv.id in GHOST_TEMPLATE_IDS for inv in invariants)


def resolve_ghost_templates(
    invariants: list[Invariant], source: str,
) -> tuple[list[Invariant], list[str]]:
    """Drop ghost templates whose tracked calls can't be resolved.

    A tracked call must resolve to a fuzzable target function with a
    compatible amount expression; otherwise the ghost accounting would be
    silently wrong — so the template is skipped with a loud note instead.
    Returns (kept invariants, notes).
    """
    from web3guard.invariants.harness import extract_target_functions as _etf

    # Target-scoped (weakness-hunt round, target 2): ghost tracking must
    # resolve against the deploy-target contract's functions, not every
    # function in a multi-contract file.
    sigs = {s.name: s for s in _etf(source) if s.fuzzable}
    kept: list[Invariant] = []
    notes: list[str] = []
    for inv in invariants:
        spec = _GHOST_SPECS.get(inv.id)
        if spec is None:
            kept.append(inv)
            continue
        problems: list[str] = []
        for tc in spec.tracked:
            sig = sigs.get(tc.function)
            if sig is None:
                problems.append(f"'{tc.function}' is not a fuzzable target function")
                continue
            if _plast_expr(tc, sig) is None and ("{plast}" in (tc.update + tc.custom_body)):
                problems.append(
                    f"'{tc.function}' has no usable amount parameter for ghost tracking"
                )
        if problems:
            msg = (
                f"ghost template '{inv.id}' SKIPPED (cannot track calls safely: "
                + "; ".join(problems) + ")"
            )
            LOGGER.warning(msg)
            notes.append(msg)
            continue
        kept.append(inv)
    return kept, notes


def _plast_expr(tc: TrackedCall, sig: Any) -> str | None:
    """Solidity expression for ``{plast}``: last uint param, or msg.value."""
    text = tc.update + tc.custom_body
    if "{plast}" not in text:
        return "p0"  # unused; never emitted
    if sig.params:
        ptype = sig.params[-1][0]
        if re.match(r"^uint\d*$", ptype):
            return f"p{len(sig.params) - 1}"
        return None
    if sig.mutability == "payable":
        return "msg.value"
    return None


_PLACEHOLDER_RE = re.compile(r"\{(p\d+|plast|args|value|call)\}")


def _format_hook(text: str, tc: TrackedCall, sig: Any, t: str) -> str | None:
    """Fill placeholders; return None when a placeholder can't resolve."""
    params = [f"p{i}" for i in range(len(sig.params))]
    args = ", ".join(params)
    call = f"target.{sig.name}({args})"
    if sig.mutability == "payable":
        call = f"target.{sig.name}{{value: msg.value}}({args})"
    out = text.replace("{t}", t).replace("{call}", call).replace("{args}", args)
    for i in range(len(params)):
        out = out.replace(f"{{p{i}}}", params[i])
    plast = _plast_expr(tc, sig)
    if "{plast}" in out:
        if plast is None:
            return None
        out = out.replace("{plast}", plast)
    if "{value}" in out:
        if sig.mutability != "payable":
            return None
        out = out.replace("{value}", "msg.value")
    if _PLACEHOLDER_RE.search(out):
        return None
    return out


def _call_expr(sig: Any) -> str:
    args = ", ".join(f"p{i}" for i in range(len(sig.params)))
    if sig.mutability == "payable":
        return f"target.{sig.name}{{value: msg.value}}({args})"
    return f"target.{sig.name}({args})"


def _passthrough(sig: Any, hooks: list[str]) -> str:
    # Every passthrough takes the target's own parameters plus a trailing
    # sender seed (weakness-hunt round, target 1): the fuzzer picks WHO
    # calls from the sender pool (handler, built-in users, mined
    # hardcoded addresses), so role-gated paths are reachable without the
    # harness itself ever being the owner (neutral deployment, below).
    params = ", ".join(
        [f"{t} p{i}" for i, (t, _) in enumerate(sig.params)] + ["uint256 _wgSender"]
    )
    payable_kw = " payable" if sig.mutability == "payable" else ""
    call = _call_expr(sig)
    if not hooks:
        body = f"{call};"
    else:
        inner = "\n            ".join(h for h in hooks if h)
        body = f"try {call} {{\n            {inner}\n        }} catch {{}}"
    return (
        f"    function {sig.name}({params}) public{payable_kw} {{\n"
        f"        _wgPrank(_wgPickSender(_wgSender));\n"
        f"        {body}\n"
        f"    }}"
    )


def _render_hooks_for(
    spec: TemplateSpec, sig: Any, notes: list[str],
) -> list[str] | None:
    """Render all hook statements for one (template, function) pair.

    Returns None when a tracked call on this function can't be rendered
    (the caller drops the template with a loud note).
    """
    assert spec.ghost is not None
    t = _sanitize(spec.id)
    pieces: list[str] = []
    tracked_here = [tc for tc in spec.ghost.tracked if tc.function == sig.name]
    for tc in tracked_here:
        if tc.custom_body:
            formatted = _format_hook(tc.custom_body, tc, sig, t)
            if formatted is None:
                return None
            pieces.append(formatted)
        elif tc.update:
            formatted = _format_hook(tc.update, tc, sig, t)
            if formatted is None:
                return None
            pieces.append(formatted)
    for obs in spec.ghost.observe_after_all:
        fobs = _format_hook(obs, TrackedCall(function=sig.name), sig, t)
        if fobs is not None:
            pieces.append(fobs)
    return pieces


def render_ghost_project(
    contract_source: str,
    contract_name: str,
    invariants: list[Invariant],
    bounds: FuzzBounds,
    *,
    attack: bool | None = None,
) -> tuple[dict[str, str], list[str]]:
    """Render a Foundry project with the ghost-state handler harness.

    Returns (files, notes). Raises ValueError when no usable ghost template
    survived resolution (caller falls back to an honest skip).

    ``attack`` (weakness-hunt round, target 4): when True (default follows
    ``bounds.attack_enabled``, ON by default), the ghost handler ALSO
    deploys the Phase-1 attacker contracts and exposes the attack actions
    — but routed through the handler's own passthroughs, so ghost
    accounting stays in lockstep. This closes the integration gap where
    ghost (temporal) templates disabled the attack simulator and the
    reentrancy family stayed uncaught through the main pipeline.
    """
    from web3guard.invariants.harness import (
        NEUTRAL_DEPLOYER,
        _render_entry_dispatcher,
        extract_mined_senders,
        sender_pool,
    )
    from web3guard.invariants.harness import (
        extract_contract_names as _ecn,
    )
    from web3guard.invariants.harness import (
        extract_target_functions as _etf,
    )

    notes: list[str] = []
    specs = [
        (_TEMPLATE_BY_ID[inv.id], inv)
        for inv in invariants
        if inv.id in _GHOST_SPECS
    ]
    if not specs:
        raise ValueError("no ghost templates to render")

    # Weakness-hunt round, target 2: only the deploy-target contract's own
    # functions are wrapped. Auxiliary contracts in the same file still
    # compile as dependencies; their functions are never called against
    # the target (that used to be a compile failure + silent no-verdict).
    _all_names = _ecn(contract_source)
    sigs = [s for s in _etf(contract_source) if s.fuzzable]
    if len(_all_names) > 1:
        notes.append(
            f"ghost harness: multi-contract file ({', '.join(_all_names)}); "
            f"fuzzing '{contract_name}' only"
        )
    # Sender pool (weakness-hunt round, target 1): handler itself first,
    # then built-ins, configured senders, and mined hardcoded addresses.
    pool_addrs = ["address(this)"] + sender_pool(contract_source, bounds)
    mined = extract_mined_senders(contract_source)
    if mined:
        notes.append(
            "ghost harness sender impersonation: mined from source: "
            + ", ".join(mined)
        )
    # Weakness-hunt round, target 4: run the attacker contracts INSIDE
    # ghost mode. `use_attack` follows bounds.attack_enabled by default.
    use_attack = bounds.attack_enabled if attack is None else bool(attack)
    atk_specs: list = []
    atk_vault = None
    atk_eth_vault = False
    atk_approve_fn = None
    if use_attack:
        from web3guard.invariants import attackers as _attackers

        pragma = extract_pragma(contract_source)
        atk_specs, atk_notes = _attackers.select_attackers(pragma, sigs)
        notes.extend(f"ghost harness: {n}" for n in atk_notes)
        atk_vault = _attackers.detect_vault_interface(sigs)
        by_name = {fn.name: fn for fn in sigs}
        dep_fn = by_name.get(atk_vault.deposit_fn) if atk_vault else None
        atk_eth_vault = bool(
            atk_vault is not None
            and dep_fn is not None
            and dep_fn.mutability == "payable"
            and not dep_fn.params
        )
        atk_approve_fn = next(
            (
                fn
                for fn in sigs
                if fn.name.lower() == "approve"
                and len(fn.params) == 2
                and fn.params[0][0] == "address"
                and fn.params[1][0].startswith("uint")
            ),
            None,
        )
        notes.append(
            "ghost harness: attacker contracts deployed inside ghost mode "
            f"({', '.join(s.name for s in atk_specs)}); attack actions route "
            "through the ghost passthroughs so accounting stays in lockstep."
        )
    # Weakness-hunt round, target 5: if any invariant is time-limited
    # (e.g. oracle freshness), time-warp actions are disabled — warping
    # the clock past the window would be a false positive, not a bug.
    warp_disabled = any(
        inv.temporal_scope == "time-limited"
        or infer_temporal_scope(inv) == "time-limited"
        for inv in invariants
    )
    if warp_disabled:
        notes.append(
            "ghost harness: time-warp actions DISABLED — a time-limited "
            "invariant is active; warping the clock would manufacture a "
            "false positive."
        )
    seen_names: set[str] = set()
    passthroughs: list[str] = []
    dropped_specs: set[str] = set()
    for sig in sigs:
        if sig.name in seen_names or sig.name in _DANGEROUS_PASSTHROUGH:
            if sig.name not in seen_names:
                notes.append(
                    f"ghost harness: no passthrough for '{sig.name}' "
                    "(name reserved by the harness)"
                )
            continue
        if sig.name.startswith("ghost_"):
            continue
        if sig.name.startswith("_wg"):
            notes.append(
                f"ghost harness: no passthrough for '{sig.name}' "
                "(name reserved by the harness)"
            )
            continue
        seen_names.add(sig.name)
        hooks: list[str] = []
        for spec, _inv in specs:
            rendered = _render_hooks_for(spec, sig, notes)
            if rendered is None:
                msg = (
                    f"ghost harness: hook for '{sig.name}' from '{spec.id}' "
                    "could not be rendered; template skipped"
                )
                LOGGER.warning(msg)
                notes.append(msg)
                dropped_specs.add(spec.id)
                continue
            hooks.extend(rendered)
        passthroughs.append(_passthrough(sig, hooks))

    specs = [(spec, inv) for spec, inv in specs if spec.id not in dropped_specs]
    if not specs:
        raise ValueError("no ghost templates survived hook rendering")

    # Merge ghost declarations / setup / extra fns (dedupe by name).
    var_decls: dict[str, str] = {}
    setup_all: list[str] = []
    extra_fns: list[str] = []
    for spec, _inv in specs:
        assert spec.ghost is not None
        for vname, vtype in spec.ghost.vars:
            if vname in var_decls:
                if var_decls[vname] != vtype:
                    raise ValueError(
                        f"ghost variable name clash: {vname} declared as both "
                        f"{var_decls[vname]} and {vtype}"
                    )
                continue
            var_decls[vname] = vtype
        for stmt in spec.ghost.setup:
            if stmt not in setup_all:
                setup_all.append(stmt)
        for fn in spec.ghost.extra_fns:
            if fn not in extra_fns:
                extra_fns.append(fn)

    handler_parts = [
        "// SPDX-License-Identifier: MIT",
        extract_pragma(contract_source),
        "",
        "// Web3Guard ghost-state invariant harness (Phase 3).",
        "// The handler wraps every fuzzable target function; ghost variables",
        "// are updated inside try/catch so reverted calls can never desync",
        "// accounting. The fuzzer is restricted to this handler via",
        "// targetContracts() below, so no call bypasses ghost tracking.",
        "//",
        "// Weakness-hunt round, target 1: the target is deployed as a fixed",
        "// NEUTRAL address (never the handler), so the harness can never act",
        "// as the contract's owner — owner-confusion false positives are",
        "// gone. Each passthrough takes a sender seed: the fuzzer picks WHO",
        "// calls from the sender pool (handler, built-in users, hardcoded",
        "// addresses mined from the source), so role-gated paths stay",
        "// reachable. act_phish models tx.origin phishing (msg.sender != owner,",
        "// tx.origin == owner).",
        f'import "../src/{contract_name}.sol";',
        "",
        "interface WgVm {",
        "    function deal(address account, uint256 newBalance) external;",
        "    function prank(address msgSender) external;",
        "    function prank(address msgSender, address txOrigin) external;",
        "    function warp(uint256 newTimestamp) external;",
        "}",
        "WgVm constant WGVM = WgVm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);",
        f"address constant WG_NEUTRAL_DEPLOYER = address({NEUTRAL_DEPLOYER});",
        "",
        "contract GhostHandler {",
        f"    {contract_name} public target;",
        "    // The neutral deployer doubles as the tx.origin-phishing owner.",
        "    address public wgNeutralDeployer;",
        "    // Sender pool: every address the harness may act as.",
        "    address[] public wgSenderPool;",
        "    // tx.origin override for the phishing action (0 = none).",
        "    address internal _wgTxOrigin;",
        "",
    ]
    if use_attack:
        # Attacker-contract imports (target 4): deployed below, driven
        # through the ghost passthroughs.
        handler_parts.insert(
            handler_parts.index(f'import "../src/{contract_name}.sol";') + 1,
            'import "./attackers/DonationAttacker.sol";\n'
            'import "./attackers/ReentrancyAttacker.sol";\n'
            'import "./attackers/ApprovalDrainer.sol";',
        )
        handler_parts.extend([
            "    // --- attacker contracts (weakness-hunt round, target 4) ---",
            "    DonationAttacker public donationAttacker;",
            "    ReentrancyAttacker public reenterAttacker;",
            "    ApprovalDrainer public approvalDrainer;",
            "    // Ghost accounting for attacker funding (see the",
            "    // invariant_attacker_no_profit invariant in the test).",
            "    uint256 public totalAttackerFunding;",
            "    // Sender-pool slots for the attacker contracts (appended",
            "    // after users/mined senders; indices fixed at render time).",
            f"    uint256 constant WG_SENDER_DONATION = {len(pool_addrs)};",
            f"    uint256 constant WG_SENDER_REENTER = {len(pool_addrs) + 1};",
            f"    uint256 constant WG_SENDER_DRAINER = {len(pool_addrs) + 2};",
            "    uint256 constant WG_MAX_CALL_VALUE = "
            f"{bounds.attack_max_value_wei};",
            "    // On-chain epsilon-greedy bandit state (adaptive strategy).",
            "    uint256[4] public wgModeScore;",
            "    uint256 public wgModePulls;",
            "",
        ])
        pool_addrs.extend([
            "address(donationAttacker)",
            "address(reenterAttacker)",
            "address(approvalDrainer)",
        ])
    for vname, vtype in var_decls.items():
        handler_parts.append(f"    {vtype} public {vname};")
    if var_decls:
        handler_parts.append("")
    handler_parts.append("    constructor() {")
    handler_parts.append("        WGVM.prank(WG_NEUTRAL_DEPLOYER);")
    handler_parts.append(f"        target = new {contract_name}();")
    handler_parts.append("        wgNeutralDeployer = WG_NEUTRAL_DEPLOYER;")
    if use_attack:
        handler_parts.append("        donationAttacker = new DonationAttacker();")
        if any(s.name == "ReentrancyAttacker" for s in atk_specs):
            handler_parts.append("        reenterAttacker = new ReentrancyAttacker();")
        if any(s.name == "ApprovalDrainer" for s in atk_specs):
            handler_parts.append("        approvalDrainer = new ApprovalDrainer();")
    for a in pool_addrs:
        handler_parts.append(f"        wgSenderPool.push({a});")
    handler_parts.append("        for (uint256 _wgi = 0; _wgi < wgSenderPool.length; _wgi++) {")
    handler_parts.append("            WGVM.deal(wgSenderPool[_wgi], 10000 ether);")
    handler_parts.append("        }")
    if use_attack:
        # The attacker contracts sit in the sender pool (so the harness can
        # prank as them) but must NOT start with 10000 ETH — that would
        # break invariant_attacker_no_profit by construction. They start at
        # zero; _wgFundAttacker is the only funding source the invariant
        # counts. (deal on address(0) for an undeployed attacker is a no-op.)
        handler_parts.append("        WGVM.deal(address(donationAttacker), 0);")
        handler_parts.append("        WGVM.deal(address(reenterAttacker), 0);")
        handler_parts.append("        WGVM.deal(address(approvalDrainer), 0);")
    for stmt in setup_all:
        handler_parts.append(f"        {stmt}")
    handler_parts.append("    }")
    handler_parts.append("")
    handler_parts.append("    receive() external payable {}")
    handler_parts.append("")
    handler_parts.extend([
        "    function _wgPickSender(uint256 i) internal view returns (address) {",
        "        return wgSenderPool[i % wgSenderPool.length];",
        "    }",
        "",
        "    // Prank as u, preserving a phishing tx.origin override when set.",
        "    function _wgPrank(address u) internal {",
        "        if (_wgTxOrigin == address(0)) { WGVM.prank(u); }",
        "        else { WGVM.prank(u, _wgTxOrigin); }",
        "    }",
        "",
        "    // Phishing model for tx.origin bugs: the neutral owner is tricked",
        "    // into triggering a contract call; the target sees msg.sender = a",
        "    // pool sender with tx.origin = owner. Routed through the handler's",
        "    // own passthroughs so ghost accounting stays in lockstep.",
        "    function act_phish(uint256 _wgFn, uint256 _wgA, uint256 _wgB, uint256 _wgSender) public {",
        "        _wgTxOrigin = WG_NEUTRAL_DEPLOYER;",
        "        _wgCallEntry(_wgFn, address(0), _wgA, _wgB, _wgSender);",
        "        _wgTxOrigin = address(0);",
        "    }",
        "",
        _render_entry_dispatcher(contract_name, sigs, via_passthrough=True),
    ])
    # Weakness-hunt round, target 4: the attack actions, routed through the
    # ghost passthroughs (this.deposit(...)/this.withdraw(...)) so every
    # attacker-driven call is ghost-tracked exactly like a fuzzer call.
    if use_attack:
        _atk_lines: list[str] = [
            "    // --- attack actions (weakness-hunt round, target 4) ---",
            "    // Routed through the ghost passthroughs above, so attacker-",
            "    // driven calls are ghost-tracked exactly like fuzzer calls.",
            "    function _wgCap(uint256 v) internal view returns (uint256) {",
            "        return v > WG_MAX_CALL_VALUE ? WG_MAX_CALL_VALUE : v;",
            "    }",
            "",
            "    function _wgFundAttacker(address a, uint256 v) internal {",
            "        if (v == 0 || a == address(0)) return;",
            "        WGVM.deal(a, a.balance + v);",
            "        totalAttackerFunding += v;",
            "    }",
            "",
            "    function _wgAttackerFunds() internal view returns (uint256) {",
            "        return address(donationAttacker).balance",
            "            + address(reenterAttacker).balance",
            "            + address(approvalDrainer).balance;",
            "    }",
            "",
        ]
        if atk_eth_vault and atk_vault is not None:
            _dep, _wd = atk_vault.deposit_fn, atk_vault.withdraw_fn
            _atk_lines.extend([
                "    // Scripted reentrancy: the attacker is armed with the",
                "    // *passthrough* signature, so the reentrant call is ghost-",
                "    // tracked exactly like a fuzzer call.",
                "    function _wgDoReenter(uint256 v, uint256 userSeed) internal {",
                "        if (address(reenterAttacker) == address(0) || v == 0) return;",
                f"        this.{_dep}{{value: v}}(userSeed);",
                "        _wgFundAttacker(address(reenterAttacker), v);",
                "        reenterAttacker.arm(",
                "            address(this),",
                f'            abi.encodeWithSignature("{_wd}(uint256,uint256)", v, WG_SENDER_REENTER),',
                "            3",
                "        );",
                f"        this.{_dep}{{value: v}}(WG_SENDER_REENTER);",
                f"        this.{_wd}(v, WG_SENDER_REENTER);",
                "        reenterAttacker.disarm();",
                "    }",
                "",
                "    function act_attack_reenter(uint256 _wgValue, uint256 _wgSeed) public {",
                "        _wgDoReenter(_wgCap(_wgValue), _wgSeed);",
                "    }",
                "",
                "    // Multi-step heist: deposit, warp time, reenter, donate dust.",
                "    function _wgDoHeist(uint256 v, uint256 warpDays, uint256 userSeed) internal {",
                "        if (v == 0) return;",
                f"        this.{_dep}{{value: v}}(userSeed);",
            ])
            if not warp_disabled:
                _atk_lines.append(
                    "        WGVM.warp(block.timestamp + ((warpDays % 30) * 1 days));"
                )
            _atk_lines.extend([
                "        _wgDoReenter(v, userSeed + 1);",
                "        uint256 dust = v / 100;",
                "        if (dust > 0 && address(donationAttacker).balance == 0) {",
                "            _wgFundAttacker(address(donationAttacker), dust);",
                "            donationAttacker.donate(payable(address(target)));",
                "        }",
                "    }",
                "",
                "    function act_heist(uint256 _wgValue, uint256 _wgA, uint256 _wgSeed) public {",
                "        _wgDoHeist(_wgCap(_wgValue), _wgA, _wgSeed);",
                "    }",
                "",
                "    // Deposit + withdraw cycle through the passthroughs.",
                "    function act_vaultCycle(uint256 _wgValue, uint256 _wgW, uint256 _wgUser) public {",
                "        uint256 v = _wgCap(_wgValue);",
                f"        this.{_dep}{{value: v}}(_wgUser);",
                f"        this.{_wd}(v > _wgW ? _wgW : v, _wgUser);",
                "    }",
                "",
            ])
        # Forced-ETH donation (needs no vault shape).
        _atk_lines.extend([
            "    // Forced-ETH donation: selfdestruct-style value injection",
            "    // that bypasses the target's own accounting (deliberately",
            "    // NOT ghost-tracked — that is the point).",
            "    function act_donateForcedEth(uint256 _wgValue, uint256 _wgSeed) public {",
            "        uint256 v = _wgCap(_wgValue);",
            "        if (v == 0) return;",
            "        _wgFundAttacker(address(donationAttacker), v);",
            "        donationAttacker.donate(payable(address(target)));",
            "        _wgSeed; // (seed kept for fuzzer arity)",
            "    }",
            "",
        ])
        if not warp_disabled:
            _atk_lines.extend([
                "    // Time-warp: advances the clock so deadline/vesting logic",
                "    // runs against future timestamps.",
                "    function act_warpTime(uint256 _wgDays) public {",
                "        WGVM.warp(block.timestamp + ((_wgDays % 3650) * 1 days));",
                "    }",
                "",
            ])
        if atk_approve_fn is not None:
            _ap = atk_approve_fn.name
            _atk_lines.extend([
                "    // Approval drain: approve max to the drainer, then drain.",
                "    function act_approvalDrain(uint256 _wgSeed) public {",
                "        if (address(approvalDrainer) == address(0)) return;",
                f"        this.{_ap}(address(approvalDrainer), type(uint256).max, _wgSeed);",
                "        approvalDrainer.drain(address(target));",
                "    }",
                "",
            ])
        # Adaptive bandit: four modes, epsilon-greedy over observed profit.
        _atk_lines.extend([
            "    // Adaptive assault: on-chain epsilon-greedy bandit over four",
            "    // attack modes, reinforced by observed attacker profit.",
            "    function act_adaptiveAssault(uint256 _wgSeed, uint256 _wgA, uint256 _wgB) public {",
            "        uint256 before = _wgAttackerFunds();",
            "        uint256 mode = 0;",
            "        wgModePulls += 1;",
            "        if (wgModePulls % 5 == 0) {",
            "            mode = (uint256(keccak256(abi.encodePacked(block.timestamp, _wgSeed))) % 4);",
            "        } else {",
            "            uint256 best = 0;",
            "            for (uint256 _wgm = 1; _wgm < 4; _wgm++) {",
            "                if (wgModeScore[_wgm] > wgModeScore[best]) { best = _wgm; }",
            "            }",
            "            mode = best;",
            "        }",
        ])
        if atk_eth_vault and atk_vault is not None:
            _dep2, _wd2 = atk_vault.deposit_fn, atk_vault.withdraw_fn
            if warp_disabled:
                # Target 5: no warp — mode 2 becomes a plain deposit.
                _atk_lines.extend([
                    f"        if (mode == 0) {{ this.{_dep2}{{value: _wgCap(_wgB)}}(_wgA); }}",
                    "        else if (mode == 1) { _wgDoReenter(_wgCap(_wgA), _wgB); }",
                    f"        else if (mode == 2) {{ this.{_dep2}{{value: _wgCap(_wgA)}}(_wgB); }}",
                    "        else { _wgDoHeist(_wgCap(_wgA), _wgB, _wgSeed); }",
                ])
            else:
                _atk_lines.extend([
                    f"        if (mode == 0) {{ this.{_dep2}{{value: _wgCap(_wgB)}}(_wgA); }}",
                    "        else if (mode == 1) { _wgDoReenter(_wgCap(_wgA), _wgB); }",
                    f"        else if (mode == 2) {{ WGVM.warp(block.timestamp + ((_wgA % 30) * 1 days)); this.{_dep2}{{value: _wgCap(_wgA)}}(_wgB); }}",
                    "        else { _wgDoHeist(_wgCap(_wgA), _wgB, _wgSeed); }",
                ])
        else:
            if warp_disabled:
                _atk_lines.extend([
                    "        if (mode == 0 || mode == 1) { act_donateForcedEth(_wgA, _wgB); }",
                    "        else { _wgCallEntry(_wgSeed, address(0), _wgA, _wgB, _wgSeed); }",
                ])
            else:
                _atk_lines.extend([
                    "        if (mode == 0 || mode == 1) { act_donateForcedEth(_wgA, _wgB); }",
                    "        else if (mode == 2) { act_warpTime(_wgA); }",
                    "        else { _wgCallEntry(_wgSeed, address(0), _wgA, _wgB, _wgSeed); }",
                ])
        _atk_lines.extend([
            "        uint256 afterProfit = _wgAttackerFunds();",
            "        if (afterProfit > before) { wgModeScore[mode] += (afterProfit - before); }",
            "    }",
            "",
        ])
        handler_parts.extend(_atk_lines)
    handler_parts.append("")
    for fn in extra_fns:
        handler_parts.append(f"    {fn}")
        handler_parts.append("")
    for pt in passthroughs:
        handler_parts.append(pt)
        handler_parts.append("")
    handler_parts.append("}")
    handler_src = "\n".join(handler_parts) + "\n"

    test_parts = [
        "// Web3Guard ghost-state invariant test (Phase 3).",
        "",
        "contract InvariantTest {",
        "    GhostHandler public handler;",
        f"    {contract_name} public target;",
        "",
        "    function setUp() public {",
        "        handler = new GhostHandler();",
        "        target = handler.target();",
        "    }",
        "",
        "    // Foundry invariant protocol hook (forge-std-free): fuzz ONLY",
        "    // the handler, so every call flows through ghost accounting.",
        "    function targetContracts() public view returns (address[] memory) {",
        "        address[] memory _targets = new address[](1);",
        "        _targets[0] = address(handler);",
        "        return _targets;",
        "    }",
        "",
    ]
    test_parts.append("    // --- invariants under test ---")
    for _spec, inv in specs:
        test_parts.append(_render_ghost_invariant(inv, _spec, contract_source))
        test_parts.append("")
    # Non-ghost invariants also run in the ghost campaign (over `target`).
    plain = [inv for inv in invariants if inv.id not in _GHOST_SPECS]
    for inv in plain:
        test_parts.append(_render_plain_invariant(inv))
        test_parts.append("")
    if use_attack:
        # Attacker-no-profit invariant (target 4): the attacker contracts
        # must never end up holding more than they were funded with.
        test_parts.append(
            "    // --- attacker no-profit invariant (target 4) ---\n"
            "    function invariant_attacker_no_profit() public view {\n"
            "        uint256 held = address(handler.donationAttacker()).balance\n"
            "            + address(handler.reenterAttacker()).balance\n"
            "            + address(handler.approvalDrainer()).balance;\n"
            "        assert(held <= handler.totalAttackerFunding());\n"
            "    }\n"
        )
    test_parts.append("}")
    # Single-file project: the handler contract (with its own header) goes
    # first, then the test contract body above.
    test_src = handler_src + "\n" + "\n".join(test_parts) + "\n"

    foundry_toml = f"""\
# Web3Guard-generated foundry.toml (Phase 3 ghost-state harness).
# Generated by our renderer -- never by the LLM -- so it is trusted input.
# Hardened: no ffi, no filesystem access for the fuzzed code.
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
test = "test"
auto_detect_solc = true
ffi = false
fs_permissions = []

[invariant]
runs = {bounds.runs}
depth = {bounds.effective_depth if use_attack else bounds.depth}
fail_on_revert = {"true" if bounds.fail_on_revert else "false"}
"""

    files: dict[str, str] = {
        "foundry.toml": foundry_toml,
        f"src/{contract_name}.sol": contract_source,
        "test/Invariant.t.sol": test_src,
    }
    if use_attack:
        from web3guard.invariants import attackers as _attackers

        pragma = extract_pragma(contract_source)
        files["test/attackers/DonationAttacker.sol"] = (
            _attackers.donation_attacker_source(pragma)
        )
        files["test/attackers/ReentrancyAttacker.sol"] = (
            _attackers.reentrancy_attacker_source(pragma)
        )
        files["test/attackers/ApprovalDrainer.sol"] = (
            _attackers.approval_drainer_source(pragma)
        )
    return (files, notes)


def _render_ghost_invariant(
    inv: Invariant, spec: TemplateSpec, source: str,
) -> str:
    fn = _sanitize("invariant_" + inv.id)
    stmt = inv.statement.replace("*/", "* /").replace("\n", " ")
    bindings = spec.match(source) or {}
    bindings = {"t": _sanitize(spec.id), **bindings}
    header = f"    // {inv.id} [{inv.bug_class}, {inv.source}]: {stmt}"
    if spec.body:
        body = _sub(spec.body, bindings)
        return f"{header}\n    function {fn}() public view {{\n        {body}\n    }}"
    assertion = _sub(inv.assertion, bindings)
    return (
        f"{header}\n"
        f"    function {fn}() public view {{\n"
        f"        assert({assertion});\n"
        f"    }}"
    )


def _render_plain_invariant(inv: Invariant) -> str:
    fn = _sanitize("invariant_" + inv.id)
    stmt = inv.statement.replace("*/", "* /").replace("\n", " ")
    assertion = " ".join(inv.assertion.split())
    return (
        f"    // {inv.id} [{inv.bug_class}, {inv.source}]: {stmt}\n"
        f"    function {fn}() public view {{\n"
        f"        assert({assertion});\n"
        f"    }}"
    )

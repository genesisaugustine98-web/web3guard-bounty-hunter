"""Built-in static analyzer — deterministic, offline, multi-language.

The AI pass is the scanner's most powerful signal, but it requires a
configured LLM provider. The original architecture left an entire
failure mode open: with no API key the scanner could only report
secret-scan hits and whatever external tools (slither, aderyn, ...)
happened to be installed — usually nothing.

This module fills that gap with a *built-in* heuristic analyzer that
always runs. It is registered as a :class:`DiscoveryEngineBase` whose
``binary`` is ``""`` (i.e. always "installed"), so it contributes
findings on every scan regardless of toolchain or LLM availability.

The detectors are deliberately conservative: each one targets a well-
known class (reentrancy, access control, oracle, arithmetic, ...) and
requires both a trigger pattern and a confirming context before it
emits a finding, so precision stays high on real codebases. Output is
normalized into :class:`DiscoveryResult` objects consumed by the
scanner core exactly like any other engine's output.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from web3guard.discovery.base import DiscoveryEngineBase, DiscoveryResult
from web3guard.languages.base import TargetLanguage

# ---------------------------------------------------------------------------
# Issue shape
# ---------------------------------------------------------------------------


@dataclass
class StaticIssue:
    """A single heuristic finding from the static analyzer."""
    file: str
    line: int
    function: str = ""
    category: str = ""
    severity: str = "MEDIUM"
    title: str = ""
    description: str = ""
    swc_id: str = ""
    confidence: float = 0.6
    extra: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Structural helpers
# ---------------------------------------------------------------------------


def _brace_body(text: str, open_idx: int) -> int:
    """Return the index just past the matching close brace of text[open_idx]."""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


_FN_DEFS = {
    "solidity": re.compile(
        r"\b(?:function\s+([A-Za-z0-9_]+)|(fallback|receive))\s*\([^)]*\)"),
    "rust": re.compile(r"\bfn\s+([A-Za-z0-9_]+)\s*[^{;]*"),
    "move": re.compile(r"\b(?:entry\s+)?fun\s+([A-Za-z0-9_]+)\s*[^{;]*"),
    "cairo": re.compile(r"\bfn\s+([A-Za-z0-9_]+)\s*[^{;]*"),
    "go": re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z0-9_]+)\s*[^{;]*"),
    "huff": re.compile(r"#define\s+macro\s+([A-Za-z0-9_]+)"),
    "scilla": re.compile(r"\btransition\s+([A-Za-z0-9_]+)\s*\("),
}


def _iter_braced_functions(text: str, lang: str) -> list[tuple[str, str, int, int, str]]:
    """Yield (name, body, start_line, body_start_offset, decl) tuples.

    ``decl`` is the signature/modifier text that precedes the body and
    is used for guard detection (e.g. ``onlyRole(...)``). Interface /
    prototype declarations (``function foo(...);``) are skipped: a body
    is only accepted when a ``{`` appears before any ``;`` in the
    declaration statement.
    """
    pattern = _FN_DEFS.get(lang)
    if pattern is None:
        return []
    out: list[tuple[str, str, int, int, str]] = []
    for m in pattern.finditer(text):
        name = m.group(1) or m.group(2) or ""
        brace = text.find("{", m.end())
        if brace == -1:
            continue
        stmt = text[m.end():brace]
        if ";" in stmt:
            continue  # prototype / interface declaration
        start_line = text[: m.start()].count("\n") + 1
        end = _brace_body(text, brace)
        # decl = the full match (name + parameter list where the regex
        # consumes it) plus the modifier/returns tail up to the brace, so
        # callers see the complete signature for guard detection.
        out.append((name, text[brace:end], start_line, brace, m.group(0) + stmt))
    return out


def _clean_code(text: str, lang: str) -> str:
    """Remove comments so heuristics match code, not prose.

    Detectors are precision-sensitive: a comment that *mentions* a
    missing ``accept()`` or ``get_execution_info().caller_addr`` must
    not satisfy (or suppress) a detector. Comment stripping keeps the
    heuristics honest.

    Block comments are replaced by spaces (newlines preserved), so
    reported line numbers stay aligned with the original file even when
    header comments are stripped.
    """
    if lang in ("solidity", "rust", "move", "cairo", "func", "ts", "go", "wat"):
        text = re.sub(r"/\*.*?\*/",
                      lambda m: re.sub(r"[^\n]", " ", m.group(0)), text,
                      flags=re.DOTALL)
        text = re.sub(r"(?m)^[ \t]*//.*$", "", text)
    elif lang in ("huff", "yul", "scilla", "michelson", "sass", "al"):
        text = re.sub(r"(?m)^[ \t]*//.*$", "", text)
        if lang in ("yul", "michelson"):
            # Yul/Michelson block comments
            text = re.sub(r"/\*.*?\*/",
                          lambda m: re.sub(r"[^\n]", " ", m.group(0)), text,
                          flags=re.DOTALL)
    elif lang == "vyper":
        text = re.sub(r"(?m)^[ \t]*#.*$", "", text)
    if lang in ("func", "clarity"):
        text = re.sub(r"(?m)^[ \t]*;;.*$", "", text)
    return text


def _iter_python_functions(text: str) -> list[tuple[str, str, int]]:
    """Approximate Python/Vyper function bodies (indentation-based)."""
    out: list[tuple[str, str, int]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"^\s*(?:@external|@public|@view|@payable|@nonpayable|@pure)?\s*def\s+([a-z_][a-z0-9_]*)\s*\(", lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        start_line = i + 1
        j = i + 1
        while j < len(lines):
            if lines[j].strip() and not lines[j][0].isspace():
                break
            j += 1
        out.append((name, "\n".join(lines[i:j]), start_line))
        i = j
    return out


# NB: `.send` and `.transfer` forward only 2300 gas, so they cannot carry a
# reentrant payload and are intentionally excluded from the reentrancy
# trigger. The `(?!From|Ownership)` lookahead avoids matching `msg.sender`
# and `.transferFrom(...)`/`.transferOwnership(...)`.
_EXT_CALL_RE = re.compile(
    r"\.(?:call|delegatecall)\b\s*\{?|"
    r"raw_call\s*\(|contract-call\?|stx-transfer\?|"
    r"coin::transfer|invoke\s*\(|invoke_signed\s*\("
)
_STATE_WRITE_RE = re.compile(
    r"(?:"
    r"[a-zA-Z_][a-zA-Z0-9_]*\s*\[[^\]]*\]"      # any indexed write: map[key] = / += / -=
    r"|totalShares|totalAssets|vault\.balance|self\.balances|self\.[a-z_]*\s*\[[^\]]*\]"
    r"|balances|shares|balanceOf|deposits|collateral|borrowed|credit|buddies|balance"
    r")\s*[^=;]*(\+|-)?="
)
_GUARD_RE = re.compile(
    r"only[A-Za-z][A-Za-z0-9_]*\b|"
    r"require\s*\([^;]{0,120}\bmsg\.sender\b|require\s*\([^;]{0,80}owner|"
    r"assert\s+msg\.sender\s*==\s*self\.(?:owner|admin)|"
    r"asserts!\s*\(is-eq\s+(?:tx-sender|contract-caller)|"
    r"has_one\s*=\s*owner|signer\s*::|Signer<|is_signer|"
    r"#[^\n]*Signer<"
)
# NB (uncontrolled-payout): an external token/ETH transfer whose amount
# argument references a caller-supplied parameter, while the same function
# touches an entitlement ledger (claimable/vested/allocations/... mapping)
# and no bound or clamp on the parameter exists. "Pay what the caller asks"
# instead of "pay what the ledger owes" is a recurring high-severity
# business-logic flaw that no other detector shape covers. Only the amount
# argument is inspected; the recipient argument is intentionally free-form.
_PAYOUT_AMOUNT_ARG_RES = (
    # ERC20-style: <token>.transfer(recipient, AMOUNT) / safeTransfer
    re.compile(
        r"\b[\w.\[\]]+\s*\.\s*(?:safeTransfer|transfer)\s*"
        r"\(\s*[\w.]+\s*,\s*([^,()]+?)\s*\)"),
    # native ETH transfer, pre-0.5 and modern: recipient.transfer(AMOUNT)
    # / .send(AMOUNT) (single-argument form, optionally behind payable();
    # the two-argument ERC20 shape cannot match this regex).
    re.compile(
        r"\b(?:payable\s*\([^)]*\)|[\w.\[\]]+)\s*\.\s*"
        r"(?:transfer|send)\s*\(\s*([^,()]+?)\s*\)"),
)
# NB: ETH value forwarded along a low-level call (x.call{value: ...} and
# the legacy x.call.value(...) form) is deliberately NOT a payout trigger:
# raw forwarding helpers (Address.sendValue, withdrawal plumbing) are
# trusted paths, and the legacy .call.value variant is still exempted via
# the low-level-call check in the detector body.
_PAYOUT_LEDGER_RE = re.compile(
    r"\b(?:claim\w*|entitle\w*|allocat\w*|allot\w*|vest\w*|reward\w*|"
    r"owed|releas\w*|airdrop\w*|merkle\w*|deposit\w*|balance\w*|"
    r"share\w*|contribution\w*)\s*\["
)
_PAYOUT_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
# Authorization only: a claim/withdraw is *validated* by
# require(ledger[msg.sender] > 0) — that is not an access guard and must
# not suppress the uncontrolled-payout check. Only owner-style modifiers
# or ownership comparisons count here.
_AUTH_GUARD_RE = re.compile(
    r"only[A-Za-z][A-Za-z0-9_]*\b|"
    r"require\s*\([^;]{0,80}\bmsg\.sender\s*==|"
    r"assert\s*\([^;]{0,80}\bmsg\.sender\s*==|"
    r"require\s*\([^;]{0,80}==\s*msg\.sender"
)


def _param_names(sig: str) -> set[str]:
    """Extract parameter *names* from a function signature.

    ``function claim(uint256 amount, address to)`` -> ``{"amount", "to"}``.
    Handles typed declarations (``uint256`` etc.), data locations
    (``memory``/``calldata``/``storage``), ``indexed``, array suffixes,
    and unnamed parameters (which contribute nothing).
    """
    inner = sig.split("(", 1)[-1].rsplit(")", 1)[0]
    type_words = {
        "uint", "uint256", "uint128", "uint64", "uint32", "uint8",
        "int", "int256", "int128", "int64", "int32", "int8",
        "address", "bool", "bytes", "bytes32", "bytes20", "string",
        "mapping", "memory", "calldata", "storage", "payable", "indexed",
    }
    names: set[str] = set()
    for part in inner.split(","):
        words = part.strip().split()
        if not words:
            continue
        last = re.sub(r"\[[^\]]*\]$", "", words[-1])
        if re.fullmatch(r"[A-Za-z_$][\w$]*", last) and last not in type_words:
            names.add(last)
    return names


def _payout_amount_is_unbounded(body: str, idents: set[str]) -> bool:
    """True when none of ``idents`` is visibly bounded in ``body``.

    A bound is any of:
    - an ordering comparison against a non-literal operand
      (``require(ledger[msg.sender] >= amount)`` or
      ``if (amount > bal) revert``) — comparing against a *literal*
      (``require(amount > 0)``) does not bound the payout,
    - an in-function clamp assignment keeping the same name
      (``amount = ...`` / ``amount -= ...``),
    - a min()/max() clamp call anywhere in the function (conservative:
      may be unrelated to the amount, which errs toward suppression).
    """
    literal_re = re.compile(r"\d+|0[xX][0-9a-fA-F]+")
    for ident in idents:
        esc = re.escape(ident)
        if re.search(rf"\b{esc}\b\s*(?:[-+*/]|<<|>>)?=", body):
            return False
        for cm in re.finditer(
                r"([\w.\[\]]+)\s*(<=|>=|<|>)\s*([\w.\[\]]+)", body):
            left, _op, right = cm.groups()
            if ident in (left, right):
                other = right if left == ident else left
                if not literal_re.fullmatch(other):
                    return False
        if re.search(r"\bmin\s*\(|\bmax\s*\(|\bMath\.min|\bMath\.max", body):
            return False
    return True
_PRIVILEGED_FN = re.compile(
    r"^(?:set|update|change|upgrade|authorize|transfer_?owner|add_?to_?whitelist|"
    r"remove_?from_?whitelist|pause|unpause|kill|steal|rescue|sweep|withdraw_?all|"
    r"renounce|grant|revoke|mint|burn)"
)
_OWNER_VAR_RE = re.compile(r"\b(?:owner|admin|controller|guardian|governor)\b")

_SWC = {
    "reentrancy": "SWC-107",
    "access-control": "SWC-115",
    "oracle-manipulation": "SWC-120",
    "arithmetic": "SWC-101",
    "randomness": "SWC-120",
    "signature-replay": "SWC-122",
    "tx-origin": "SWC-115",
    "unprotected-init": "SWC-105",
    "proxy-upgrade": "SWC-105",
    "unchecked-external-call": "SWC-104",
    "selfdestruct": "SWC-106",
    "delegatecall": "SWC-112",
    "unlimited-approval": "SWC-114",
    "slippage": "SWC-108",
    "denial-of-service": "SWC-113",
    "front-running": "SWC-114",
}


def _issue(file: str, line: int, category: str, severity: str, title: str,
           description: str, function: str = "", swc_id: str = "",
           confidence: float = 0.6) -> StaticIssue:
    return StaticIssue(
        file=file, line=line, function=function, category=category,
        severity=severity, title=title, description=description,
        swc_id=swc_id or _SWC.get(category, ""), confidence=confidence,
    )


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


def _detect_solidity(content: str, rel: str) -> list[StaticIssue]:
    content = _clean_code(content, "solidity")
    issues: list[StaticIssue] = []
    has_owner = bool(_OWNER_VAR_RE.search(content))

    for name, body, start_line, _, sig in _iter_braced_functions(content, "solidity"):
        lines = body.splitlines()
        # 1. Reentrancy: external call before a state write.
        for i, ln in enumerate(lines):
            if _EXT_CALL_RE.search(ln):
                tail = "\n".join(lines[i + 1:i + 40])
                if _STATE_WRITE_RE.search(tail):
                    issues.append(_issue(
                        rel, start_line + i, "reentrancy", "HIGH",
                        "Reentrancy (external call before state update)",
                        f"{name}() performs an external call that is not "
                        "followed by the state update in CEI order; a "
                        "malicious receiver can re-enter before accounting "
                        "is settled.", function=name, confidence=0.8))
                break
        # 1b. Unchecked low-level call return value (SWC-104). A call
        # whose result is not captured into a `(bool ...)` tuple and not
        # wrapped in require(...) silently ignores failure. Note that
        # capturing into `(bool x,) = ...` is the *safe* form, so it must
        # not be flagged (this keeps SimpleDAO / SafeVault clean).
        for i, ln in enumerate(lines):
            if re.search(r"\.(?:call|delegatecall)\b\s*(\{|\()", ln):
                lo = max(0, i - 2)
                hi = min(len(lines), i + 2)
                window = "\n".join(lines[lo:hi])
                if not re.search(r"\(bool\s+\w+\s*,?\s*\)?\s*=|"
                                 r"bool\s+\w+\s*=\s*\w+\.call|"
                                 r"require\s*\(\s*\w+\.call|"
                                 r"assert\s*\(\s*\w+\.call", window):
                    issues.append(_issue(
                        rel, start_line + i, "unchecked-external-call",
                        "MEDIUM",
                        "Unchecked low-level call return value",
                        f"{name}() ignores the (bool, bytes) result of a "
                        "low-level .call/.delegatecall; a failed call is "
                        "silently treated as success.",
                        function=name, confidence=0.7))
                break
        # 1c. Unchecked .send -> denial of service (SWC-113). `.send`
        # forwards 2300 gas and returns false instead of reverting, so a
        # discarded result silently drops the payment and can leave the
        # contract in an inconsistent (stuck) state. Owner-guarded fee
        # collectors are trusted paths: a silently failing transfer there
        # is the owner's own loss, not an attack surface, so they are
        # skipped.
        guarded = bool(_GUARD_RE.search(sig + body))
        for i, ln in enumerate(lines):
            if re.search(r"\.send\s*\(", ln):
                if guarded:
                    break
                lo = max(0, i - 2)
                hi = min(len(lines), i + 2)
                window = "\n".join(lines[lo:hi])
                if not re.search(r"\(bool\s+\w+\s*,?\s*\)?\s*=|"
                                 r"require\s*\([^)]*\.send|"
                                 r"assert\s*\([^)]*\.send", window):
                    issues.append(_issue(
                        rel, start_line + i, "denial-of-service", "MEDIUM",
                        "Unchecked .send (silent payment failure)",
                        f"{name}() ignores the bool returned by .send(); "
                        "a failed 2300-gas transfer is silently swallowed, "
                        "which can brick payouts or corrupt accounting.",
                        function=name, confidence=0.65))
                break
        # 2. Access control.
        if _PRIVILEGED_FN.match(name) and not guarded and has_owner:
            issues.append(_issue(
                rel, start_line, "access-control", "HIGH",
                "Missing access control on privileged function",
                f"{name}() mutates role state but contains no authorization "
                "guard (onlyOwner / require(msg.sender == owner)).",
                function=name, confidence=0.85))
        # 2b. Anyone-can-become-owner: a callable function that sets the
        # ownership variable from msg.sender with no guard. Constructors,
        # initializers, and ownership-transfer claim functions (which use
        # require(msg.sender == pending) / onlyOwner) are excluded.
        if not guarded and name not in (
                "constructor", "init", "initialize", "fallback", "receive") \
                and re.search(
                    r"\b(?:owner|creator|admin|governor|controller|guardian)\b"
                    r"\s*=\s*(?:payable\s*\(\s*)?msg\.sender\b", body):
            issues.append(_issue(
                rel, start_line, "access-control", "HIGH",
                "Anyone can become owner (unprotected ownership assignment)",
                f"{name}() assigns the ownership variable from msg.sender "
                "without authorization; any caller can take over the "
                "contract.", function=name, confidence=0.85))
        # 3. Oracle manipulation: single-pool spot price.
        if re.search(r"getReserves\s*\(|latestRoundData\s*\(", body):
            issues.append(_issue(
                rel, start_line, "oracle-manipulation", "HIGH",
                "Single-source spot-price oracle (flash-loan manipulable)",
                f"{name}() reads a spot price from a single pool/oracle "
                "with no TWAP, no staleness check, and no deviation "
                "bounds.", function=name, confidence=0.8))
        # 4. ERC-4626 first-deposit / rounding.
        if re.search(r"totalShares\s*==\s*0", body):
            issues.append(_issue(
                rel, start_line, "arithmetic", "HIGH",
                "ERC-4626 first-depositor share inflation",
                f"{name}() does not use virtual shares / offset on the "
                "first deposit, so an attacker can inflate share price and "
                "steal subsequent deposits.", function=name, confidence=0.8))
        if re.search(r"\b\w+\s*\*\s*(?:totalAssets|totalShares)\s*/\s*"
                     r"(?:totalShares|totalAssets)", body):
            issues.append(_issue(
                rel, start_line, "arithmetic", "MEDIUM",
                "Round-trip arithmetic (division rounding)",
                f"{name}() multiplies then divides, rounding in the "
                "attacker's favor; check the rounding direction.",
                function=name, confidence=0.6))
        # 5. Randomness.  `blockhash` is essentially only ever used to
        # derive an on-chain outcome, so it alone is sufficient. The
        # block.timestamp / difficulty / prevrandao family is also used
        # for deadlines and time-locks, so those still need an outcome
        # conjunct (`%`, winner, rand, pick, lucky) to avoid false hits.
        if re.search(r"blockhash\s*\(", body) or (
                re.search(r"block\.timestamp|block\.difficulty|prevrandao",
                          body) and re.search(
                              r"%(?:[\w\[\]])|winner|rand|pick|lucky",
                              body)):
            issues.append(_issue(
                rel, start_line, "randomness", "HIGH",
                "Predictable randomness (blockhash / block.timestamp)",
                f"{name}() derives a random outcome from on-chain "
                "predictable state; a miner can pre-compute the result.",
                function=name, confidence=0.85))
        # 6. Signature replay (ecrecover without chainid).
        if re.search(r"ecrecover\s*\(", body) and not re.search(
                r"chainid|block\.chainid|domainSeparator|DOMAIN_SEPARATOR",
                content):
            issues.append(_issue(
                rel, start_line, "signature-replay", "MEDIUM",
                "Signature replay risk (no chainid in signed payload)",
                f"{name}() verifies signatures with ecrecover but the "
                "signed payload omits chain id (and possibly a nonce), "
                "enabling cross-chain / cross-application replay.",
                function=name, confidence=0.7))
        # 7. tx.origin auth.
        if re.search(r"\btx\.origin\b", body) and re.search(
                r"require\s*\(|if\s*\(", body):
            issues.append(_issue(
                rel, start_line, "tx-origin", "HIGH",
                "tx.origin used for authorization",
                f"{name}() authorizes with tx.origin; a victim calling a "
                "malicious contract can have the check pass on the "
                "victim's behalf.", function=name, confidence=0.8))
        # 8. Unprotected init.
        if name == "initialize" and not re.search(
                r"initializer|onlyInitializing|_initialized|require\s*\([^)]*"
                r"initialized|alreadyInitialized", body):
            issues.append(_issue(
                rel, start_line, "unprotected-init", "HIGH",
                "Unprotected initialize() (re-initializable)",
                "initialize() lacks an initializer/guard, so anyone can "
                "re-initialize or initialize before the deployer does.",
                function=name, confidence=0.85))
        # 8b. Uncontrolled payout: an external transfer whose amount comes
        # from a caller-supplied parameter while the same function reads an
        # entitlement ledger and no clamp exists on the parameter. "Pay what
        # the caller asks" instead of "pay what the ledger owes" is a
        # recurring business-logic flaw (drains airdrops, claim faucets,
        # vesting wallets) that the shape-based detectors above cannot see.
        if not _AUTH_GUARD_RE.search(sig + body) \
                and _PAYOUT_LEDGER_RE.search(sig + body):
            params = _param_names(sig)
            for amount_re in _PAYOUT_AMOUNT_ARG_RES:
                m = amount_re.search(body)
                if m is None:
                    continue
                arg = m.group(1)
                user_idents = set(_PAYOUT_IDENT_RE.findall(arg))
                user_idents -= {"msg", "sender", "value", "balance", "this"}
                user_idents &= params
                if not user_idents:
                    continue
                if not _payout_amount_is_unbounded(body, user_idents):
                    continue
                issues.append(_issue(
                    rel, start_line, "uncontrolled-payout", "HIGH",
                    "Uncontrolled payout amount (ledger bypass)",
                    f"{name}() transfers a caller-supplied amount while "
                    "reading an entitlement ledger; unless the amount is "
                    "derived from the ledger this can pay out more than "
                    "the caller is owed.",
                    function=name, confidence=0.75))
                break
        # 9. selfdestruct without guard.
        if re.search(r"selfdestruct|selfdestruct\(", body) and not guarded:
            issues.append(_issue(
                rel, start_line, "selfdestruct", "CRITICAL",
                "Unprotected selfdestruct",
                f"{name}() can selfdestruct the contract without "
                "authorization, permanently destroying funds.",
                function=name, confidence=0.8))
        # 10. delegatecall to an address variable.
        if re.search(r"\.delegatecall\s*\(|delegatecall\(", body) and not guarded:
            issues.append(_issue(
                rel, start_line, "delegatecall", "HIGH",
                "delegatecall to a variable address",
                f"{name}() delegatecalls into a runtime address; if that "
                "address is attacker-controllable the whole storage layout "
                "is compromised.", function=name, confidence=0.7))

    # Unprotected proxy upgrade: upgradeTo + fallback delegatecall combo.
    upgrade_unprotected = False
    has_delegatecall_fallback = False
    for name, body, _sl, _e, sig in _iter_braced_functions(content, "solidity"):
        if re.match(r"^(upgradeTo|upgrade|authorizeUpgrade)", name) and \
                not _GUARD_RE.search(sig + body):
            upgrade_unprotected = True
        if name == "fallback" and re.search(r"delegatecall\s*\(", body):
            has_delegatecall_fallback = True
    if upgrade_unprotected and has_delegatecall_fallback:
        issues.append(_issue(
            rel, 1, "proxy-upgrade", "CRITICAL",
            "Unprotected proxy upgrade (anyone can hijack storage)",
            "upgradeTo() has no access control and the fallback "
            "delegatecalls the stored implementation, so any attacker can "
            "point the proxy at a malicious implementation.",
            confidence=0.85))

    # approve/transferFrom race (transaction-order dependence, SWC-114):
    # approve() overwrites an allowance in the old token convention, so a
    # spender can front-run a newer approve with a transferFrom of the
    # previous allowance.
    has_transfer_from = bool(re.search(r"transferFrom\s*\(", content))
    for name, body, start_line, _, _ in _iter_braced_functions(content, "solidity"):
        if name == "approve" and has_transfer_from and re.search(
                r"(?:_allowed|allowed|allowance)\s*\[[^\]]*\]\s*\[[^\]]*\]\s*=",
                body):
            # EIP-20 recommends guarding approve against a non-zero
            # previous allowance (e.g. `assert(!((_value != 0) &&
            # (allowed[msg.sender][_spender] != 0)))`); such a guard closes
            # the race, so the function is no longer front-runnable
            # (SmartBillions).
            if re.search(
                    r"assert\s*\([^;]*![^;]*(?:allowed|allowance)\s*\[",
                    body) or re.search(
                        r"(?:allowed|allowance)\s*\[[^\]]*\]\s*\[[^\]]*\]"
                        r"\s*==\s*0", body):
                continue
            issues.append(_issue(
                rel, start_line, "front-running", "MEDIUM",
                "approve()/transferFrom() race (front-runnable)",
                "approve() overwrites the allowance directly; a spender can "
                "front-run a new approval and spend both the old and the "
                "new allowance (use increaseAllowance/decreaseAllowance).",
                function=name, confidence=0.7))
    return issues


def _detect_vyper(content: str, rel: str) -> list[StaticIssue]:
    content = _clean_code(content, "vyper")
    issues: list[StaticIssue] = []
    for name, body, start_line in _iter_python_functions(content):
        lines = body.splitlines()
        for i, ln in enumerate(lines):
            if re.search(r"raw_call\s*\(", ln):
                tail = "\n".join(lines[i + 1:i + 30])
                if re.search(r"self\.\w+\s*\[[^\]]*\]\s*(\+|-)?=", tail):
                    issues.append(_issue(
                        rel, start_line + i, "reentrancy", "HIGH",
                        "Reentrancy via raw_call before state update",
                        f"{name}() raw_calls before updating balances; "
                        "a re-entrant call can double-withdraw.",
                        function=name, confidence=0.8))
                break
        if _PRIVILEGED_FN.match(name) and not re.search(
                r"assert\s+msg\.sender\s*==\s*self\.(owner|admin)", body) \
                and _OWNER_VAR_RE.search(content):
            issues.append(_issue(
                rel, start_line, "access-control", "HIGH",
                "Missing access control on privileged function",
                f"{name}() changes role state without checking "
                "msg.sender.", function=name, confidence=0.85))
        if re.search(r"\.transfer\s*\(|\.approve\s*\(", body) and not re.search(
                r"assert\s+\w+|asserts?\s*\(", body):
            issues.append(_issue(
                rel, start_line, "unchecked-external-call", "LOW",
                "Unchecked token transfer return value",
                f"{name}() ignores the return value of a token "
                "transfer/approve.", function=name, confidence=0.55))
    return issues


def _detect_move(content: str, rel: str) -> list[StaticIssue]:
    content = _clean_code(content, "move")
    issues: list[StaticIssue] = []
    for name, body, start_line, _, _sig in _iter_braced_functions(content, "move"):
        if re.search(r"borrow_global\s*<|borrow_global_mut\s*<", body) and \
                not re.search(r"acquires\s+\w+", body):
            issues.append(_issue(
                rel, start_line, "missing-acquires", "MEDIUM",
                "Missing acquires annotation (runtime abort)",
                f"{name}() borrows global state without an `acquires` "
                "annotation, which aborts at runtime.",
                function=name, confidence=0.8))
        if re.search(r"(?:pub\s+)?fun\s+[^({]*\bhas\s+\w+|move_from\s*<", body) \
                and not re.search(r"public entry|entry fun", body):
            issues.append(_issue(
                rel, start_line, "access-control", "HIGH",
                "Capability / resource leak by value",
                f"{name}() returns a capability-bearing resource by value; "
                "callers can obtain privileges they should not hold.",
                function=name, confidence=0.7))
    if re.search(r"struct\s+\w+\s+has\s+[^\{]*\bcopy\b", content):
        issues.append(_issue(
            rel, 1, "access-control", "MEDIUM",
            "Copyable capability struct",
            "A struct holding privileged state has the `copy` ability, so "
            "it can be duplicated and exfiltrated.",
            confidence=0.6))
    return issues


def _detect_cairo(content: str, rel: str) -> list[StaticIssue]:
    content = _clean_code(content, "cairo")
    issues: list[StaticIssue] = []
    for m in re.finditer(r"get_caller_address\s*\(\s*\)", content):
        line = content[: m.start()].count("\n") + 1
        if re.search(r"get_execution_info\s*\(\s*\)\.caller_addr", content):
            continue
        issues.append(_issue(
            rel, line, "access-control", "HIGH",
            "get_caller_address() vs execution-info caller confusion",
            "Authorization checks use get_caller_address(), which is the "
            "immediate caller. A malicious contract can impersonate a "
            "user by calling on their behalf; prefer "
            "get_execution_info().caller_addr.", confidence=0.7))
    for m in re.finditer(r"#\[l1_handler\]", content):
        line = content[: m.start()].count("\n") + 1
        segment = content[m.start(): m.start() + 1200]
        if not re.search(r"nonce|message_hash|seen\b|used\b|consume|pop_front",
                         segment):
            issues.append(_issue(
                rel, line, "signature-replay", "MEDIUM",
                "L1->L2 handler without replay protection",
                "This l1_handler processes inbound messages with no nonce "
                "or deduplication, so an L1 message can be re-executed.",
                confidence=0.65))
    return issues


def _detect_clarity(content: str, rel: str) -> list[StaticIssue]:
    content = _clean_code(content, "clarity")
    issues: list[StaticIssue] = []
    for m in re.finditer(r"\(asserts!\s*\(is-eq\s+tx-sender", content):
        line = content[: m.start()].count("\n") + 1
        issues.append(_issue(
            rel, line, "access-control", "MEDIUM",
            "tx-sender used for authorization (should be contract-caller)",
            "The authorization check uses tx-sender, the original "
            "transaction signer. If this contract is called from another "
            "contract, tx-sender is the user, letting a malicious contract "
            "act on the user's behalf; prefer contract-caller.",
            confidence=0.7))
    for m in re.finditer(r"\(as-contract\b", content):
        line = content[: m.start()].count("\n") + 1
        issues.append(_issue(
            rel, line, "access-control", "MEDIUM",
            "as-contract? misuse",
            "as-contract? changes tx-sender to the contract principal and "
            "can bypass surrounding access checks when used inside a "
            "public function.", confidence=0.6))
    if content.count("(define-public") > 0 and "post-conditions" not in content.lower() \
            and "post-condition" not in content.lower():
        issues.append(_issue(
            rel, 1, "unchecked-external-call", "LOW",
            "No post-conditions on public functions",
            "Public functions do not define post-conditions, so callers "
            "cannot enforce transfer limits inside the transaction "
            "envelope.", confidence=0.4))
    return issues


def _detect_func(content: str, rel: str) -> list[StaticIssue]:
    content = _clean_code(content, "func")
    issues: list[StaticIssue] = []
    has_internal = "recv_internal" in content
    has_external = "recv_external" in content
    if has_internal and not re.search(r"\baccept\s*\(", content):
        issues.append(_issue(
            rel, 1, "arithmetic", "MEDIUM",
            "Missing accept() in recv_internal",
            "recv_internal() never calls accept(), so gas is not reserved "
            "and state-changing message processing can fail / be griefed.",
            confidence=0.7))
    if has_external:
        for m in re.finditer(r"recv_external", content):
            line = content[: m.start()].count("\n") + 1
            tail = content[m.start(): m.start() + 800]
            if re.search(r"load_uint|send_raw_message|send_message|op\s*==", tail):
                issues.append(_issue(
                    rel, line, "access-control", "MEDIUM",
                    "State-changing logic reachable from recv_external",
                    "External messages can trigger state-changing "
                    "operations that should require internal (funded) "
                    "messages; external messages are free to craft.",
                    confidence=0.6))
    if re.search(r"load_uint\s*\(", content) and re.search(r"begin_parse|in_msg", content):
        issues.append(_issue(
            rel, 1, "arithmetic", "LOW",
            "Possible slice underflow / TL-B parse abort",
            "Unbounded load_uint on message slices can abort the contract "
            "on malformed input (DoS).", confidence=0.5))
    return issues


def _detect_rust_solana(content: str, rel: str) -> list[StaticIssue]:
    content = _clean_code(content, "rust")
    issues: list[StaticIssue] = []
    for name, body, start_line, _, _sig in _iter_braced_functions(content, "rust"):
        if name not in ("initialize", "init"):
            continue
        guarded = re.search(
            r"require!|assert|has_one\s*=\s*owner|initialized\s*[!=]=?|"
            r"!vault\.initialized|close\s*=|owner\s*!=|!= .*owner", body)
        if guarded:
            continue
        if re.search(r"\.owner\s*=|owner\s*=|owner:", body):
            issues.append(_issue(
                rel, start_line, "unprotected-init", "HIGH",
                "Unprotected initialize (re-initializable)",
                "initialize() overwrites the account owner without "
                "checking the existing owner or an initialized flag, so "
                "anyone can reinitialize and take over the account.",
                confidence=0.75))
    for m in re.finditer(r"AccountInfo<'info>", content):
        line = content[: m.start()].count("\n") + 1
        segment = content[max(0, m.start() - 400):m.start()]
        if re.search(r"has_one|owner\s*=|constraint|seeds\s*=|bump", segment):
            continue
        issues.append(_issue(
            rel, line, "access-control", "HIGH",
            "Unverified AccountInfo (account substitution)",
            "An AccountInfo is accepted without an owner/constraint check; "
            "an attacker can substitute a crafted account. Prefer Account "
            "with #[account(...)] constraints.", confidence=0.7))
    for m in re.finditer(r"try_borrow_mut_lamports", content):
        line = content[: m.start()].count("\n") + 1
        issues.append(_issue(
            rel, line, "arithmetic", "MEDIUM",
            "Manual lamport manipulation",
            "Borrowing and mutating lamports by hand risks arithmetic "
            "errors and rent-exemption violations; prefer system_program "
            "transfers.", confidence=0.6))
    if re.search(r"#[^\n]*close\s*=\s*\w+", content) and re.search(
            r"lamports\(\)", content):
        issues.append(_issue(
            rel, 1, "arithmetic", "MEDIUM",
            "Closing account that still holds lamports",
            "An account is closed without first clearing its lamports, "
            "stranding value.", confidence=0.7))
    return issues


def _in_line_comment(content: str, start: int) -> bool:
    """True if ``start`` sits after a ``//`` on the same line."""
    line_start = content.rfind("\n", 0, start) + 1
    return "//" in content[line_start:start]


def _detect_ts_sdk(content: str, rel: str) -> list[StaticIssue]:
    content = _clean_code(content, "ts")
    issues: list[StaticIssue] = []
    for m in re.finditer(r"(?:amountOutMin|minOut|slippage|minimumOut|"
                         r"minAmountOut)\s*[:=]\s*(0|0n|0x0)\b", content):
        if _in_line_comment(content, m.start()):
            continue
        line = content[: m.start()].count("\n") + 1
        issues.append(_issue(
            rel, line, "slippage", "HIGH",
            "Slippage tolerance set to zero",
            "The swap sets minimum output / slippage to 0, making the "
            "transaction trivially sandwichable by MEV bots.",
            confidence=0.85))
    # Positional zero: swapExactTokensForTokens(amountIn, 0, ...)
    for m in re.finditer(
            r"swap\w*\s*\([^)]*,\s*0\s*,", content, re.DOTALL):
        if _in_line_comment(content, m.start()):
            continue
        line = content[: m.start()].count("\n") + 1
        issues.append(_issue(
            rel, line, "slippage", "HIGH",
            "Slippage tolerance set to zero",
            "A swap call passes 0 as minimum output, making the "
            "transaction trivially sandwichable by MEV bots.",
            confidence=0.8))
    for m in re.finditer(
            r"approve\s*\([^)]*\b(?:MaxUint256|MAX_UINT256|"
            r"ethers\.MaxUint256|2\s*\*\*\s*256\s*-\s*1)",
            content, re.DOTALL):
        line = content[: m.start()].count("\n") + 1
        issues.append(_issue(
            rel, line, "unlimited-approval", "MEDIUM",
            "Unlimited token approval",
            "approve() grants a max (uint256) allowance, so the spender "
            "can drain the wallet if compromised; use exact or "
            "time-limited allowances.", confidence=0.85))
    for m in re.finditer(r"permit\s*\(", content):
        line = content[: m.start()].count("\n") + 1
        issues.append(_issue(
            rel, line, "signature-replay", "LOW",
            "Permit submission (front-runnable)",
            "EIP-2612 permit submissions are public; consider expiry and "
            "relay protections.", confidence=0.4))
    return issues


# ---------------------------------------------------------------------------
# Extended-language detectors (analysis tier)
# ---------------------------------------------------------------------------

_UNCHECKED_CALL_SOLIDITY_WINDOW = re.compile(
    r"\(bool\s+\w+\s*,?\s*\)?\s*=|require\s*\(\s*\w+\.(?:call|delegatecall)|"
    r"assert\s*\(\s*\w+\.(?:call|delegatecall)"
)


def _detect_huff(content: str, rel: str) -> list[StaticIssue]:
    content = _clean_code(content, "huff")
    issues: list[StaticIssue] = []
    for m in re.finditer(r"#define\s+macro\s+([A-Za-z0-9_]+)", content):
        name = m.group(1)
        body_start = m.end()
        body = content[body_start:body_start + 3000]
        # Unchecked call: CALL/STATICCALL/DELEGATECALL result discarded.
        if re.search(r"\b(?:CALL|STATICCALL|DELEGATECALL)\b", body) and not re.search(
                r"(?:ISZERO|DUP1\s+ISZERO|PUSH\d*\s+JUMPI)", body):
            issues.append(_issue(
                rel, content[:m.start()].count("\n") + 1, "unchecked-external-call", "HIGH",
                "Unchecked CALL result in Huff macro",
                f"macro {name}() issues a CALL-family opcode without branching on the "
                "success flag (ISZERO/JUMPI); a reverted external call is treated "
                "as success.", function=name, confidence=0.75))
        # Auth: CALLVALUE/CALLER read but no comparison against stored owner.
        if re.search(r"\bCALLER\b", body) and not re.search(
                r"\b(?:EQ|DUP\d+\s+EQ|SLOAD)\b", body):
            issues.append(_issue(
                rel, content[:m.start()].count("\n") + 1, "access-control", "MEDIUM",
                "CALLER read without comparison",
                f"macro {name}() reads CALLER but never compares it against stored "
                "authorization state; verify the auth path.",
                function=name, confidence=0.5))
    # selfdestruct without auth macro guard
    for m in re.finditer(r"\bSELFDESTRUCT\b", content):
        line = content[:m.start()].count("\n") + 1
        window = content[max(0, m.start() - 800):m.start()]
        if not re.search(r"(?:CALLER|AUTH|OWNER)", window):
            issues.append(_issue(
                rel, line, "selfdestruct", "CRITICAL",
                "Unprotected SELFDESTRUCT in Huff macro",
                "SELFDESTRUCT is reachable without a visible authorization "
                "comparison; anyone who triggers this macro destroys the contract.",
                confidence=0.7))
    return issues


def _detect_yul(content: str, rel: str) -> list[StaticIssue]:
    content = _clean_code(content, "yul")
    issues: list[StaticIssue] = []
    for m in re.finditer(r"\bfunction\s+([A-Za-z0-9_]+)\s*\(", content):
        name = m.group(1)
        brace = content.find("{", m.end())
        if brace < 0:
            continue
        end = _brace_body(content, brace)
        body = content[brace:end]
        line = content[:m.start()].count("\n") + 1
        if re.search(r"\b(?:call|staticcall|delegatecall)\s*\(", body) and not re.search(
                r"\biszero\s*\(", body, re.IGNORECASE):
            issues.append(_issue(
                rel, line, "unchecked-external-call", "HIGH",
                "Unchecked call success in Yul function",
                f"{name}() invokes call/staticcall/delegatecall without an iszero "
                "check on the returned success flag.", function=name, confidence=0.75))
        if re.search(r"\bsstore\s*\(", body) and re.search(
                r"\b(?:add|sub|mul)\s*\(\s*(?:calldataload|mload)", body, re.IGNORECASE):
            issues.append(_issue(
                rel, line, "arithmetic", "HIGH",
                "Computed storage slot from user input (collision risk)",
                f"{name}() derives an SSTORE slot from calldata/memory arithmetic; "
                "verify slot-collision and overflow behavior.",
                function=name, confidence=0.6))
    return issues


def _detect_ink(content: str, rel: str) -> list[StaticIssue]:
    content = _clean_code(content, "rust")
    issues: list[StaticIssue] = []
    if "ink_lang" not in content and "use ink" not in content and "#[ink:" not in content:
        return []
    for name, body, start_line, _, sig in _iter_braced_functions(content, "rust"):
        # Unchecked cross-contract call result
        if re.search(r"\b(?:build_call|invoke_contract|call\()", body) and not re.search(
                r"\b(?:unwrap_or|unwrap\(|expect\(|\?|match\s+)", body):
            issues.append(_issue(
                rel, start_line, "unchecked-external-call", "HIGH",
                "Unchecked ink! cross-contract call result",
                f"{name}() performs a cross-contract call without unwrapping the "
                "returned Result; a failed call is silently ignored.",
                function=name, confidence=0.7))
        # Panic on user input
        if re.search(r"\.unwrap\(\)|\.expect\(", body) and re.search(
                r"(?:msg|caller|input|args|amount)", body, re.IGNORECASE) \
                and "test" not in sig.lower():
            issues.append(_issue(
                rel, start_line, "denial-of-service", "MEDIUM",
                "unwrap()/expect() on call path (caller-triggered abort)",
                f"{name}() can panic on user-controlled input, aborting the "
                "message and reverting state (gas griefing / DoS).",
                function=name, confidence=0.6))
    # Missing initializer guard on constructor-ish fns
    for m in re.finditer(r"#\[ink\(constructor\)\]", content):
        seg = content[m.start():m.start() + 1200]
        if not re.search(r"already_init|initialized|self\.owner\.set", seg):
            issues.append(_issue(
                rel, content[:m.start()].count("\n") + 1, "unprotected-init", "MEDIUM",
                "Constructor without visible initialization guard",
                "ink! constructor sets state without an explicit initialized "
                "flag; verify re-deployment semantics.", confidence=0.5))
    return issues


def _detect_cosmwasm(content: str, rel: str) -> list[StaticIssue]:
    content = _clean_code(content, "rust")
    issues: list[StaticIssue] = []
    if "cosmwasm" not in content and "cw_" not in content:
        return []
    for name, body, start_line, _, _sig in _iter_braced_functions(content, "rust"):
        if re.search(r"\b(?:addr_validate|addr_canonicalize|canonicalize)\b", body):
            continue
        if re.search(r"\b(?:Addr::unchecked|deps\.api\.addr_)\b", body):
            issues.append(_issue(
                rel, start_line, "access-control", "HIGH",
                "Addr::unchecked on caller path",
                f"{name}() constructs an Addr via Addr::unchecked; unvalidated "
                "addresses enable addr aliasing and spoofing.",
                function=name, confidence=0.75))
        if re.search(r"\.unwrap\(\)", body) and re.search(
                r"(?:Uint|Int|try_from|coins|amount)", body):
            issues.append(_issue(
                rel, start_line, "arithmetic", "MEDIUM",
                "unwrap() on numeric conversion (truncation/overflow abort)",
                f"{name}() unwraps a numeric conversion; a caller-chosen value "
                "can panic the contract (DoS) or truncate balances.",
                function=name, confidence=0.65))
    # Reply reentrancy: ReplyOn::Always with state writes
    if re.search(r"ReplyOn::Always", content) and re.search(
            r"fn reply", content) and re.search(r"store\(|save\(|update\( minors", content):
        issues.append(_issue(
            rel, 1, "reentrancy", "MEDIUM",
            "ReplyOn::Always with state writes in reply()",
            "Submessages configured with ReplyOn::Always combined with state "
            "mutations in reply() can double-apply state on failure paths.",
            confidence=0.55))
    return issues


def _detect_substrate(content: str, rel: str) -> list[StaticIssue]:
    content = _clean_code(content, "rust")
    issues: list[StaticIssue] = []
    if "frame_" not in content and "#[pallet" not in content:
        return []
    for m in re.finditer(r"#\[pallet::weight\]\s*\(\s*(\d+)", content):
        weight = int(m.group(1))
        seg_end = min(len(content), m.start() + 3000)
        seg = content[m.start():seg_end]
        loop_iters = len(re.findall(r"for\s+\w+\s+in\s+", seg))
        if loop_iters and weight < 10_000:
            issues.append(_issue(
                rel, content[:m.start()].count("\n") + 1, "denial-of-service", "MEDIUM",
                "Weight annotation below loop-complexity reality",
                f"Extrinsic declares weight {weight} but iterates over storage "
                "collections; the block-gas budget can be exhausted by a "
                "single call.", confidence=0.6))
    for name, body, start_line, _, _sig in _iter_braced_functions(content, "rust"):
        if re.search(r"\bT::Currency::transfer\b", body) and not re.search(
                r"\?\s*;|ensure!|\.map_err", body):
            issues.append(_issue(
                rel, start_line, "unchecked-external-call", "HIGH",
                "Currency::transfer result ignored",
                f"{name}() calls T::Currency::transfer without propagating the "
                "result; failed transfers corrupt accounting.",
                function=name, confidence=0.8))
    return issues


def _detect_go_cosmos_impl(content: str, rel: str) -> list[StaticIssue]:
    content = _clean_code(content, "go")
    issues: list[StaticIssue] = []
    if "sdk" not in content and "bankkeeper" not in content.lower():
        return []
    for m in re.finditer(r"func\s+(?:\([^)]*\)\s*)?(\w+)\s*\([^)]*\)[^{]*\{", content):
        name = m.group(1)
        brace = content.find("{", m.end() - 1)
        if brace < 0:
            continue
        end = _brace_body(content, brace)
        body = content[brace:end]
        line = content[:m.start()].count("\n") + 1
        if re.search(r"SendCoins|SendCoinsFromModuleToAccount", body) and not re.search(
                r"if\s+err\s*!=\s*nil|:=\s*.*err|return\s+err", body):
            issues.append(_issue(
                rel, line, "unchecked-external-call", "HIGH",
                "Bank transfer error ignored",
                f"{name}() invokes a bank-keeper transfer without checking the "
                "returned error; failed sends leave state inconsistent.",
                function=name, confidence=0.8))
        if re.search(r"msg\.GetAuthority\(\)|\.GetAuthority\(\)", body) is None and re.search(
                r"UpdateParams|SetParams|ParamChange", body):
            issues.append(_issue(
                rel, line, "access-control", "HIGH",
                "Param update without authority check",
                f"{name}() mutates module params without verifying "
                "msg authority; any signer can rewrite module configuration.",
                function=name, confidence=0.8))
        for_range = len(re.findall(r"for\s+_?\w*\s*:?=\s*range\s+", body))
        if for_range and not re.search(r"Paginator|limit|Limit", body):
            issues.append(_issue(
                rel, line, "denial-of-service", "MEDIUM",
                "Unbounded store iteration (gas DoS)",
                f"{name}() ranges over a store prefix without pagination; a "
                "large dataset exhausts the block gas limit.",
                function=name, confidence=0.65))
    return issues


def _detect_go_cosmos(content: str, rel: str) -> list[StaticIssue]:
    return _detect_go_cosmos_impl(content, rel)


def _detect_scilla(content: str, rel: str) -> list[StaticIssue]:
    content = _clean_code(content, "scilla")
    issues: list[StaticIssue] = []
    for m in re.finditer(r"\btransition\s+([A-Za-z0-9_]+)", content):
        name = m.group(1)
        seg = content[m.start():m.start() + 4000]
        line = content[:m.start()].count("\n") + 1
        send_idx = seg.find("send")
        balance_idx = max(seg.find("_balance"), seg.find("balance"))
        sends_before_state = send_idx >= 0 and (
            balance_idx < 0 or send_idx < balance_idx
        )
        if sends_before_state:
            issues.append(_issue(
                rel, line, "reentrancy", "HIGH",
                "send before balance/state update (Scilla reentrancy)",
                f"transition {name} issues messages with send before updating "
                "_balance or state fields; a re-entrant transition can "
                "double-spend.", function=name, confidence=0.7))
        if re.search(r"\b_sender\b", seg) and re.search(
                r"\bowner\b", seg) and not re.search(
                r"_sender\s*=\s*owner|owner\s*=\s*_sender|builtin\s+eq", seg):
            issues.append(_issue(
                rel, line, "access-control", "MEDIUM",
                "_sender accepted without owner comparison",
                f"transition {name} reads _sender and references owner without "
                "an equality check; verify the authorization path.",
                function=name, confidence=0.5))
    return issues


def _detect_michelson(content: str, rel: str) -> list[StaticIssue]:
    content = _clean_code(content, "michelson")
    issues: list[StaticIssue] = []
    if re.search(r"\bTRANSFER_TOKENS\b", content) and not re.search(
            r"\bFAILWITH\b", content):
        issues.append(_issue(
            rel, 1, "unchecked-external-call", "HIGH",
            "TRANSFER_TOKENS without visible failure path",
            "The contract transfers tokens without a FAILWITH guard on the "
            "operation; a failed transfer may be silently dropped.",
            confidence=0.6))
    if re.search(r"\bSOURCE\b", content):
        issues.append(_issue(
            rel, content[:content.find("SOURCE")].count("\n") + 1 if "SOURCE" in content else 1,
            "tx-origin", "MEDIUM",
            "SOURCE used (Tezos tx.origin equivalent)",
            "SOURCE is the original transaction signer; authorization based on "
            "SOURCE instead of SENDER enables proxy-contract spoofing.",
            confidence=0.7))
    if re.search(r"\bLAMBDA\b", content) and re.search(
            r"\b(?:PUSH|CAR|CDR)\b[\s\S]{0,200}\bEXEC\b", content):
        issues.append(_issue(
            rel, 1, "delegatecall", "MEDIUM",
            "Lambda EXEC on attacker-influenced parameter",
            "A lambda built from storage/parameter values is EXECuted; a "
            "caller able to shape the closure executes arbitrary logic.",
            confidence=0.55))
    return issues


def _detect_sass(content: str, rel: str) -> list[StaticIssue]:
    content = _clean_code(content, "sass")
    issues: list[StaticIssue] = []
    for m in re.finditer(r"(?:pub\s+)?func\s+([A-Za-z0-9_]+)", content):
        name = m.group(1)
        seg = content[m.start():m.start() + 3000]
        line = content[:m.start()].count("\n") + 1
        if re.search(r"\b(?:call|delegate)\s*\(", seg) and not re.search(
                r"\b(?:if|assert|require|match)\b", seg):
            issues.append(_issue(
                rel, line, "unchecked-external-call", "MEDIUM",
                "External call without visible check",
                f"{name}() performs an external call without a visible result "
                "check; verify failure handling.", function=name, confidence=0.5))
    return issues


def _detect_solidity_asm(content: str, rel: str) -> list[StaticIssue]:
    """Assembly-focused pass over Solidity sources (inline Yul)."""
    content = _clean_code(content, "solidity")
    issues: list[StaticIssue] = []
    for m in re.finditer(r"\bassembly\s*(?:\(|\{)", content):
        line = content[:m.start()].count("\n") + 1
        brace_idx = content.find("{", m.end() - 1)
        if brace_idx < 0:
            continue
        body = content[brace_idx:_brace_body(content, brace_idx)]
        if re.search(r"\bmstore\s*\(\s*0x40", body) is None and re.search(
                r"\bm(?:load|store)\s*\(", body):
            issues.append(_issue(
                rel, line, "arithmetic", "MEDIUM",
                "Manual memory use without updating free pointer",
                "Assembly block performs mload/mstore without restoring the "
                "free-memory pointer (0x40); subsequent allocations corrupt "
                "memory.", confidence=0.55))
        if re.search(r"\bdelegatecall\s*\(", body) and not re.search(
                r"\b(?:extcodesize|require|iszero)\b", body):
            issues.append(_issue(
                rel, line, "delegatecall", "HIGH",
                "Assembly delegatecall without address validation",
                "Inline delegatecall executes with the caller's storage "
                "context; without validating the target address a caller can "
                "overwrite arbitrary storage.", confidence=0.7))
        if re.search(r"\breturndatacopy\s*\(", body) and not re.search(
                r"\breturndatasize\s*\(\s*\)", body):
            issues.append(_issue(
                rel, line, "unchecked-external-call", "MEDIUM",
                "returndatacopy without returndatasize bound",
                "Copying return data without checking returndatasize can read "
                "out of bounds or copy attacker-controlled junk.",
                confidence=0.6))
    return issues


def _detect_wat(content: str, rel: str) -> list[StaticIssue]:
    content = _clean_code(content, "wat")
    issues: list[StaticIssue] = []
    for m in re.finditer(r"\bcall_indirect\b", content):
        line = content[:m.start()].count("\n") + 1
        window = content[max(0, m.start() - 500):m.start() + 500]
        if not re.search(r"\b(?:i32\.(?:const|load)|table\.get|br_if)\b", window):
            issues.append(_issue(
                rel, line, "access-control", "HIGH",
                "call_indirect without visible index validation",
                "call_indirect dispatches through a table using a runtime "
                "index; without bounds/type validation an attacker-controlled "
                "index achieves type confusion / arbitrary dispatch.",
                confidence=0.6))
    if re.search(r"\bmemory\.grow\b", content) and not re.search(
            r"\b(?:i32\.const|memory\.size)\b[\s\S]{0,120}memory\.grow", content):
        issues.append(_issue(
            rel, content[:content.find("memory.grow")].count("\n") + 1 if "memory.grow" in content else 1,
            "denial-of-service", "MEDIUM",
            "Unbounded memory.grow",
            "memory.grow without a size ceiling lets a caller exhaust host "
            "memory (OOM DoS).", confidence=0.6))
    return issues


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

_EXT_TO_LANGUAGE: tuple[tuple[str, TargetLanguage], ...] = (
    (".sol", TargetLanguage.SOLIDITY),
    (".vy", TargetLanguage.VYPER),
    (".vyper", TargetLanguage.VYPER),
    (".move", TargetLanguage.MOVE),
    (".cairo", TargetLanguage.CAIRO),
    (".clar", TargetLanguage.CLARITY),
    (".fc", TargetLanguage.FUNC),
    (".func", TargetLanguage.FUNC),
    (".rs", TargetLanguage.RUST_SOLANA),
    (".ts", TargetLanguage.TS_SDK),
    (".js", TargetLanguage.TS_SDK),
    (".mjs", TargetLanguage.TS_SDK),
    (".cjs", TargetLanguage.TS_SDK),
    # Extended coverage (checked after the primary languages so a Rust
    # Solana repo is not misread as ink!/CosmWasm/Substrate).
    (".huff", TargetLanguage.HUFF),
    (".yul", TargetLanguage.YUL),
    (".scilla", TargetLanguage.SCILLA),
    (".tz", TargetLanguage.MICHELSON),
    (".michelson", TargetLanguage.MICHELSON),
    (".al", TargetLanguage.ALCHEMY),
    (".sass", TargetLanguage.SASM),
    (".wat", TargetLanguage.WEBASSEMBLY),
    (".wast", TargetLanguage.WEBASSEMBLY),
    (".go", TargetLanguage.GO_COSMOS),
)

_DETECTORS = {
    TargetLanguage.SOLIDITY: _detect_solidity,
    TargetLanguage.VYPER: _detect_vyper,
    TargetLanguage.MOVE: _detect_move,
    TargetLanguage.CAIRO: _detect_cairo,
    TargetLanguage.CLARITY: _detect_clarity,
    TargetLanguage.FUNC: _detect_func,
    TargetLanguage.RUST_SOLANA: _detect_rust_solana,
    TargetLanguage.TS_SDK: _detect_ts_sdk,
    TargetLanguage.HUFF: _detect_huff,
    TargetLanguage.YUL: _detect_yul,
    TargetLanguage.INK: _detect_ink,
    TargetLanguage.COSMWASM: _detect_cosmwasm,
    TargetLanguage.SUBSTRATE: _detect_substrate,
    TargetLanguage.GO_COSMOS: _detect_go_cosmos,
    TargetLanguage.SCILLA: _detect_scilla,
    TargetLanguage.MICHELSON: _detect_michelson,
    TargetLanguage.CAIRO1: _detect_cairo,
    TargetLanguage.SASM: _detect_sass,
    TargetLanguage.SOLIDITY_ASM: _detect_solidity_asm,
    TargetLanguage.WEBASSEMBLY: _detect_wat,
}

_SKIP_SUFFIXES = ("_test.move", ".test.ts", ".test.js", ".spec.ts",
                  ".spec.js", "test.sol", ".t.sol")


def _detector_for(fp: Path) -> tuple[TargetLanguage, Any] | None:
    for suffix, lang in _EXT_TO_LANGUAGE:
        if fp.name.lower().endswith(suffix):
            if any(fp.name.lower().endswith(s) for s in _SKIP_SUFFIXES):
                return None
            # Shared-extension disambiguation: .rs belongs to Solana,
            # ink!, CosmWasm, and Substrate. Pick the detector by content
            # signature so each file feeds the right vulnerability rules.
            if lang is TargetLanguage.RUST_SOLANA:
                return _rust_detector_for(fp)
            return lang, _DETECTORS.get(lang)
    return None


_INK_SIG = re.compile(r"ink_lang|use ink::|#\[ink[(:]|#\[ink::")
_CW_SIG = re.compile(r"cosmwasm_std|cosmwasm-std|cw_storage_plus|cw_serde|use cw_")
_SUB_SIG = re.compile(r"frame_support|frame::|#\[pallet|sp_runtime")


def _rust_detector_for(fp: Path) -> tuple[TargetLanguage, Any] | None:
    """Route a .rs file to the right Rust-ecosystem detector by content."""
    try:
        text = fp.read_text(errors="ignore")[:8000]
    except Exception:  # noqa: BLE001
        text = ""
    if _CW_SIG.search(text):
        return TargetLanguage.COSMWASM, _detect_cosmwasm
    if _INK_SIG.search(text):
        return TargetLanguage.INK, _detect_ink
    if _SUB_SIG.search(text):
        return TargetLanguage.SUBSTRATE, _detect_substrate
    return TargetLanguage.RUST_SOLANA, _detect_rust_solana


def language_for_file(fp: Path) -> TargetLanguage | None:
    """Map a file to the language its detector uses, or ``None``.

    Exposed so the scanner core can tag discovery findings with the
    *actual* language of the file (rather than the adapter that
    happened to invoke the multi-language static engine).
    """
    detection = _detector_for(fp)
    if detection is None:
        return None
    return detection[0]


class StaticAnalyzerEngine(DiscoveryEngineBase):
    """Built-in deterministic heuristic analyzer (no binary required).

    Every file is classified by extension and passed to the matching
    language detector, so a single engine instance covers all supported
    languages regardless of which language the scanner dispatched for.
    """

    name = "web3guard-static"
    binary = ""  # always "installed" — no external toolchain needed
    supported_languages = tuple(_DETECTORS.keys())
    default_timeout = 300
    enabled_by_default = True

    def run(self, target_path: Path, *, timeout: int = 0,
            extra_args: list[str] | None = None) -> list[DiscoveryResult]:
        results: list[DiscoveryResult] = []
        for fp in sorted(target_path.rglob("*")):
            if not fp.is_file():
                continue
            detection = _detector_for(fp)
            if detection is None:
                continue
            _lang, detector = detection
            try:
                rel = str(fp.relative_to(target_path))
            except ValueError:  # noqa: PERF203
                continue
            try:
                content = fp.read_text(errors="ignore")
            except Exception:  # noqa: BLE001
                continue
            for issue in detector(content, rel):
                results.append(DiscoveryResult(
                    engine=self.name,
                    target=str(target_path),
                    file=issue.file,
                    line=issue.line,
                    function=issue.function,
                    category=issue.category,
                    severity=issue.severity,
                    title=issue.title,
                    description=issue.description,
                    swc_id=issue.swc_id,
                    confidence=issue.confidence,
                    raw={"static": True, "notes": issue.extra},
                ))
        return results

    def run_text(self, content: str, rel_path: str = "snippet.sol",
                 language: str = "solidity") -> list[DiscoveryResult]:
        """Run the language detector over an in-memory source string.

        Same result shape as :meth:`run`; useful for targeted checks and
        tests without materializing a file tree. ``language`` is a
        ``TargetLanguage`` member name, case-insensitive with ``-`` or
        ``_`` separators (``"solidity"``, ``"Rust-Solana"``, ...).
        """
        member = getattr(
            TargetLanguage,
            language.upper().replace("-", "_"),
            None,
        )
        detector = _DETECTORS.get(member) if member is not None else None
        if detector is None:
            return []
        results: list[DiscoveryResult] = []
        for issue in detector(content, rel_path):
            results.append(DiscoveryResult(
                engine=self.name,
                target="<text>",
                file=issue.file,
                line=issue.line,
                function=issue.function,
                category=issue.category,
                severity=issue.severity,
                title=issue.title,
                description=issue.description,
                swc_id=issue.swc_id,
                confidence=issue.confidence,
                raw={"static": True, "notes": issue.extra},
            ))
        return results

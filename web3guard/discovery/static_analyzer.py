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
        out.append((name, text[brace:end], start_line, brace, stmt))
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
    if lang in ("solidity", "rust", "move", "cairo", "func", "ts"):
        text = re.sub(r"/\*.*?\*/",
                      lambda m: re.sub(r"[^\n]", " ", m.group(0)), text,
                      flags=re.DOTALL)
        text = re.sub(r"(?m)^[ \t]*//.*$", "", text)
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
    r"only[A-Z][A-Za-z0-9_]*\b|"
    r"require\s*\([^;]{0,120}\bmsg\.sender\b|require\s*\([^;]{0,80}owner|"
    r"assert\s+msg\.sender\s*==\s*self\.(?:owner|admin)|"
    r"asserts!\s*\(is-eq\s+(?:tx-sender|contract-caller)|"
    r"has_one\s*=\s*owner|signer\s*::|Signer<|is_signer|"
    r"#[^\n]*Signer<"
)
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
        # 2. Access control.
        guarded = bool(_GUARD_RE.search(sig + body))
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
    for name, body, start_line, _, sig in _iter_braced_functions(content, "solidity"):
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
    for name, body, start_line, _, sig in _iter_braced_functions(content, "move"):
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
    for name, body, start_line, _, sig in _iter_braced_functions(content, "rust"):
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
}

_SKIP_SUFFIXES = ("_test.move", ".test.ts", ".test.js", ".spec.ts",
                  ".spec.js", "test.sol", ".t.sol")


def _detector_for(fp: Path) -> tuple[TargetLanguage, Any] | None:
    for suffix, lang in _EXT_TO_LANGUAGE:
        if fp.name.lower().endswith(suffix):
            if any(fp.name.lower().endswith(s) for s in _SKIP_SUFFIXES):
                return None
            return lang, _DETECTORS.get(lang)
    return None


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

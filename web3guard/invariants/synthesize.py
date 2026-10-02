"""Invariant synthesis (Phase 2, step 1) — the PROMFUZZ pattern.

Given contract source, draft "must-always-hold" invariants in two layers:

1. **Deterministic templates** (:mod:`web3guard.invariants.templates`) — a
   WIDE registry of hand-written, widely-applicable properties (~17 Solidity
   templates across conservation, access-control, arithmetic bounds, pausing,
   fees, allowances, mint/burn symmetry, oracle staleness, and share-price
   sanity, plus Vyper/Cairo mirrors of the core set). These ALWAYS run, even
   with no AI keys, so the pipeline works keyless at reduced depth. Each
   template declares applicability conditions and is only emitted when the
   contract actually matches them. Templates with ghost state additionally
   get a generated handler harness (see templates.render_ghost_project).

2. **LLM-drafted invariants** — when the router client is active, the model is
   asked for deeper, contract-specific properties (accounting desync,
   access-control intent, oracle/price assumptions, rounding, share-price
   monotonicity). Output is validated against a strict schema; malformed
   output is rejected with a clear log line and never crashes the scan.

Every rule from either layer must additionally pass the proof gate
(:mod:`web3guard.invariants.proof_gate`) before it can produce a finding.

Security note: contract source is untrusted input to the prompt. We rely on
:class:`web3guard.ai.client.AIClient`'s built-in prompt-injection guard
(which :class:`RouterClient` inherits); the templates below never touch the
model at all.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping
from typing import Any

from web3guard.ai.router import AnyRouterClient, build_router_client
from web3guard.invariants.models import Invariant, SynthesisResult

LOGGER = logging.getLogger("web3guard.invariants.synthesize")

# Cap on source characters sent to the model: bounds token spend on huge
# files and keeps the prompt focused on the contract's core logic.
_MAX_SOURCE_CHARS = 12_000
_MAX_LLM_INVARIANTS = 12

_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_BUG_CLASS_SEVERITY = {
    "accounting-desync": "HIGH",
    "access-control": "HIGH",
    "oracle-price": "CRITICAL",
    "rounding": "MEDIUM",
    "share-price": "HIGH",
    "fee-accounting": "MEDIUM",
    "allowance": "HIGH",
    "other": "MEDIUM",
}


# ---------------------------------------------------------------------------
# Deterministic template fallback (always runs, no AI needed).
#
# The registry itself lives in web3guard.invariants.templates (Phase 3
# widened it well beyond the original 3 Solidity templates and added
# ghost-state temporal properties). The names below are re-exported for
# backward compatibility.
# ---------------------------------------------------------------------------

from web3guard.invariants.templates import (  # noqa: E402
    CAIRO_TEMPLATES,
    GENERIC_TEMPLATES,
    VYPER_TEMPLATES,
    TemplateSpec,
    template_invariants,
)

_TEMPLATES_BY_LANGUAGE: dict[str, list[TemplateSpec]] = {
    "solidity": GENERIC_TEMPLATES,
    "vyper": VYPER_TEMPLATES,
    "cairo": CAIRO_TEMPLATES,
}

__all__ = [
    "CAIRO_TEMPLATES",
    "GENERIC_TEMPLATES",
    "VYPER_TEMPLATES",
    "synthesize_invariants",
    "template_invariants",
]


# ---------------------------------------------------------------------------
# LLM-drafted invariants
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a smart-contract security auditor drafting FUZZING INVARIANTS for \
Foundry invariant testing (PROMFUZZ pattern).

An invariant is a property that must hold after EVERY possible sequence of \
transactions. You are given Solidity source. Draft invariants an attacker \
would love to break, focusing on these bug classes:

- accounting-desync: token/vault balances vs recorded totals drifting apart
- access-control: privileged actions reachable by the wrong caller, ownership intent
- oracle-price: assumptions about prices, TWAPs, or external price feeds
- rounding: dust amounts, division order, zero-share edge cases
- share-price: share price monotonicity, donation/inflation games

RULES (strict):
1. Output ONLY a JSON array. No prose, no markdown fences.
2. Each element MUST have exactly these fields:
   - "id": short slug, e.g. "no-free-mint"
   - "statement": one-sentence natural-language property
   - "assertion": ONE Solidity boolean expression evaluated against the \
contract's PUBLIC interface. The contract instance is named `target`. \
Example: "target.totalSupply() == target.totalAssets()". No ghost state, \
no new variables, no semicolons, single line.
   - "variables": array of state variable names involved (may be [])
   - "functions": array of function names involved (may be [])
   - "rationale": one sentence on why it matters
   - "bug_class": one of accounting-desync, access-control, oracle-price, \
rounding, share-price, other
3. Only use getters/functions that EXIST in the source. Never invent them.
4. Prefer 3-8 invariants. Quality over quantity.
"""

# Assertion dialects per language: the model must write assertions the
# corresponding campaign driver can actually evaluate.
_ASSERTION_RULES = {
    "solidity": (
        "ONE Solidity boolean expression evaluated against the contract's "
        "PUBLIC interface. The contract instance is named `target`. Example: "
        '"target.totalSupply() == target.totalAssets()". No ghost state, no '
        "new variables, no semicolons, single line."
    ),
    "vyper": (
        "ONE Python boolean expression evaluated against the deployed "
        "contract object named `target` (its ABI functions are called like "
        '`target.total_supply()`). Example: '
        '"target.total_supply() == target.total_assets()". Write the zero '
        "address as `address(0)`, True/False capitalized, `and`/`or`/`not` "
        "for logic — Python syntax, NOT Solidity. No ghost state, no new "
        "variables, no semicolons, single line."
    ),
    "cairo": (
        "ONE boolean expression in a RESTRICTED grammar: comparisons "
        "(`==`, `!=`, `<`, `>`, `<=`, `>=`) between `target.<getter>()` calls "
        "(the contract instance is named `target`), integer literals, or the "
        "zero address written as `address(0)` — optionally joined by `&&` / "
        "`||`. Examples: `target.total_supply() == target.total_assets()`, "
        "`target.owner() != address(0)`. Use ONLY getters that EXIST in the "
        "source, snake_case names as written. No other syntax — no arithmetic, "
        "no function calls besides the getters, no semicolons, single line."
    ),
}

_LANGUAGE_LABEL = {
    "solidity": "Solidity",
    "vyper": "Vyper",
    "cairo": "Cairo (Starknet)",
}


def _system_prompt_for(language: str) -> str:
    if language == "solidity":
        return _SYSTEM_PROMPT
    label = _LANGUAGE_LABEL.get(language, language)
    return f"""\
You are a smart-contract security auditor drafting FUZZING INVARIANTS \
(PROMFUZZ pattern) for {label} contracts.

An invariant is a property that must hold after EVERY possible sequence of \
transactions. You are given {label} source. Draft invariants an attacker \
would love to break, focusing on these bug classes:

- accounting-desync: token/vault balances vs recorded totals drifting apart
- access-control: privileged actions reachable by the wrong caller, ownership intent
- oracle-price: assumptions about prices, TWAPs, or external price feeds
- rounding: dust amounts, division order, zero-share edge cases
- share-price: share price monotonicity, donation/inflation games

RULES (strict):
1. Output ONLY a JSON array. No prose, no markdown fences.
2. Each element MUST have exactly these fields:
   - "id": short slug, e.g. "no-free-mint"
   - "statement": one-sentence natural-language property
   - "assertion": {_ASSERTION_RULES[language]}
   - "variables": array of state variable names involved (may be [])
   - "functions": array of function names involved (may be [])
   - "rationale": one sentence on why it matters
   - "bug_class": one of accounting-desync, access-control, oracle-price, \
rounding, share-price, other
3. Only use getters/functions that EXIST in the source. Never invent them.
4. Prefer 3-8 invariants. Quality over quantity.
"""


def _build_user_prompt(
    contract_name: str, source: str, language: str = "solidity",
) -> str:
    trimmed = source[:_MAX_SOURCE_CHARS]
    clipped = len(source) > _MAX_SOURCE_CHARS
    label = _LANGUAGE_LABEL.get(language, language)
    fence = {"solidity": "solidity", "vyper": "python", "cairo": "cairo"}.get(
        language, ""
    )
    return (
        f"Contract `{contract_name}` ({label}). Draft fuzzing invariants.\n\n"
        f"```{fence}\n{trimmed}\n```\n"
        + ("(source truncated to 12000 chars)\n" if clipped else "")
        + "\nReturn the JSON array now."
    )


def _str_list(item: dict[str, Any], key: str) -> list[str]:
    val = item.get(key, [])
    if not isinstance(val, list):
        return []
    return [str(v)[:80] for v in val if isinstance(v, (str, int))][:16]


def _validate_llm_invariant(
    item: Any, where: str, existing_ids: set[str],
) -> Invariant:
    """Validate one model-produced invariant; raise ValueError naming the flaw."""
    if not isinstance(item, dict):
        raise ValueError(f"{where}: must be an object")
    for field in ("id", "statement", "assertion"):
        if not isinstance(item.get(field), str) or not item[field].strip():
            raise ValueError(f"{where}: missing or empty required field {field!r}")
    inv_id = re.sub(r"[^A-Za-z0-9_-]", "-", item["id"].strip())[:64]
    if not inv_id or inv_id in existing_ids:
        raise ValueError(f"{where}: duplicate or empty id {item['id']!r}")
    existing_ids.add(inv_id)
    # The assertion must be a single-line expression: collapse whitespace,
    # reject anything that looks like a statement block.
    assertion = " ".join(item["assertion"].split())
    if any(tok in assertion for tok in (";", "{", "}")):
        raise ValueError(f"{where}: assertion must be a single expression")
    bug_class = str(item.get("bug_class", "other"))
    if bug_class not in _BUG_CLASS_SEVERITY:
        bug_class = "other"
    severity = str(item.get("severity", "")).upper()
    if severity not in _SEVERITIES:
        severity = _BUG_CLASS_SEVERITY[bug_class]
    return Invariant(
        id=inv_id,
        statement=item["statement"].strip()[:500],
        variables=_str_list(item, "variables"),
        functions=_str_list(item, "functions"),
        assertion=assertion[:500],
        rationale=str(item.get("rationale", ""))[:500],
        bug_class=bug_class,
        source="llm",
        severity=severity,
    )


def _parse_llm_invariants(
    raw: str, *, existing_ids: set[str],
) -> tuple[list[Invariant], list[str]]:
    """Validate model output, skipping bad elements instead of dumping the batch.

    Raises ValueError (the whole batch is rejected) only for structurally
    malformed output — not valid JSON, or not a JSON array. An individual
    element with a duplicate id, a missing field, or a statement-shaped
    assertion is skipped with a reason recorded in the returned rejection
    list: one confused element no longer discards the rest of an otherwise
    good batch. Every kept element passed the full strict validation above.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"LLM invariant output is not valid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise ValueError(
            f"LLM invariant output must be a JSON array, got {type(data).__name__}"
        )
    out: list[Invariant] = []
    rejected: list[str] = []
    for i, item in enumerate(data[:_MAX_LLM_INVARIANTS]):
        where = f"element {i}"
        try:
            out.append(_validate_llm_invariant(item, where, existing_ids))
        except ValueError as exc:
            # Self-improvement loop, iteration 5: skip the one bad
            # element (loudly) instead of rejecting the whole batch.
            LOGGER.warning("skipping malformed LLM invariant %s: %s", where, exc)
            rejected.append(str(exc))
    return out, rejected


def synthesize_invariants(
    contract_source: str,
    client: AnyRouterClient | None,
    config: Mapping[str, Any] | None,
    *,
    contract_name: str = "Target",
    language: str = "solidity",
) -> SynthesisResult:
    """Draft invariants for ``contract_source``.

    Templates always run. The LLM layer runs only when ``client`` is active;
    when AI is inactive the function logs a LOUD static-only message and
    returns the templates alone — it never fails the scan.
    """
    result = SynthesisResult()
    templates = template_invariants(contract_source, language=language)
    result.invariants.extend(templates)
    existing_ids = {inv.id for inv in templates}

    if client is None:
        client = build_router_client(config)

    if not client.is_active:
        reason = getattr(client, "inactive_reason", "AI inactive")
        msg = (
            "AI INVARIANT SYNTHESIS SKIPPED (static-only mode): "
            f"{reason}. Continuing with {len(templates)} hand-written "
            "template invariant(s) at reduced depth. Add a free LLM API key "
            "to enable AI-drafted invariants."
        )
        LOGGER.warning(msg)
        result.notes.append(msg)
        return result

    try:
        resp = client.chat(
            _system_prompt_for(language),
            _build_user_prompt(contract_name, contract_source, language),
            max_tokens=2000,
            temperature=0.0,
            role="analysis",
        )
    except Exception as exc:  # noqa: BLE001 - an LLM failure must not kill a scan
        msg = f"LLM invariant synthesis failed ({exc}); using templates only."
        LOGGER.warning(msg)
        result.notes.append(msg)
        return result

    if resp.raw.get("ai_inactive"):
        # Defensive: client claimed active but returned the null response.
        msg = "LLM client reported inactive mid-call; using templates only."
        LOGGER.warning(msg)
        result.notes.append(msg)
        return result

    try:
        llm_invariants, rejected = _parse_llm_invariants(
            resp.content, existing_ids=existing_ids
        )
    except ValueError as exc:
        LOGGER.warning("rejecting malformed LLM invariant output: %s", exc)
        result.notes.append(f"LLM invariant output rejected ({exc}); using templates only.")
        return result

    if rejected:
        result.notes.append(
            f"LLM invariant synthesis: {len(rejected)} element(s) skipped as "
            f"malformed ({'; '.join(rejected[:3])}"
            f"{'...' if len(rejected) > 3 else ''}); "
            f"keeping {len(llm_invariants)} valid element(s)."
        )
    result.invariants.extend(llm_invariants)
    result.ai_used = bool(llm_invariants)
    LOGGER.info(
        "synthesized %d invariants for %s (%d template, %d LLM)",
        len(result.invariants), contract_name, len(templates), len(llm_invariants),
    )
    return result

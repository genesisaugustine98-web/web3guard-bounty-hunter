"""Invariant synthesis (Phase 2, step 1) — the PROMFUZZ pattern.

Given Solidity contract source, draft "must-always-hold" invariants in two
layers:

1. **Deterministic templates** (:data:`GENERIC_TEMPLATES`) — a small set of
   hand-written, widely-applicable properties (e.g. ``totalSupply ==
   totalAssets`` for 1:1 vaults). These ALWAYS run, even with no AI keys, so
   the pipeline works keyless at reduced depth. Each template declares the
   public getters it needs; it is only emitted when the contract actually
   exposes them.

2. **LLM-drafted invariants** — when the router client is active, the model is
   asked for deeper, contract-specific properties (accounting desync,
   access-control intent, oracle/price assumptions, rounding, share-price
   monotonicity). Output is validated against a strict schema; malformed
   output is rejected with a clear log line and never crashes the scan.

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
    "other": "MEDIUM",
}


# ---------------------------------------------------------------------------
# Deterministic template fallback (always runs, no AI needed)
# ---------------------------------------------------------------------------


class _Template:
    """One hand-written invariant template with applicability conditions."""

    def __init__(
        self,
        id: str,
        statement: str,
        requires: list[str],
        assertion: str,
        rationale: str,
        bug_class: str,
        severity: str,
        variables: list[str] | None = None,
        functions: list[str] | None = None,
    ) -> None:
        self.id = id
        self.statement = statement
        self.requires = requires          # regexes; ALL must match the source
        self.assertion = assertion        # Solidity over `target`
        self.rationale = rationale
        self.bug_class = bug_class
        self.severity = severity
        self.variables = variables or []
        self.functions = functions or []

    def applies(self, source: str) -> bool:
        return all(re.search(p, source) for p in self.requires)

    def to_invariant(self) -> Invariant:
        return Invariant(
            id=self.id,
            statement=self.statement,
            variables=list(self.variables),
            functions=list(self.functions),
            assertion=self.assertion,
            rationale=self.rationale,
            bug_class=self.bug_class,
            source="template",
            severity=self.severity,
        )


# Matches either an explicit getter (``totalSupply()``) or a public state
# variable declaration (``uint256 public totalSupply;``), which Solidity
# auto-exposes as a getter.
def _getter_pat(name: str) -> str:
    return rf"(?:\bpublic\b[^\n;{{}}]*\b{name}\b|\b{name}\s*\(\s*\))"


GENERIC_TEMPLATES: list[_Template] = [
    _Template(
        id="tmpl-solvency-1-1",
        statement="For a 1:1 vault, totalSupply must always equal totalAssets: "
                  "every share in existence is backed by exactly one unit of assets.",
        requires=[_getter_pat("totalSupply"), _getter_pat("totalAssets")],
        assertion="target.totalSupply() == target.totalAssets()",
        rationale="A mismatch means shares were minted without backing "
                  "(free mint / donation-inflation hole) or assets left "
                  "without burning shares — the classic vault accounting "
                  "desync behind share-price manipulation exploits.",
        bug_class="accounting-desync",
        severity="HIGH",
        variables=["totalSupply", "totalAssets"],
    ),
    _Template(
        id="tmpl-share-price-positive",
        statement="The reported share price must always be strictly positive.",
        requires=[_getter_pat("sharePrice")],
        assertion="target.sharePrice() > 0",
        rationale="A zero (or underflowing) share price breaks every "
                  "deposit/withdraw quote; attackers abuse rounding to push "
                  "it to zero and mint shares for free.",
        bug_class="rounding",
        severity="MEDIUM",
        variables=["sharePrice"],
    ),
    _Template(
        id="tmpl-owner-nonzero",
        statement="The contract owner must never be the zero address.",
        requires=[_getter_pat("owner")],
        assertion="target.owner() != address(0)",
        rationale="Ownership silently landing on address(0) bricks admin "
                  "functions or, worse, signals a broken access-control "
                  "handoff an attacker can race.",
        bug_class="access-control",
        severity="MEDIUM",
        variables=["owner"],
    ),
]


def template_invariants(source: str) -> list[Invariant]:
    """Return every generic template whose required getters exist in ``source``."""
    out: list[Invariant] = []
    for tmpl in GENERIC_TEMPLATES:
        try:
            if tmpl.applies(source):
                out.append(tmpl.to_invariant())
        except re.error as exc:  # a bad hand-written regex must not kill a scan
            LOGGER.warning("invariant template %s regex failed: %s", tmpl.id, exc)
    return out


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


def _build_user_prompt(contract_name: str, source: str) -> str:
    trimmed = source[:_MAX_SOURCE_CHARS]
    clipped = len(source) > _MAX_SOURCE_CHARS
    return (
        f"Contract `{contract_name}` (Solidity). Draft fuzzing invariants.\n\n"
        f"```solidity\n{trimmed}\n```\n"
        + ("(source truncated to 12000 chars)\n" if clipped else "")
        + "\nReturn the JSON array now."
    )


def _parse_llm_invariants(raw: str, *, existing_ids: set[str]) -> list[Invariant]:
    """Strictly validate model output; raise ValueError with a clear reason."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"LLM invariant output is not valid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise ValueError(
            f"LLM invariant output must be a JSON array, got {type(data).__name__}"
        )
    out: list[Invariant] = []
    for i, item in enumerate(data[:_MAX_LLM_INVARIANTS]):
        where = f"element {i}"
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

        def _str_list(key: str, item: dict[str, Any]) -> list[str]:
            val = item.get(key, [])
            if not isinstance(val, list):
                return []
            return [str(v)[:80] for v in val if isinstance(v, (str, int))][:16]

        out.append(
            Invariant(
                id=inv_id,
                statement=item["statement"].strip()[:500],
                variables=_str_list("variables", item),
                functions=_str_list("functions", item),
                assertion=assertion[:500],
                rationale=str(item.get("rationale", ""))[:500],
                bug_class=bug_class,
                source="llm",
                severity=severity,
            )
        )
    return out


def synthesize_invariants(
    contract_source: str,
    client: AnyRouterClient | None,
    config: Mapping[str, Any] | None,
    *,
    contract_name: str = "Target",
) -> SynthesisResult:
    """Draft invariants for ``contract_source``.

    Templates always run. The LLM layer runs only when ``client`` is active;
    when AI is inactive the function logs a LOUD static-only message and
    returns the templates alone — it never fails the scan.
    """
    result = SynthesisResult()
    templates = template_invariants(contract_source)
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
            _SYSTEM_PROMPT,
            _build_user_prompt(contract_name, contract_source),
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
        llm_invariants = _parse_llm_invariants(resp.content, existing_ids=existing_ids)
    except ValueError as exc:
        LOGGER.warning("rejecting malformed LLM invariant output: %s", exc)
        result.notes.append(f"LLM invariant output rejected ({exc}); using templates only.")
        return result

    result.invariants.extend(llm_invariants)
    result.ai_used = True
    LOGGER.info(
        "synthesized %d invariants for %s (%d template, %d LLM)",
        len(result.invariants), contract_name, len(templates), len(llm_invariants),
    )
    return result

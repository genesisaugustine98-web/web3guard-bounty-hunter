"""AI red-team layer: adversarial hypothesis generation + defense.

The standard AI analysis asks "is this code vulnerable?" — auditor framing
that invites checklist thinking and single-verdict answers. The red-team
layer instead asks "how would an attacker steal funds from this code?" and
runs a structured adversary process:

1. **Hypothesis generation** (attacker persona): produce N *diverse* attack
   hypotheses, each a concrete step-by-step attack path, not a vague
   category label. Forced diversity across attack primitives prevents five
   reentrancy-shaped variants of the same idea.
2. **Defense** (defender persona): each hypothesis is handed to a defender
   whose only job is to REFUTE it — to show, step by step, why the attack
   fails. Hypotheses that survive keep a "why the obvious defense fails"
   note, which is itself valuable signal.
3. **Exploitability triage**: survivors are ranked by concrete
   exploitability (capital required, prerequisites, profit) so the
   hypothesis-to-exploit loop spends its budget where it matters.

Cross-contract context (:class:`CrossContractContext`) feeds the attacker
richer material than a single chunk: inheritance, external call targets,
and shared state — because real exploits cross contract boundaries.

Everything degrades gracefully: with no AI client (or on call failure) the
analyzer returns an empty report instead of raising, so offline scans are
unaffected. All prompts avoid instruction-subversion phrasing so the
prompt-injection guard treats them as ordinary analysis traffic.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

LOGGER = logging.getLogger(__name__)

# Attack primitives the hypothesis generator must diversify across. The
# prompt demands each hypothesis use a *different* primitive from this
# list, which is the main defense against five variants of one idea.
ATTACK_PRIMITIVES = (
    "reentrancy (single-function)",
    "reentrancy (cross-function)",
    "reentrancy (read-only)",
    "access-control bypass",
    "privilege escalation",
    "price/oracle manipulation",
    "flash-loan assisted",
    "front-running / transaction ordering",
    "signature replay / malleability",
    "unchecked external call return",
    "integer arithmetic edge",
    "denial of service / griefing",
    "storage collision (proxy)",
    "delegatecall injection",
    "uninitialized implementation",
    "token standard violation (ERC-20/721/4626)",
    "rounding / precision drain",
    "permissionless initialization",
    "cross-contract state desync",
    "MEV / sandwich",
)


@dataclass
class AttackHypothesis:
    """One concrete, step-by-step attack hypothesis."""

    id: str
    title: str
    category: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    primitive: str  # one of ATTACK_PRIMITIVES (or "other")
    target_function: str
    attack_path: list[str] = field(default_factory=list)
    prerequisites: str = ""
    capital_required: str = "unknown"
    confidence: float = 0.5
    status: str = "proposed"  # proposed | refuted | surviving
    refutation: str = ""
    defense_failure_note: str = ""  # why the obvious defense doesn't work
    exploitability_score: float = 0.0  # 0-1, set by triage

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "primitive": self.primitive,
            "target_function": self.target_function,
            "attack_path": self.attack_path,
            "prerequisites": self.prerequisites,
            "capital_required": self.capital_required,
            "confidence": self.confidence,
            "status": self.status,
            "refutation": self.refutation,
            "defense_failure_note": self.defense_failure_note,
            "exploitability_score": self.exploitability_score,
        }


@dataclass
class RedTeamReport:
    """Result of a red-team pass over one chunk."""

    file: str
    language: str
    hypotheses: list[AttackHypothesis] = field(default_factory=list)
    llm_calls: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def survivors(self) -> list[AttackHypothesis]:
        return [h for h in self.hypotheses if h.status == "surviving"]

    @property
    def refuted(self) -> list[AttackHypothesis]:
        return [h for h in self.hypotheses if h.status == "refuted"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "language": self.language,
            "llm_calls": self.llm_calls,
            "errors": self.errors,
            "hypotheses": [h.to_dict() for h in self.hypotheses],
        }


class _ChatClient(Protocol):
    """Minimal interface the red-team layer needs from an AI client."""

    def chat(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int = ...,
        temperature: float = ...,
        role: str = ...,
        response_format: Any = ...,
    ) -> Any: ...


def _extract_json(text: str) -> dict[str, Any] | list[Any] | None:
    """Extract a JSON object or array from a chat response."""
    if not text:
        return None
    m = re.search(r"```json\s*(\{.*?\}|\[.*?\])\s*```", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:  # noqa: BLE001
            pass
    start_candidates = [i for i, c in enumerate(text) if c in "{["]
    for start in start_candidates:
        open_c, close_c = text[start], ("}" if text[start] == "{" else "]")
        depth = 0
        for i in range(start, len(text)):
            if text[i] == open_c:
                depth += 1
            elif text[i] == close_c:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except Exception:  # noqa: BLE001
                        break
    return None


class RedTeamPrompts:
    """Adversarial prompt templates.

    The attacker prompts frame the model as an exploiter, not an auditor.
    The defender prompts frame it as a hostile reviewer whose only goal is
    to kill the hypothesis. Both avoid instruction-subversion phrasing
    ("ignore previous instructions", "you are now...") so the injection
    guard does not flag them.
    """

    @staticmethod
    def attacker_system(language: str) -> str:
        return (
            "You are an elite smart-contract exploit developer. You study "
            f"{language} contracts the way a burglar studies a bank: every "
            "external function is a door, every state variable is a vault, "
            "every external call is a tunnel. Your goal is to find concrete "
            "ways to steal funds, brick the contract, or extract value that "
            "does not belong to you.\n\n"
            "Rules:\n"
            "- Think in ATTACK PATHS: numbered, concrete steps an attacker "
            "executes on-chain (deploy attacker contract, call f() with "
            "args, front-run tx, etc.). Vague category labels are useless.\n"
            "- Each hypothesis must use a DIFFERENT attack primitive. Do not "
            "submit five reentrancy variants.\n"
            "- Be specific about prerequisites: capital needed, ordering "
            "requirements, victim actions.\n"
            "- If a path requires a step you cannot justify from the code, "
            "say so and lower confidence instead of inventing it.\n"
            "- Respond with a single JSON object. No prose outside the JSON."
        )

    @staticmethod
    def hypothesis_user(
        code: str,
        context: str,
        n: int,
        file: str,
    ) -> str:
        primitives = "\n".join(f"- {p}" for p in ATTACK_PRIMITIVES)
        user = (
            f"Target file: {file}\n\n"
            "---- CODE ----\n"
            f"{code}\n"
            "---- END CODE ----\n"
        )
        if context.strip():
            user += (
                "\n---- CROSS-CONTRACT CONTEXT ----\n"
                f"{context}\n"
                "---- END CONTEXT ----\n"
            )
        user += (
            f"\nGenerate exactly {n} distinct attack hypotheses against this "
            "code. Each hypothesis must use a different attack primitive "
            "from this list:\n"
            f"{primitives}\n\n"
            "Respond with a single JSON object:\n"
            "{\n"
            '  "hypotheses": [\n'
            "    {\n"
            '      "title": "<short attack name>",\n'
            '      "category": "<vuln category>",\n'
            '      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",\n'
            '      "primitive": "<primitive from the list, or \'other\'>",\n'
            '      "target_function": "<function under attack>",\n'
            '      "attack_path": ["step 1: ...", "step 2: ...", ...],\n'
            '      "prerequisites": "<capital, ordering, victim actions>",\n'
            '      "capital_required": "<estimate or \'unknown\'>",\n'
            '      "confidence": 0.0-1.0\n'
            "    }\n"
            "  ]\n"
            "}\n"
            "If the code genuinely offers fewer than "
            f"{n} plausible attack paths, return fewer — do not pad with "
            "implausible ones. Low-confidence hypotheses are fine; mark "
            "their confidence honestly."
        )
        return user

    @staticmethod
    def defender_system() -> str:
        return (
            "You are a defensive smart-contract security auditor. A red-team "
            "attacker has proposed an attack hypothesis against a contract. "
            "Your ONLY job is to REFUTE it — to show, concretely and step by "
            "step, why the attack FAILS.\n\n"
            "Rules:\n"
            "- Attack each step of the proposed path. Quote the step, then "
            "explain why it does not work, citing the code.\n"
            "- Valid refutations: the step requires a privilege the attacker "
            "lacks, a check blocks it, the ordering is impossible, the math "
            "does not work out, the state cannot be as assumed.\n"
            "- INVALID refutations: 'this seems unlikely', 'auditors would "
            "catch this', 'the team is reputable'. Only code-grounded "
            "arguments count.\n"
            "- If you CANNOT refute a step, say so explicitly: "
            "'STEP N SURVIVES: <why>'.\n"
            "- Verdict 'refuted' only if EVERY step fails or the chain "
            "breaks. Verdict 'surviving' otherwise.\n"
            "- Respond with a single JSON object. No prose outside the JSON."
        )

    @staticmethod
    def defense_user(hypothesis: AttackHypothesis, code: str) -> str:
        path = "\n".join(
            f"Step {i + 1}: {s}" for i, s in enumerate(hypothesis.attack_path)
        )
        return (
            "Attack hypothesis to refute:\n"
            f"Title: {hypothesis.title}\n"
            f"Target function: {hypothesis.target_function}\n"
            f"Prerequisites: {hypothesis.prerequisites}\n"
            f"Attack path:\n{path}\n\n"
            "---- CODE ----\n"
            f"{code}\n"
            "---- END CODE ----\n\n"
            "Refute this hypothesis step by step. Respond with a single "
            "JSON object:\n"
            "{\n"
            '  "verdict": "refuted" | "surviving",\n'
            '  "step_analysis": [\n'
            '    {"step": 1, "outcome": "fails" | "survives", '
            '"reason": "<code-grounded reason>"}\n'
            "  ],\n"
            '  "refutation_summary": "<one paragraph, empty if surviving>",\n'
            '  "defense_failure_note": "<if surviving: why the obvious '
            'defense does not work>"\n'
            "}"
        )

    @staticmethod
    def triage_system() -> str:
        return (
            "You are a smart-contract exploit triage analyst. Given attack "
            "hypotheses that survived defensive review, score each one's "
            "real-world exploitability: how likely is an actual attacker to "
            "execute it profitably?\n\n"
            "Consider: capital required vs. profit, prerequisite realism "
            "(does it need a victim to act first?), ordering feasibility "
            "(front-running windows), competition (would MEV bots beat the "
            "attacker to it?), and code-grounded certainty.\n\n"
            "Respond with a single JSON object. No prose outside the JSON."
        )

    @staticmethod
    def triage_user(hypotheses: list[AttackHypothesis]) -> str:
        items = "\n".join(
            f"- id {h.id}: {h.title} | target {h.target_function} | "
            f"prereqs: {h.prerequisites} | capital: {h.capital_required} | "
            f"confidence {h.confidence:.2f} | "
            f"path: {' -> '.join(h.attack_path[:4])}"
            + (" ..." if len(h.attack_path) > 4 else "")
            for h in hypotheses
        )
        return (
            "Score the exploitability of each surviving hypothesis "
            "(0.0 = theoretical only, 1.0 = trivially exploitable today):\n\n"
            f"{items}\n\n"
            "Respond with a single JSON object:\n"
            "{\n"
            '  "scores": [\n'
            '    {"id": "<hypothesis id>", "exploitability": 0.0-1.0, '
            '"rationale": "<one sentence>"}\n'
            "  ]\n"
            "}"
        )


class RedTeamAnalyzer:
    """Orchestrates the attacker -> defender -> triage loop."""

    DEFAULTS: dict[str, Any] = {
        "redteam_max_hypotheses": 5,
        "redteam_enable_defense": True,
        "redteam_enable_triage": True,
        "redteam_max_code_chars": 12000,
        "redteam_max_context_chars": 6000,
    }

    def __init__(
        self,
        ai_client: _ChatClient | None,
        config: dict[str, Any] | None = None,
    ) -> None:
        self.client = ai_client
        self.config = {**self.DEFAULTS, **(config or {})}

    # ---- public API ---------------------------------------------------

    def analyze(
        self,
        code: str,
        *,
        file: str = "",
        language: str = "solidity",
        context: str = "",
    ) -> RedTeamReport:
        """Run the full red-team loop over one code chunk."""
        report = RedTeamReport(file=file, language=language)
        if self.client is None:
            report.errors.append("no AI client configured")
            return report
        code = code[: int(self.config["redteam_max_code_chars"])]
        context = context[: int(self.config["redteam_max_context_chars"])]

        hypotheses = self._generate_hypotheses(code, context, file, language, report)
        report.hypotheses.extend(hypotheses)

        if self.config["redteam_enable_defense"]:
            for h in hypotheses:
                self._defend(h, code, report)

        survivors = [h for h in hypotheses if h.status == "surviving"]
        if survivors and self.config["redteam_enable_triage"]:
            self._triage(survivors, report)
        return report

    # ---- stages --------------------------------------------------------

    def _generate_hypotheses(
        self,
        code: str,
        context: str,
        file: str,
        language: str,
        report: RedTeamReport,
    ) -> list[AttackHypothesis]:
        client = self.client
        assert client is not None  # analyze() guards this
        n = int(self.config["redteam_max_hypotheses"])
        system = RedTeamPrompts.attacker_system(language)
        user = RedTeamPrompts.hypothesis_user(code, context, n, file)
        try:
            resp = client.chat(
                system, user,
                max_tokens=2500, temperature=0.4, role="redteam_attack",
            )
            report.llm_calls += 1
        except Exception as e:  # noqa: BLE001
            report.errors.append(f"hypothesis generation failed: {e}")
            return []
        parsed = _extract_json(getattr(resp, "content", ""))
        if not isinstance(parsed, dict):
            report.errors.append("hypothesis generation: no JSON in response")
            return []
        out: list[AttackHypothesis] = []
        for raw in parsed.get("hypotheses", [])[:n]:
            if not isinstance(raw, dict):
                continue
            try:
                confidence = float(raw.get("confidence", 0.5))
            except (TypeError, ValueError):
                confidence = 0.5
            path = raw.get("attack_path") or []
            out.append(AttackHypothesis(
                id=f"rt-{uuid.uuid4().hex[:8]}",
                title=str(raw.get("title", "untitled"))[:200],
                category=str(raw.get("category", ""))[:80],
                severity=str(raw.get("severity", "MEDIUM")).upper(),
                primitive=str(raw.get("primitive", "other"))[:80],
                target_function=str(raw.get("target_function", ""))[:120],
                attack_path=[str(s)[:500] for s in path][:12],
                prerequisites=str(raw.get("prerequisites", ""))[:500],
                capital_required=str(raw.get("capital_required", "unknown"))[:120],
                confidence=max(0.0, min(1.0, confidence)),
            ))
        return out

    def _defend(
        self,
        hypothesis: AttackHypothesis,
        code: str,
        report: RedTeamReport,
    ) -> None:
        client = self.client
        assert client is not None  # analyze() guards this
        system = RedTeamPrompts.defender_system()
        user = RedTeamPrompts.defense_user(hypothesis, code)
        try:
            resp = client.chat(
                system, user,
                max_tokens=1500, temperature=0.0, role="redteam_defense",
            )
            report.llm_calls += 1
        except Exception as e:  # noqa: BLE001
            report.errors.append(f"defense failed for {hypothesis.id}: {e}")
            return
        parsed = _extract_json(getattr(resp, "content", ""))
        if not isinstance(parsed, dict):
            report.errors.append(f"defense: no JSON for {hypothesis.id}")
            return
        verdict = str(parsed.get("verdict", "")).lower()
        if verdict == "refuted":
            hypothesis.status = "refuted"
            hypothesis.refutation = str(
                parsed.get("refutation_summary", ""))[:1000]
        else:
            # Anything that is not an explicit refutation keeps the
            # hypothesis alive — the defender failed to kill it.
            hypothesis.status = "surviving"
            hypothesis.defense_failure_note = str(
                parsed.get("defense_failure_note", ""))[:1000]

    def _triage(
        self,
        survivors: list[AttackHypothesis],
        report: RedTeamReport,
    ) -> None:
        client = self.client
        assert client is not None  # analyze() guards this
        system = RedTeamPrompts.triage_system()
        user = RedTeamPrompts.triage_user(survivors)
        try:
            resp = client.chat(
                system, user,
                max_tokens=1200, temperature=0.0, role="redteam_triage",
            )
            report.llm_calls += 1
        except Exception as e:  # noqa: BLE001
            report.errors.append(f"triage failed: {e}")
            return
        parsed = _extract_json(getattr(resp, "content", ""))
        if not isinstance(parsed, dict):
            report.errors.append("triage: no JSON in response")
            return
        by_id = {h.id: h for h in survivors}
        for raw in parsed.get("scores", []):
            if not isinstance(raw, dict):
                continue
            h = by_id.get(str(raw.get("id", "")))
            if h is None:
                continue
            try:
                score = float(raw.get("exploitability", 0.0))
            except (TypeError, ValueError):
                score = 0.0
            h.exploitability_score = max(0.0, min(1.0, score))
        # Sort survivors by exploitability so the exploit loop spends its
        # budget on the most practical attacks first.
        survivors.sort(key=lambda h: h.exploitability_score, reverse=True)


class CrossContractContext:
    """Build attack-relevant cross-contract context for a target file.

    Real exploits cross contract boundaries: a vault's `deposit()` is only
    interesting together with the token it pulls and the oracle it reads.
    This builder extracts, for one file:

    - inheritance chain (parent contracts),
    - external call targets (addresses/interfaces called),
    - shared state (state variables written by multiple contracts),
    - imported interfaces (function signatures available to call).

    It is heuristic and offline — no compilation needed.
    """

    _IMPORT_RE = re.compile(
        r"""import\s+(?:[^'"]*from\s+)?['"]([^'"]+)['"]""")
    _INHERIT_RE = re.compile(
        r"contract\s+(\w+)\s+is\s+([^{]+)\{")
    _EXTCALL_RE = re.compile(
        r"(\w+)\s*\.\s*(call|delegatecall|staticcall)\s*[\({]")
    _IFACECALL_RE = re.compile(
        r"\b([A-Z]\w*)\s*\(\s*(?:address\s*\()?0x[0-9a-fA-F]{40}")
    _STATEVAR_RE = re.compile(
        r"^\s*(?:uint\d*|int\d*|bool|address|bytes\d*|mapping\s*\(|string)"
        r"\s+(?:public\s+|private\s+|internal\s+)?(\w+)",
        re.MULTILINE)

    def __init__(self, target_root: Path | str) -> None:
        self.root = Path(target_root)

    def for_file(self, file_path: Path | str, code: str) -> str:
        """Return a compact cross-contract context block."""
        sections: list[str] = []
        inheritance = self._inheritance(code)
        if inheritance:
            sections.append(
                "Inherits from: " + ", ".join(inheritance))
        imports = self._IMPORT_RE.findall(code)
        if imports:
            resolved = [self._resolve_import(str(file_path), i)
                        for i in imports[:8]]
            sections.append(
                "Imports: " + ", ".join(r for r in resolved if r))
        ext_calls = sorted(set(self._EXTCALL_RE.findall(code)))
        if ext_calls:
            sections.append(
                "Low-level external calls on: "
                + ", ".join(f"{t}.{k}" for t, k in ext_calls[:10]))
        interfaces = self._interface_summaries(code)
        if interfaces:
            sections.append("External interfaces used:\n" + interfaces)
        shared = self._shared_state(str(file_path), code)
        if shared:
            sections.append(
                "State also touched by sibling contracts: "
                + ", ".join(shared[:10]))
        return "\n".join(sections)

    # ---- helpers ------------------------------------------------------

    def _inheritance(self, code: str) -> list[str]:
        out: list[str] = []
        for _name, parents in self._INHERIT_RE.findall(code):
            for p in parents.split(","):
                p = p.strip().split("(")[0].strip()
                if p and p not in out:
                    out.append(p)
        return out[:8]

    def _resolve_import(self, file_path: str, imp: str) -> str:
        if imp.startswith("."):
            base = (self.root / file_path).parent
            try:
                return str((base / imp).resolve().relative_to(
                    self.root.resolve()))
            except Exception:  # noqa: BLE001
                return imp
        return imp

    def _interface_summaries(self, code: str) -> str:
        """Summarize interface functions called on external contracts."""
        # Map variable name -> interface type from declarations like
        # `IERC20 public token;` so `token.transfer(` resolves to
        # `IERC20.transfer`.
        var_types: dict[str, str] = {}
        for m in re.finditer(
                r"\b([A-Z]\w*)\s+(?:public\s+|private\s+|internal\s+)?"
                r"(\w+)\s*(?:=|;)", code):
            var_types[m.group(2)] = m.group(1)
        seen: list[str] = []
        # `Iface(addr).fn(` style.
        for iface, fn in re.findall(
                r"\b([A-Z]\w+)\s*\(\s*[^)]*\)\s*\.\s*(\w+)\s*\(", code):
            item = f"{iface}.{fn}"
            if item not in seen:
                seen.append(item)
        # `token.fn(` where token was declared with an interface type.
        for var, fn in re.findall(r"\b(\w+)\s*\.\s*(\w+)\s*\(", code):
            iface = var_types.get(var)
            if iface:
                item = f"{iface}.{fn}"
                if item not in seen:
                    seen.append(item)
        return "\n".join(f"  - {s}" for s in seen[:15])

    def _shared_state(self, file_path: str, code: str) -> list[str]:
        """State variable names also present in sibling contracts."""
        own_vars = set(self._STATEVAR_RE.findall(code))
        if not own_vars:
            return []
        shared: list[str] = []
        try:
            siblings = [
                p for p in self.root.rglob("*.sol")
                if str(p) != str(self.root / file_path)
                and "test" not in str(p).lower()
                and "lib" not in str(p).lower()
            ][:20]
        except Exception:  # noqa: BLE001
            return []
        for sib in siblings:
            try:
                sib_vars = set(
                    self._STATEVAR_RE.findall(
                        sib.read_text(errors="ignore")))
            except OSError:
                continue
            for v in own_vars & sib_vars:
                if v not in shared:
                    shared.append(v)
        return shared

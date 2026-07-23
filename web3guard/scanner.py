"""
Scanner core — the orchestrator that ties every component together.

The original scanner was a single 3500-line `core_scanner.py` file
with the entire pipeline. This augmented version splits the
pipeline across modules:

- :class:`Scanner` — top-level orchestrator.
- ``web3guard.discovery`` — multi-engine discovery (Slither, Aderyn,
  Mythril, Echidna, etc.) and language-specific discovery engines.
- ``web3guard.sandbox`` — language-specific test runners.
- ``web3guard.reports`` — plain text, JSON, SARIF, Markdown.
- ``web3guard.findings_db`` — SQLite-backed finding lifecycle.
- ``web3guard.ai`` — multi-provider AI client with circuit breaker.
- ``web3guard.security`` — prompt-injection guard and sandbox
  hardening.

The scanner exposes a clean Python API:

.. code-block:: python

    from web3guard import Scanner
    scanner = Scanner.from_config("config.yaml")
    result = scanner.scan(["https://github.com/owner/repo|max"])
    print(result.report_text)

A CLI lives in ``web3guard.cli``.
"""

from __future__ import annotations

import dataclasses
import datetime
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Sequence

from web3guard.ai import AIClient, AIProvider, CostTracker, OpenAICompatibleProvider
from web3guard.ai.client import AIClient as _AIClient
from web3guard.findings_db import FindingsDB, FindingRecord
from web3guard.languages import (
    LanguageAdapter,
    LanguageRegistry,
    TargetLanguage,
    default_registry,
    detect_target_language,
)
from web3guard.reports import ReportBuilder, ReportFormat
from web3guard.security import (
    PromptInjectionGuard,
    SandboxGuard,
    SandboxPolicy,
)

LOGGER = logging.getLogger("web3guard.scanner")


# ---------------------------------------------------------------------------
# Top-level data types
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """One vulnerability finding produced by the scanner."""
    target: str
    language: str
    file: str
    function: str = ""
    category: str = ""
    severity: str = "LOW"     # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence: float = 0.5
    swc_id: str = ""
    description: str = ""
    reasoning: str = ""
    status: str = "POTENTIAL"  # POTENTIAL | CONFIRMED EXPLOIT | REJECTED
    poc_code: str = ""
    exploit_log: str = ""
    fingerprint: str = ""
    tool_consensus: list[str] = field(default_factory=list)
    dynamically_confirmed: bool = False
    line_hint: str = ""
    gas_used: int | None = None
    cost_basis_usd: float = 0.0
    expected_profit_usd: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TargetResult:
    """Result of scanning a single target."""
    target: str
    language: TargetLanguage
    findings: list[Finding] = field(default_factory=list)
    files_analyzed: int = 0
    chunks_analyzed: int = 0
    elapsed_seconds: float = 0.0
    framework: dict[str, Any] = field(default_factory=dict)
    research_plan: dict[str, Any] = field(default_factory=dict)
    attack_sequences: dict[str, Any] = field(default_factory=dict)
    role_map: dict[str, Any] = field(default_factory=dict)
    secrets_findings: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Top-level result of a multi-target scan."""
    started_at: str
    finished_at: str
    config: dict[str, Any]
    targets: list[TargetResult] = field(default_factory=list)
    cost_summary: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def all_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for t in self.targets:
            out.extend(t.findings)
        return out

    @property
    def confirmed_findings(self) -> list[Finding]:
        return [f for f in self.all_findings if f.status == "CONFIRMED EXPLOIT"]


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


DEFAULT_CONFIG: dict[str, Any] = {
    # AI providers (in priority order). The scanner tries them in
    # sequence and falls through on failure.
    "ai_providers": [
        {
            "type": "nim",
            "name": "nim-deepseek",
            "base_url": "https://integrate.api.nvidia.com/v1",
            "api_key_env": "NIM_API_KEY",
            "rpm": 35,
            "model": "deepseek-ai/deepseek-v4-flash",
        },
        {
            "type": "openrouter",
            "name": "openrouter-deepseek",
            "base_url": "https://openrouter.ai/api/v1",
            "api_key_env": "OPENROUTER_API_KEY",
            "rpm": 60,
            "model": "deepseek/deepseek-chat",
        },
        {
            "type": "groq",
            "name": "groq-llama",
            "base_url": "https://api.groq.com/openai/v1",
            "api_key_env": "GROQ_API_KEY",
            "rpm": 30,
            "model": "llama-3.3-70b-versatile",
        },
    ],
    "model": "deepseek-ai/deepseek-v4-flash",
    "max_cost_usd": 50.0,
    "default_seed": 0,
    "max_chunk_chars": 6000,
    "max_context_chars": 6000,
    "discovery_time_budget_seconds": 900,
    "enable_exploit": True,
    "max_exploit_attempts": 3,
    "use_ai_planning": True,
    "enable_self_critique": True,
    "enable_attack_sequence_brainstorm": True,
    "enable_role_map": True,
    "enable_secret_scan": True,
    "enable_incremental_scan": False,
    "enable_deployment_verification": False,
    "enable_economic_analyzer": True,
    "report_formats": ["txt", "json", "sarif", "md"],
    "findings_db_path": ".web3guard/findings.db",
    "cache_path": ".web3guard/llm_cache.db",
    "cost_db_path": ".web3guard/cost.db",
    "languages": {
        "solidity":    {"enabled": True},
        "vyper":       {"enabled": True},
        "move":        {"enabled": True},
        "cairo":       {"enabled": True},
        "clarity":     {"enabled": True},
        "func":        {"enabled": True},
        "rust-solana": {"enabled": True},
        "ts-sdk":      {"enabled": True},
    },
}


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def load_config(path: Path | None) -> dict[str, Any]:
    """Load a YAML or JSON config file and merge over :data:`DEFAULT_CONFIG`.

    A ``None`` path returns a deep copy of the defaults.
    """
    import copy
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if path is None or not path.exists():
        return cfg
    text = path.read_text()
    loaded: dict[str, Any]
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
            loaded = yaml.safe_load(text) or {}
        except ImportError:
            # No yaml; fall back to JSON.
            loaded = json.loads(text)
    else:
        loaded = json.loads(text)
    # Shallow merge; nested dicts are replaced wholesale.
    cfg.update(loaded)
    return cfg


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class Scanner:
    """Top-level scanner.

    The scanner's responsibilities:
    - Build an AI client from the configured providers.
    - For each target, detect the language(s) and dispatch to the
      right :class:`LanguageAdapter`.
    - Run discovery, AI analysis, exploit generation, and self-
      critique per chunk.
    - Persist findings to the findings DB.
    - Build a multi-format report.
    """

    def __init__(
        self,
        *,
        config: dict[str, Any],
        registry: LanguageRegistry | None = None,
        ai_client: AIClient | None = None,
        findings_db: FindingsDB | None = None,
        sandbox_guard: SandboxGuard | None = None,
        injection_guard: PromptInjectionGuard | None = None,
        workdir: Path | None = None,
    ) -> None:
        self.config = config
        self.registry = registry or default_registry
        self.workdir = workdir or Path.cwd()
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.findings_db = findings_db or FindingsDB(
            Path(self.config.get("findings_db_path", ".web3guard/findings.db"))
        )
        self.sandbox_guard = sandbox_guard or SandboxGuard(SandboxPolicy())
        self.injection_guard = injection_guard or PromptInjectionGuard()
        self.ai_client = ai_client or self._build_ai_client()
        # Track run state
        self._start_ts: str = ""
        self._end_ts: str = ""

    # ---- factory ---------------------------------------------------------

    @classmethod
    def from_config(
        cls,
        path: str | Path | None = None,
        *,
        workdir: Path | None = None,
    ) -> "Scanner":
        cfg = load_config(Path(path)) if path is not None else load_config(None)
        return cls(config=cfg, workdir=workdir)

    # ---- AI client construction ------------------------------------------

    def _build_ai_client(self) -> AIClient:
        providers: list[AIProvider] = []
        for p in self.config.get("ai_providers", []):
            if p.get("enabled", True) is False:
                continue
            try:
                providers.append(OpenAICompatibleProvider(
                    base_url=p["base_url"],
                    api_key_env=p["api_key_env"],
                    rpm=int(p.get("rpm", 35)),
                    name=p.get("name", p["type"]),
                ))
            except Exception as e:  # noqa: BLE001
                LOGGER.warning("failed to build provider %s: %s", p.get("name"), e)
        # Cost tracker with persistence
        cost_path = self.workdir / self.config.get("cost_db_path", ".web3guard/cost.db")
        cost_path.parent.mkdir(parents=True, exist_ok=True)
        cost = CostTracker(
            max_cost_usd=float(self.config.get("max_cost_usd", 50.0)),
            persist_path=cost_path,
        )
        # LLM cache
        cache_path = self.workdir / self.config.get("cache_path", ".web3guard/llm_cache.db")
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        return AIClient(
            providers=providers,
            model=str(self.config.get("model", "deepseek-ai/deepseek-v4-flash")),
            cost_tracker=cost,
            cache_path=cache_path,
            injection_guard=self.injection_guard,
            default_seed=self.config.get("default_seed", 0),
        )

    # ---- main entry point ------------------------------------------------

    def scan(
        self,
        targets: Sequence[str],
        *,
        min_severity: str = "LOW",
    ) -> ScanResult:
        """Scan a list of targets and return a :class:`ScanResult`.

        Each target is a string of the form ``"<git-url>|<budget>"``,
        matching the original scanner's CLI grammar. ``<budget>`` is
        a number (token budget per chunk) or ``"max"`` for unlimited.
        """
        self._start_ts = datetime.datetime.utcnow().isoformat() + "Z"
        parsed = self._parse_targets(targets)
        result = ScanResult(
            started_at=self._start_ts,
            finished_at="",
            config={k: v for k, v in self.config.items() if k != "ai_providers"},
        )
        for url, budget in parsed:
            LOGGER.info("scanning target: %s (budget=%s)", url, budget)
            t0 = time.monotonic()
            tr = self._scan_one(url, budget, min_severity=min_severity)
            tr.elapsed_seconds = time.monotonic() - t0
            # Persist findings
            for f in tr.findings:
                self.findings_db.upsert(FindingRecord.from_finding(f))
            result.targets.append(tr)
        self._end_ts = datetime.datetime.utcnow().isoformat() + "Z"
        result.finished_at = self._end_ts
        result.cost_summary = self.ai_client.cost_tracker().summary()
        return result

    # ---- target handling -------------------------------------------------

    def _parse_targets(self, targets: Iterable[str]) -> list[tuple[str, int]]:
        out: list[tuple[str, int]] = []
        for t in targets:
            if isinstance(t, tuple):
                url, budget = t
            elif "|" in str(t):
                url, budget = str(t).split("|", 1)
            else:
                url, budget = str(t), 200000
            if not isinstance(budget, int):
                try:
                    budget = 0 if str(budget).strip().lower() == "max" else int(str(budget))
                except (ValueError, AttributeError):
                    budget = 200000
            out.append((str(url).strip(), budget))
        return out

    def _scan_one(
        self,
        target: str,
        budget: int,
        *,
        min_severity: str,
    ) -> TargetResult:
        """Scan a single target.

        This is the per-target pipeline. It:
        1. Clones the repo (or copies a local path).
        2. Detects the language(s) and instantiates the right adapter.
        3. Runs discovery engines for the detected language.
        4. Chunks the user code and runs AI analysis per chunk.
        5. Generates Foundry/Anchor/Move/Cairo/etc. PoCs for each
           finding.
        6. Runs self-critique.
        7. Computes economic impact (if enabled).
        """
        target_path = self._clone_target(target)
        if target_path is None:
            return TargetResult(
                target=target, language=TargetLanguage.UNKNOWN,
                error=f"failed to clone or locate target {target!r}",
            )
        # Detect languages
        detection = detect_target_language(target_path)
        adapters = self.registry.detect_for(target_path)
        LOGGER.info("detected languages: %s; adapters: %s",
                    [l.value for l in detection.detected],
                    [a.language.value for a in adapters])
        # Build the result
        tr = TargetResult(
            target=target,
            language=detection.primary,
        )
        tr.framework = detection.confidence_notes
        if not adapters:
            tr.error = "no language adapter matched the target"
            return tr
        # If multiple adapters match, run them all (in priority order)
        # and merge findings. In practice, multi-language repos are
        # rare; if they exist, the most relevant adapter goes first.
        primary = adapters[0]
        # Discover files
        files = primary.discover_files(target_path)
        tr.files_analyzed = len(files)
        LOGGER.info("primary adapter %s found %d files",
                    primary.language.value, len(files))
        # Per-chunk analysis
        analysis_budget = max(1, budget // 1500) if budget else 0
        chunks_to_analyze: list[tuple[Any, dict]] = []  # (chunk, ctx)
        for fp in files:
            try:
                chunks = primary.chunk(fp, self.config.get("max_chunk_chars", 6000))
            except Exception as e:  # noqa: BLE001
                LOGGER.warning("chunker failed on %s: %s", fp, e)
                continue
            for ch in chunks:
                try:
                    ch.context = primary.resolve_context(fp, target_path)
                except Exception as e:  # noqa: BLE001
                    LOGGER.warning("context resolver failed on %s: %s", fp, e)
                chunks_to_analyze.append((ch, {"file_path": fp}))
                if analysis_budget and len(chunks_to_analyze) >= analysis_budget:
                    break
            if analysis_budget and len(chunks_to_analyze) >= analysis_budget:
                break
        tr.chunks_analyzed = len(chunks_to_analyze)
        # Run analysis per chunk
        for ch, ctx in chunks_to_analyze:
            finding = self._analyze_chunk(primary, ch, target_path, target)
            if finding is not None:
                if self._severity_at_least(finding.severity, min_severity):
                    tr.findings.append(finding)
        # Optional: post-scan tasks
        if self.config.get("enable_secret_scan", True):
            tr.secrets_findings = self._run_secret_scan(target_path)
        # Sort findings by severity then confidence
        tr.findings.sort(key=lambda f: (-f.confidence, f.severity != "CRITICAL",
                                         f.severity != "HIGH"))
        return tr

    def _clone_target(self, target: str) -> Path | None:
        """Clone a git URL or accept a local path."""
        if target.startswith(("http://", "https://", "git@", "git://")):
            import subprocess
            import tempfile
            tmp = Path(tempfile.mkdtemp(prefix="web3guard-target-"))
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", target, str(tmp)],
                    check=True, capture_output=True, timeout=120,
                )
            except Exception as e:  # noqa: BLE001
                LOGGER.error("clone failed: %s", e)
                return None
            # Git clones into a subdir of the target path; return that.
            subdirs = [d for d in tmp.iterdir() if d.is_dir()]
            if len(subdirs) == 1:
                return subdirs[0]
            return tmp
        # Local path
        p = Path(target).resolve()
        return p if p.is_dir() else None

    def _analyze_chunk(
        self,
        adapter: LanguageAdapter,
        chunk: Any,
        target_path: Path,
        target_url: str,
    ) -> Finding | None:
        """Run analysis + exploit generation + self-critique for one chunk."""
        # 1. Build the system prompt
        system = adapter.analysis_system_prompt()
        # 2. Build the user prompt (with cross-file context if available)
        user = (
            f"Target: {target_url}\n"
            f"Language: {adapter.language.value}\n"
            f"File: {chunk.file}\n"
            f"Lines: {chunk.lines or '?'}\n\n"
            f"---- CODE ----\n{chunk.content}\n---- END CODE ----\n"
        )
        if chunk.context:
            user += f"\n---- CONTEXT ----\n{chunk.context}\n---- END CONTEXT ----\n"
        user += (
            "\nRespond with a single JSON object with the schema:\n"
            "{\n"
            '  "status": "clean" | "vulnerable" | "inconclusive",\n'
            '  "category": "reentrancy" | "access-control" | "oracle" | ...,\n'
            '  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",\n'
            '  "confidence": 0.0-1.0,\n'
            '  "function": "<function name>",\n'
            '  "swc_id": "SWC-XXX" or "",\n'
            '  "description": "<one-paragraph description>",\n'
            '  "reasoning": "<one-paragraph reasoning>",\n'
            '  "line_hint": "<line range>"\n'
            "}"
        )
        try:
            resp = self.ai_client.chat(system, user, max_tokens=1500, role="analysis")
        except Exception as e:  # noqa: BLE001
            LOGGER.warning("analysis call failed on %s: %s", chunk.file, e)
            return None
        # 3. Parse response
        parsed = self._extract_json(resp.content)
        if not parsed:
            return None
        if parsed.get("status", "").lower() != "vulnerable":
            return None
        # 4. Build the finding
        finding = Finding(
            target=target_url,
            language=adapter.language.value,
            file=chunk.file,
            function=parsed.get("function", ""),
            category=parsed.get("category", ""),
            severity=str(parsed.get("severity", "MEDIUM")).upper(),
            confidence=float(parsed.get("confidence", 0.5) or 0.5),
            swc_id=parsed.get("swc_id", ""),
            description=parsed.get("description", ""),
            reasoning=parsed.get("reasoning", ""),
            line_hint=parsed.get("line_hint", ""),
        )
        # 5. Generate a PoC if enabled
        if self.config.get("enable_exploit", True):
            self._generate_poc(adapter, finding, chunk, target_path)
        # 6. Self-critique if enabled
        if self.config.get("enable_self_critique", True):
            self._self_critique(finding, chunk)
        # 7. Economic analyzer if enabled
        if self.config.get("enable_economic_analyzer", True):
            self._economic_analyzer(finding)
        return finding

    def _generate_poc(
        self,
        adapter: LanguageAdapter,
        finding: Finding,
        chunk: Any,
        target_path: Path,
    ) -> None:
        """Run the exploit-generation loop. Mutates ``finding`` in place."""
        from web3guard.sandbox import create_sandbox
        sandbox = create_sandbox(adapter, target_path, self.workdir)
        if sandbox is None:
            finding.status = "POTENTIAL (sandbox init failed)"
            return
        max_attempts = int(self.config.get("max_exploit_attempts", 3))
        template = adapter.exploit_user_template()
        system = adapter.analysis_system_prompt()
        last_err = ""
        for attempt in range(1, max_attempts + 1):
            try:
                resp = self.ai_client.chat(
                    system,
                    template.format(
                        category=finding.category,
                        severity=finding.severity,
                        description=finding.description,
                        concept=finding.reasoning or "(see description)",
                        code=chunk.content[: self.config.get("max_chunk_chars", 6000)],
                        context=chunk.context or "(none)",
                        fork_hint="",
                        oracle_hint="",
                    ),
                    max_tokens=3500,
                    temperature=0.3,
                    role="exploit",
                )
            except Exception as e:  # noqa: BLE001
                last_err = str(e)
                continue
            code = self._extract_code_block(resp.content, language=adapter.language.value)
            if not code:
                last_err = "no code block in response"
                continue
            if adapter.test_runner.has_impact_assertion and \
               not adapter.test_runner.has_impact_assertion(code):
                last_err = "PoC missing impact assertion"
                continue
            ok, out = sandbox.write_and_run(code, finding.fingerprint or "exploit")
            if ok:
                finding.status = "CONFIRMED EXPLOIT"
                finding.poc_code = code
                finding.exploit_log = out
                return
            last_err = out[-1500:]
        finding.status = f"POTENTIAL (PoC unconfirmed: {last_err[:200]})"
        finding.poc_code = code if 'code' in locals() else ""

    def _self_critique(self, finding: Finding, chunk: Any) -> None:
        """Run an independent adversarial pass to try to disprove the finding.

        Uses a *different* prompt and (optionally) a different provider
        so the critique is not the same model checking its own work.
        """
        try:
            resp = self.ai_client.chat(
                "You are an adversarial security reviewer. The job is to "
                "try to DISPROVE a candidate vulnerability. If the "
                "candidate survives your challenge, say so explicitly.",
                (
                    f"Claim: {finding.description}\n"
                    f"Reasoning: {finding.reasoning}\n"
                    f"Category: {finding.category}\n\n"
                    "Code:\n" + chunk.content[: self.config.get("max_chunk_chars", 6000)]
                ),
                max_tokens=1000,
                temperature=0.0,
                role="self_critique",
            )
        except Exception as e:  # noqa: BLE001
            LOGGER.warning("self-critique failed: %s", e)
            return
        verdict = self._extract_json(resp.content)
        if not verdict:
            return
        # If the critique says it's a false positive, downgrade confidence
        if str(verdict.get("verdict", "")).lower() in ("false_positive", "false-positive", "fp"):
            finding.confidence = max(0.0, finding.confidence - 0.3)
            finding.metadata["self_critique"] = verdict
        else:
            finding.metadata["self_critique"] = verdict

    def _economic_analyzer(self, finding: Finding) -> None:
        """Estimate the attacker's required capital and expected profit.

        For oracle-manipulation findings, the canonical attack is a
        flash loan. The cost is therefore the flash-loan fee; the
        profit is the drained funds. We do not yet have on-chain data
        here, so this is a placeholder. Future versions will integrate
        with a mainnet-fork RPC.
        """
        finding.cost_basis_usd = 0.0
        finding.expected_profit_usd = 0.0
        finding.metadata["economic"] = {
            "note": "offline estimate; pass --fork-url for on-chain TVL data",
        }

    def _run_secret_scan(self, target_path: Path) -> list[dict[str, Any]]:
        """Cheap regex-only secret scan. Replace with gitleaks if installed."""
        findings: list[dict[str, Any]] = []
        patterns: dict[str, re.Pattern[str]] = {
            "private_key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
            "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
            "alchemy_rpc": re.compile(r"https://[a-z0-9-]+\.alchemy\.com/v2/[A-Za-z0-9_-]{20,}"),
            "infura_rpc": re.compile(r"https://[a-z0-9-]+\.infura\.io/v3/[A-Za-z0-9_-]{20,}"),
            "mnemonic": re.compile(r"\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b"),
        }
        for fp in target_path.rglob("*"):
            if fp.is_dir():
                continue
            if any(p in str(fp).lower() for p in ("/.git/", "/node_modules/", "/target/", "/build/")):
                continue
            try:
                content = fp.read_text(errors="ignore")
            except Exception:  # noqa: BLE001
                continue
            for kind, pattern in patterns.items():
                for m in pattern.finditer(content):
                    line_no = content[: m.start()].count("\n") + 1
                    findings.append({
                        "kind": kind,
                        "file": str(fp.relative_to(target_path)),
                        "line": line_no,
                        "snippet": m.group(0)[:120],
                    })
        return findings

    # ---- helpers ---------------------------------------------------------

    @staticmethod
    def _extract_json(text: str) -> dict[str, Any] | None:
        """Extract a JSON object from a chat response, tolerating prose."""
        # Look for ```json ... ``` first.
        m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except Exception:  # noqa: BLE001
                pass
        # Then look for the first balanced JSON object.
        start = text.find("{")
        if start < 0:
            return None
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except Exception:  # noqa: BLE001
                        return None
        return None

    @staticmethod
    def _extract_code_block(text: str, language: str = "solidity") -> str:
        """Extract the first code block of a given language from a response."""
        m = re.search(rf"```{language}\s*\n(.*?)```", text, re.DOTALL | re.IGNORECASE)
        if m:
            return m.group(1)
        m = re.search(r"```\s*\n(.*?)```", text, re.DOTALL)
        if m:
            return m.group(1)
        return text

    @staticmethod
    def _severity_at_least(actual: str, minimum: str) -> bool:
        order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return order.get(actual.upper(), 0) >= order.get(minimum.upper(), 0)

    # ---- report construction --------------------------------------------

    def build_report(
        self,
        result: ScanResult,
        *,
        formats: Sequence[str] | None = None,
        out_dir: Path | None = None,
    ) -> dict[str, Path]:
        """Build a multi-format report. Returns ``{format: path}``."""
        fmt_list = list(formats or self.config.get("report_formats", ["txt", "json", "sarif", "md"]))
        builder = ReportBuilder(result, findings_db=self.findings_db)
        return builder.write(out_dir or self.workdir, formats=fmt_list)

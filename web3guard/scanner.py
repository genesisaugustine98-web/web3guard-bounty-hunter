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

import datetime
import hashlib
import json
import logging
import re
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from web3guard.ai import AIClient, AIProvider, CostTracker, OpenAICompatibleProvider
from web3guard.findings_db import FindingRecord, FindingsDB
from web3guard.languages import (
    LanguageAdapter,
    LanguageRegistry,
    TargetLanguage,
    default_registry,
    detect_target_language,
)
from web3guard.reports import ReportBuilder
from web3guard.security import (
    PromptInjectionGuard,
    SandboxGuard,
    SandboxPolicy,
)
from web3guard.utils.secrets import scan_path
from web3guard.utils.vuln_catalog import get_catalog

LOGGER = logging.getLogger("web3guard.scanner")


# ---------------------------------------------------------------------------
# Top-level data types
# ---------------------------------------------------------------------------


class Severity(StrEnum):
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
    dependency_of: str = ""  # set when this target was scanned as a dependency


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


_FN_DEF_RE = re.compile(
    r"(?:function\s+([A-Za-z0-9_]+)\s*\(|"
    r"def\s+([a-z_][a-z0-9_]*)\s*\(|"
    r"pub\s+(?:entry\s+)?fun\s+([a-z_][a-z0-9_]*)\s*\(|"
    r"fn\s+([a-z_][a-z0-9_]*)\s*\()"
)


def _function_name_at(lines: list[str], line_idx: int) -> str:
    """Return the name of the function that owns ``line_idx``."""
    for i in range(line_idx, -1, -1):
        m = _FN_DEF_RE.search(lines[i])
        if m:
            return next(g for g in m.groups() if g)
    return ""


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
            "model": "deepseek-ai/deepseek-v4-flash-0731",
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
    "model": "deepseek-ai/deepseek-v4-flash-0731",
    "max_cost_usd": 50.0,
    "default_seed": 0,
    "max_chunk_chars": 6000,
    "max_context_chars": 6000,
    "discovery_time_budget_seconds": 900,
    "enable_discovery": True,
    "enable_ai_analysis": True,
    "enable_exploit": True,
    "max_exploit_attempts": 3,
    "use_ai_planning": True,
    "enable_self_critique": True,
    "enable_attack_sequence_brainstorm": True,
    "enable_role_map": True,
    "enable_secret_scan": True,
    "enable_incremental_scan": False,
    "enable_deployment_verification": False,
    "enable_dependency_scan": False,
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
        findings_path = Path(self.config.get("findings_db_path", ".web3guard/findings.db"))
        if not findings_path.is_absolute():
            findings_path = self.workdir / findings_path
        self.findings_db = findings_db or FindingsDB(
            findings_path
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
    ) -> Scanner:
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
                    timeout=float(p.get("timeout", 120.0)),
                    name=p.get("name", p["type"]),
                    use_streaming=bool(p.get("use_streaming", True)),
                ))
            except Exception as e:  # noqa: BLE001
                LOGGER.warning("failed to build provider %s: %s", p.get("name"), e)
        # Retries: the first enabled provider's per-provider cap wins, so a
        # flaky provider can be configured to fall through to the next one
        # faster instead of burning N x timeout seconds on hopeless retries.
        max_retries = None
        for p in self.config.get("ai_providers", []):
            if p.get("enabled", True) is False:
                continue
            max_retries = int(p.get("max_retries", 2))
            break
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
            model=str(self.config.get("model", "deepseek-ai/deepseek-v4-flash-0731")),
            cost_tracker=cost,
            cache_path=cache_path,
            injection_guard=self.injection_guard,
            default_seed=self.config.get("default_seed", 0),
            max_retries_per_provider=max_retries,
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
        self._start_ts = datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")
        parsed = self._parse_targets(targets)
        result = ScanResult(
            started_at=self._start_ts,
            finished_at="",
            config=self._sanitize_config(),
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
            if self.config.get("enable_dependency_scan", False):
                dep_trs = self._scan_dependencies(
                    url, budget, min_severity=min_severity)
                for dep_tr in dep_trs:
                    for f in dep_tr.findings:
                        self.findings_db.upsert(FindingRecord.from_finding(f))
                result.targets.extend(dep_trs)
        self._end_ts = datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")
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
                    [language.value for language in detection.detected],
                    [a.language.value for a in adapters])
        # Build the result
        tr = TargetResult(
            target=target,
            language=detection.primary,
        )
        tr.framework = {
            "build_tools": detection.build_tools,
            "confidence_notes": detection.confidence_notes,
        }
        if not adapters:
            tr.error = "no language adapter matched the target"
            return tr

        # Optional research planning: deterministically score files by
        # structural risk so the analysis budget is spent on the
        # highest-risk files first.
        plan: dict[str, Any] = {}
        if self.config.get("use_ai_planning", True):
            plan = self._plan_target(adapters, target_path)
            tr.research_plan = plan

        # Run every matching adapter (not just the primary one) so
        # mixed-language repos get full coverage. Findings are merged
        # and de-duplicated by fingerprint across adapters.
        analysis_budget = max(1, budget // 1500) if budget else 0
        seen_fps: set[str] = set()
        tr.role_map = {}
        tr.attack_sequences = {}
        for adapter in adapters:
            lang = adapter.language.value
            LOGGER.info("adapter %s analyzing target", lang)
            # Discovery for this language.
            if self.config.get("enable_discovery", True):
                for finding in self._run_discovery(target_path, target, adapter.language):
                    if finding.fingerprint in seen_fps:
                        continue
                    if not self._severity_at_least(finding.severity, min_severity):
                        continue
                    seen_fps.add(finding.fingerprint)
                    tr.findings.append(finding)
            # Discover files, ordered by research-plan risk.
            try:
                files = adapter.discover_files(target_path)
            except Exception as e:  # noqa: BLE001
                LOGGER.warning("adapter %s discover_files failed: %s", lang, e)
                files = []
            files = self._ordered_files(files, target_path, plan)
            tr.files_analyzed += len(files)
            LOGGER.info("adapter %s found %d files", lang, len(files))
            # Per-chunk analysis.
            chunks_to_analyze: list[Any] = []
            for fp in files:
                if analysis_budget and len(chunks_to_analyze) >= analysis_budget:
                    break
                try:
                    chunks = adapter.chunk(fp, self.config.get("max_chunk_chars", 6000))
                except Exception as e:  # noqa: BLE001
                    LOGGER.warning("chunker failed on %s: %s", fp, e)
                    continue
                for ch in chunks:
                    try:
                        ch.context = adapter.resolve_context(fp, target_path)
                    except Exception as e:  # noqa: BLE001
                        LOGGER.warning("context resolver failed on %s: %s", fp, e)
                    chunks_to_analyze.append(ch)
                    if analysis_budget and len(chunks_to_analyze) >= analysis_budget:
                        break
            tr.chunks_analyzed += len(chunks_to_analyze)
            if self.config.get("enable_ai_analysis", True):
                for ch in chunks_to_analyze:
                    finding = self._analyze_chunk(adapter, ch, target_path, target)
                    if finding is None:
                        continue
                    if finding.fingerprint in seen_fps:
                        continue
                    seen_fps.add(finding.fingerprint)
                    if self._severity_at_least(finding.severity, min_severity):
                        tr.findings.append(finding)
            # Optional post-scan passes (deterministic, offline).
            if self.config.get("enable_attack_sequence_brainstorm", True):
                tr.attack_sequences[lang] = self._attack_sequences(adapter, target_path)
            if self.config.get("enable_role_map", True):
                tr.role_map[lang] = self._role_map(adapter, target_path)
        # Optional: secret scan (whole target once).
        if self.config.get("enable_secret_scan", True):
            tr.secrets_findings = scan_path(target_path)
        # Sort findings by severity then confidence.
        severity_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        tr.findings.sort(
            key=lambda f: (
                -severity_order.get(str(f.severity).upper(), 0),
                -f.confidence,
            )
        )
        return tr

    def _clone_target(self, target: str) -> Path | None:
        """Clone a git URL or accept a local path."""
        if target.startswith(("http://", "https://", "git@", "git://")):
            import subprocess
            import tempfile
            tmp_root = Path(tempfile.mkdtemp(prefix="web3guard-target-"))
            clone_path = tmp_root / "repo"
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", target, str(clone_path)],
                    check=True, capture_output=True, timeout=120,
                )
            except Exception as e:  # noqa: BLE001
                LOGGER.error("clone failed: %s", e)
                return None
            return clone_path
        # Local path
        p = Path(target).resolve()
        return p if p.is_dir() else None

    def _scan_dependencies(
        self,
        target: str,
        budget: int,
        *,
        min_severity: str,
    ) -> list[TargetResult]:
        """Scan the git dependencies declared by ``target``.

        The target is cloned (or resolved as a local path), its declared
        dependencies are discovered offline, and each dependency that is
        not the target itself is scanned with the same per-target
        pipeline. This closes the "dependency is never scanned" gap for
        repos that vendor an OpenZeppelin fork, Solana SDK, Cairo
        library, etc. Guarded by ``enable_dependency_scan``.
        """
        from web3guard.utils.dependencies import discover_dependencies

        path = self._clone_target(target)
        if path is None:
            return []
        deps = discover_dependencies(path)
        LOGGER.info("target %s declares %d dependency repo(s)", target, len(deps))
        results: list[TargetResult] = []
        for dep in deps:
            if dep.rstrip("/") == str(target).rstrip("/"):
                continue  # a target must not scan itself
            LOGGER.info("scanning dependency: %s (budget=%s)", dep, budget)
            t0 = time.monotonic()
            tr = self._scan_one(dep, budget, min_severity=min_severity)
            tr.elapsed_seconds = time.monotonic() - t0
            tr.dependency_of = target
            results.append(tr)
        return results

    def _build_system_prompt(self, adapter: LanguageAdapter) -> str:
        """Compose the analysis system prompt (generic + language-specific)."""
        system = adapter.analysis_system_prompt()
        catalog = get_catalog(adapter.language)
        if catalog:
            system += (
                "\n\nLanguage-specific vulnerability catalog to check against:\n"
                + catalog.strip()
            )
        adapter_catalog = adapter.vulnerability_catalog()
        if adapter_catalog and adapter_catalog.strip() not in system:
            system += "\n\n" + adapter_catalog.strip()
        return system

    @staticmethod
    def _build_exploit_system_prompt(adapter: LanguageAdapter) -> str:
        """Compose the exploit-generation system prompt.

        Deliberately does NOT reuse the analysis system prompt, which
        instructs the model to "respond with a single JSON object".
        Live scans showed models following that instruction and
        returning an analysis blob instead of a PoC, so every exploit
        was rejected by the impact-assertion gate.
        """
        return (
            "You are an expert smart-contract exploit developer. You "
            "write proof-of-concept test code that compiles and runs "
            "against the given target. Output ONLY the requested test "
            "code inside a single fenced code block. Never output JSON, "
            "analysis, prose, or explanation outside the code block."
        )

    def _analyze_chunk(
        self,
        adapter: LanguageAdapter,
        chunk: Any,
        target_path: Path,
        target_url: str,
    ) -> Finding | None:
        """Run analysis + exploit generation + self-critique for one chunk."""
        # 1. Build the system prompt (generic + language-specific catalog)
        system = self._build_system_prompt(adapter)
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
        raw_confidence = parsed.get("confidence")
        try:
            confidence = float(raw_confidence) if raw_confidence is not None else 0.5
        except (TypeError, ValueError):
            confidence = 0.5
        confidence = max(0.0, min(1.0, confidence))
        finding = Finding(
            target=target_url,
            language=adapter.language.value,
            file=chunk.file,
            function=parsed.get("function", ""),
            category=parsed.get("category", ""),
            severity=str(parsed.get("severity", "MEDIUM")).upper(),
            confidence=confidence,
            swc_id=parsed.get("swc_id", ""),
            description=parsed.get("description", ""),
            reasoning=parsed.get("reasoning", ""),
            line_hint=parsed.get("line_hint", ""),
        )
        finding.fingerprint = self._fingerprint(finding)
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
        sandbox = create_sandbox(
            adapter, target_path, self.workdir,
            fork_url=self.config.get("fork_url"),
        )
        if sandbox is None:
            finding.status = "POTENTIAL (sandbox init failed)"
            return
        fork_hint = self._fork_hint() if self.config.get("fork_url") else ""
        max_attempts = int(self.config.get("max_exploit_attempts", 3))
        template = adapter.exploit_user_template()
        system = self._build_exploit_system_prompt(adapter)
        last_err = ""
        for _attempt in range(1, max_attempts + 1):
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
                        fork_hint=fork_hint,
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
                self._capture_on_chain_tvl(finding, out)
                return
            last_err = out[-1500:]
        finding.status = f"POTENTIAL (PoC unconfirmed: {last_err[:200]})"
        finding.poc_code = code if 'code' in locals() else ""

    @staticmethod
    def _fork_hint() -> str:
        """Prompt guidance emitted only when a fork RPC is configured."""
        return (
            "FORK MODE: this PoC runs against a live chain fork, so real\n"
            "on-chain state (token balances, oracle prices, DEX liquidity)\n"
            "is available to the test. After the impact assertion, emit a\n"
            "uint log named \"vuln_tvl\" with the value at risk, e.g.\n"
            "    emit log_named_uint(\"vuln_tvl\", drainedWei);\n"
            "Use the drained amount in wei, or an estimated USD value if\n"
            "the drained asset is not ETH.\n"
        )

    @staticmethod
    def _capture_on_chain_tvl(finding: Finding, output: str) -> None:
        """Extract a ``vuln_tvl`` console log emitted by the PoC on the fork.

        Foundry prints ``log_named_uint`` values as ``name: value``.
        Stored raw so the economic analyzer can refine profit.
        """
        m = re.search(r"vuln_tvl:\s*(\d+)", output)
        if m:
            try:
                finding.metadata["on_chain_tvl"] = int(m.group(1))
            except ValueError:  # noqa: PERF203
                pass

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
        """Cheap regex-only secret scan (shared hardened patterns)."""
        return scan_path(target_path)

    # ---- deterministic offline passes (planning / role map / attacks) ----

    def _sanitize_config(self) -> dict[str, Any]:
        """Return a copy of the config safe to serialize into reports.

        Strips AI providers and redacts credential-bearing values such
        as RPC URLs with embedded keys so they never leak into JSON /
        SARIF / Markdown artifacts.
        """
        sensitive_keys = ("key", "token", "secret", "password")
        redacted_value_keys = ("fork_url", "rpc_url", "rpc", "web3_url", "api_url")
        out: dict[str, Any] = {}
        for k, v in self.config.items():
            if k == "ai_providers":
                continue
            if any(s in k.lower() for s in sensitive_keys):
                out[k] = "<redacted>"
                continue
            if isinstance(v, str) and k.lower() in redacted_value_keys:
                out[k] = re.sub(r"(https?://)[^?#\s]+", r"\1<redacted>", v)
                continue
            out[k] = v
        return out

    def _plan_target(
        self,
        adapters: Sequence[LanguageAdapter],
        target_path: Path,
    ) -> dict[str, Any]:
        """Score files by structural risk and record the analysis order.

        Files that move value, read an oracle, sit behind a proxy, or
        use assembly get the highest priority so the token budget is
        spent on the highest-value targets first. Fully deterministic
        (no LLM round-trip), so it doubles as a cheap triage report.
        """
        plan: dict[str, Any] = {"files": {}, "priority": []}
        for adapter in adapters:
            lang = adapter.language.value
            try:
                files = adapter.discover_files(target_path)
            except Exception:  # noqa: BLE001
                continue
            scored: list[tuple[float, str, Path]] = []
            for fp in files:
                try:
                    s = adapter.summarize(fp, target_path)
                except Exception:  # noqa: BLE001
                    continue
                risk = 0.0
                risk += min(s.external_calls, 8) * 1.5
                risk += 3.0 if s.moves_value else 0.0
                risk += 4.0 if s.reads_oracle else 0.0
                risk += 2.0 if s.behind_proxy else 0.0
                risk += 3.0 if s.has_assembly else 0.0
                risk += 2.0 if s.functions >= 8 else 0.0
                risk += 1.0 if s.state_vars >= 6 else 0.0
                try:
                    rel = str(fp.relative_to(target_path))
                except ValueError:  # noqa: PERF203
                    rel = str(fp)
                scored.append((risk, rel, fp))
            scored.sort(key=lambda t: -t[0])
            plan["files"][lang] = [
                {"file": rel, "risk": round(risk, 2)} for risk, rel, _ in scored
            ]
            plan["priority"].extend(rel for _, rel, _ in scored)
        plan["note"] = (
            "deterministic structural risk scores (external calls, value "
            "movement, oracle reads, proxies, assembly); high-risk files "
            "analyzed first"
        )
        return plan

    def _ordered_files(
        self,
        files: Sequence[Path],
        target_path: Path,
        plan: dict[str, Any],
    ) -> list[Path]:
        """Order files by research-plan risk (highest risk first)."""
        risk_map: dict[str, float] = {}
        for entries in plan.get("files", {}).values():
            for entry in entries:
                risk_map[entry["file"]] = float(entry["risk"])

        def key(fp: Path) -> tuple[float, str]:
            try:
                rel = str(fp.relative_to(target_path))
            except ValueError:  # noqa: PERF203
                rel = str(fp)
            return (-risk_map.get(rel, 0.0), rel)

        return sorted(files, key=key)

    # Privileged role names and the state vars they typically govern.
    _ROLE_VARS = ("owner", "admin", "controller", "guardian", "governor",
                  "manager", "operator", "fee", "paused", "whitelist")
    _PRIVILEGED_FN_RE = re.compile(
        r"^(set|update|change|upgrade|authorize|transfer_?owner|"
        r"add_?to_?whitelist|remove_?from_?whitelist|pause|unpause|kill|"
        r"steal|rescue|sweep|withdraw_?all|renounce|grant|revoke|mint|burn)"
    )
    _AUTH_GUARD_RES = (
        re.compile(r"onlyOwner|onlyAdmin|onlyGovernor|onlyRole|onlyOperator"),
        re.compile(r"require\s*\([^;]{0,120}\bmsg\.sender\b"),
        re.compile(r"require\s*\([^;]{0,120}\bowner\b[^;]{0,120}\)"),
        re.compile(r"assert\s+msg\.sender\s*==\s*self\.(owner|admin)"),
        re.compile(r"asserts!\s*\(is-eq\s+(tx-sender|contract-caller)"),
        re.compile(r"has_one\s*=\s*owner|constraint\s*=\s*\w+\s*\("),
    )

    def _role_map(
        self,
        adapter: LanguageAdapter,
        target_path: Path,
    ) -> dict[str, Any]:
        """Map privileged roles and which functions mutate their state.

        Detects "privileged-looking" functions that write to role state
        without an obvious auth guard. Deterministic and offline.
        """
        roles: list[dict[str, Any]] = []
        notes: list[str] = []
        for fp in self._iter_user_files(adapter, target_path):
            try:
                content = fp.read_text(errors="ignore")
            except Exception:  # noqa: BLE001
                continue
            rel = str(fp.relative_to(target_path))
            lower = content.lower()
            present = [v for v in self._ROLE_VARS if re.search(rf"\b{v}\b", lower)]
            if not present:
                continue
            for fn_match in _FN_DEF_RE.finditer(content):
                fn_name = next(g for g in fn_match.groups() if g)
                body_start = fn_match.end()
                body_end = content.find("\n\n", body_start)
                body_end = body_end if body_end > body_start else len(content)
                body = content[body_start:body_end]
                guarded = any(rg.search(body) for rg in self._AUTH_GUARD_RES)
                privileged = bool(self._PRIVILEGED_FN_RE.match(fn_name))
                if privileged and not guarded:
                    roles.append({
                        "role": present,
                        "file": rel,
                        "function": fn_name,
                        "guarded": False,
                        "reason": "privileged function name without an auth guard",
                    })
                elif privileged and guarded:
                    roles.append({
                        "role": present,
                        "file": rel,
                        "function": fn_name,
                        "guarded": True,
                        "reason": "privileged function name with an auth guard",
                    })
        if roles:
            notes.append(
                "un-guarded privileged functions are the highest-value "
                "access-control targets"
            )
        return {"roles": roles, "notes": notes}

    def _attack_sequences(
        self,
        adapter: LanguageAdapter,
        target_path: Path,
    ) -> dict[str, Any]:
        """Heuristically enumerate likely attack chains (offline).

        A chain is: [value-moving or external-call function] ->
        [re-entrant target / external contract] -> [state write after
        the call]. Produced deterministically from source structure.
        """
        sequences: list[dict[str, Any]] = []
        notes: list[str] = []
        ext_call_re = re.compile(
            r"\.(?:call|delegatecall|transfer|send)\b|"
            r"raw_call|contract-call\?|invoke\b|invoke_signed|"
            r"send_message_to_l1|stx-transfer\?|coin::transfer"
        )
        state_write_re = re.compile(
            r"(?:balances|shares|balanceOf|deposits|collateral|borrowed|"
            r"totalShares|totalAssets|owner|feeBps|fee)\s*\[?[^\]]*\]?\s*"
            r"(\+|-)?="
        )
        for fp in self._iter_user_files(adapter, target_path):
            try:
                content = fp.read_text(errors="ignore")
            except Exception:  # noqa: BLE001
                continue
            rel = str(fp.relative_to(target_path))
            lines = content.splitlines()
            for i, line in enumerate(lines):
                if not ext_call_re.search(line):
                    continue
                # Look for a state write later in the same function body.
                tail = "\n".join(lines[i:i + 30])
                if state_write_re.search(tail):
                    fn_name = _function_name_at(lines, i)
                    sequences.append({
                        "file": rel,
                        "function": fn_name or "(unknown)",
                        "line": i + 1,
                        "pattern": "external call followed by a state write "
                                   "within the same function (reentrancy / "
                                   "CEI-violation candidate)",
                        "confidence": 0.6,
                    })
        if sequences:
            notes.append(
                "reentrancy chains were inferred statically; confirm each "
                "with a PoC before reporting"
            )
        return {"sequences": sequences, "notes": notes}

    def _iter_user_files(
        self,
        adapter: LanguageAdapter,
        target_path: Path,
    ) -> list[Path]:
        """Return the adapter's user-code files (with error tolerance)."""
        try:
            return list(adapter.discover_files(target_path))
        except Exception as e:  # noqa: BLE001
            LOGGER.warning("discover_files failed for %s: %s",
                           adapter.language.value, e)
            return []

    # ---- economic analyzer -------------------------------------------------

    # Order-of-magnitude offline models per category. `scope` explains
    # what drives the real number; these are placeholder magnitudes that
    # get refined when a --fork-url RPC is provided.
    _ECONOMIC_MODELS: dict[str, dict[str, Any]] = {
        "reentrancy": {
            "cost": 0.5,
            "profit": 100_000,
            "scope": "drains contract balance; profit capped by TVL",
        },
        "oracle": {
            "cost": 25.0,
            "profit": 1_000_000,
            "scope": "flash-loan fee (~0.09% of pool) vs drained loans",
        },
        "oracle-manipulation": {
            "cost": 25.0,
            "profit": 1_000_000,
            "scope": "flash-loan fee (~0.09% of pool) vs drained loans",
        },
        "access-control": {
            "cost": 2.0,
            "profit": 250_000,
            "scope": "gas + one tx; profit = funds governed by the role",
        },
        "arithmetic": {
            "cost": 5.0,
            "profit": 50_000,
            "scope": "rounding / inflation; profit = precision loss per op",
        },
        "randomness": {
            "cost": 2.0,
            "profit": 25_000,
            "scope": "predictable jackpot / winner index",
        },
        "signature": {
            "cost": 2.0,
            "profit": 25_000,
            "scope": "replayed tx value across chains / wallets",
        },
        "unchecked-external-call": {
            "cost": 1.0,
            "profit": 10_000,
            "scope": "silent failure of token/ETH transfer",
        },
    }

    def _economic_analyzer(self, finding: Finding) -> None:
        """Estimate the attacker's required capital and expected profit.

        Uses a per-category offline model (order-of-magnitude). When a
        live fork RPC is configured and the PoC emitted an on-chain
        ``vuln_tvl`` amount, that real value-at-risk overrides the
        offline profit estimate.
        """
        on_chain_tvl = finding.metadata.get("on_chain_tvl")
        fork_configured = bool(self.config.get("fork_url"))
        if on_chain_tvl is not None:
            finding.cost_basis_usd = float(self._ECONOMIC_MODELS.get(
                finding.category.lower(), {}).get("cost", 0.0))
            finding.expected_profit_usd = min(float(on_chain_tvl), 1_000_000_000.0)
            finding.metadata["economic"] = {
                "on_chain": True,
                "source": "fork-poc-log",
                "note": "value at risk measured on a live fork PoC "
                        "(vuln_tvl console log)",
            }
            return
        model = self._ECONOMIC_MODELS.get(finding.category.lower())
        if model:
            finding.cost_basis_usd = float(model["cost"])
            finding.expected_profit_usd = float(model["profit"])
            finding.metadata["economic"] = {
                "note": "offline order-of-magnitude estimate; pass "
                        "--fork-url for on-chain TVL data",
                "scope": model["scope"],
                "on_chain": True if fork_configured else False,
            }
            return
        finding.cost_basis_usd = 0.0
        finding.expected_profit_usd = 0.0
        finding.metadata["economic"] = {
            "note": "offline estimate; pass --fork-url for on-chain TVL data",
            "scope": "unknown category; see description",
            "on_chain": True if fork_configured else False,
        }

    # ---- helpers ---------------------------------------------------------

    def _run_discovery(
        self,
        target_path: Path,
        target: str,
        language: TargetLanguage,
    ) -> list[Finding]:
        """Run installed discovery engines compatible with the target language."""
        from web3guard.discovery import ALL_ENGINES

        findings: list[Finding] = []
        deadline = time.monotonic() + int(self.config.get("discovery_time_budget_seconds", 900))
        for engine_type in ALL_ENGINES:
            engine = engine_type()
            if language not in engine.supported_languages or not engine.enabled_by_default:
                continue
            remaining = int(deadline - time.monotonic())
            if remaining <= 0:
                LOGGER.warning("discovery time budget exhausted")
                break
            if not engine.is_installed():
                continue
            try:
                discovered = engine.run(target_path, timeout=min(engine.default_timeout, remaining))
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning("discovery engine %s failed: %s", engine.name, exc)
                continue
            for item in discovered:
                # The multi-language static engine reports every language
                # it finds, regardless of which adapter requested it.
                # Resolve the file's *actual* language so findings are
                # tagged correctly and each adapter only keeps its own.
                from web3guard.discovery.static_analyzer import language_for_file
                item_lang = language_for_file(Path(target_path) / item.file) or language
                if item_lang != language:
                    continue
                finding = Finding(
                    target=target,
                    language=item_lang.value,
                    file=item.file,
                    function=item.function,
                    category=item.category or item.title,
                    severity=item.severity,
                    confidence=item.confidence,
                    swc_id=item.swc_id,
                    description=item.description or item.title,
                    reasoning=f"Reported by {item.engine}",
                    line_hint=(
                        f"{item.line}-{item.end_line}"
                        if item.line and item.end_line and item.end_line != item.line
                        else str(item.line or "")
                    ),
                    tool_consensus=[item.engine],
                    metadata={"discovery": item.raw},
                )
                finding.fingerprint = self._fingerprint(finding)
                findings.append(finding)
        return findings

    @staticmethod
    def _fingerprint(finding: Finding) -> str:
        # Description + line hint seed the fingerprint so two distinct
        # vulnerabilities in the same function do not collapse into
        # one identity (and vice-versa: identical reports dedupe).
        desc = re.sub(r"\s+", " ", (finding.description or "")).strip().lower()
        desc_seed = hashlib.sha256(desc.encode("utf-8")).hexdigest()[:12]
        material = "\0".join((
            finding.target,
            finding.file,
            finding.function,
            finding.category,
            str(finding.line_hint or ""),
            desc_seed,
        ))
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]

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
        """Extract the first code block of a given language from a response.

        Falls back to any fenced block (with or without a language
        tag), then to the raw text. ``language`` matches the adapter's
        canonical value (e.g. ``rust-solana``), so we also accept the
        natural fence tags (``rust``/``typescript``) for those adapters.
        """
        aliases: dict[str, tuple[str, ...]] = {
            "rust-solana": ("rust", "typescript", "ts", "solana", "anchor"),
            "ts-sdk": ("typescript", "ts", "javascript", "js"),
            "move": ("move", "rust"),
            "func": ("func", "ton", "tl-b"),
        }
        labels = (language, *aliases.get(language, ()))
        for label in labels:
            m = re.search(rf"```{re.escape(label)}\s*\n(.*?)```",
                          text, re.DOTALL | re.IGNORECASE)
            if m:
                return m.group(1)
        # Bare or any-tag fence: ``` ... ```
        m = re.search(r"```[a-zA-Z0-9_+-]*\s*\n(.*?)```", text, re.DOTALL)
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

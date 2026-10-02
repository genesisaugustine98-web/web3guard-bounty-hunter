"""End-to-end hunt pipeline (Phase 7 of the Hunt Bigger Fish build).

One command that runs the whole machine in order::

    static scan -> invariant synthesis + fuzz -> AI red-team ->
    verification -> version-history comparison -> plain-English report.

Public entry points for the CLI (``web3guard hunt`` / ``web3guard watch``)::

    from web3guard.hunt import run_hunt, write_hunt_report, drain_trigger_queue

    result = run_hunt("path/to/project", config)
    write_hunt_report(result, out_dir)

Every stage is optional and independently skippable. AI stages degrade
honestly when no API keys are present (the router reports inactive; the
run continues with static analysis + template invariants + machine-only
verification, and the report says so loudly). Nothing in this module
ever submits anything anywhere — reports are local files only.
"""

from __future__ import annotations

import copy
import dataclasses
import datetime
import hashlib
import json
import logging
import os
import re
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from web3guard.ai.router import build_router_client, emit_offline_warning
from web3guard.ai.verification import verify_findings
from web3guard.history.ingest import parse_report
from web3guard.history.redive import RediveQueue, default_queue_path
from web3guard.history.report import plain_verdict, summarize_verdicts
from web3guard.history.verdicts import walk_versions
from web3guard.invariants import (
    SUPPORTED_LANGUAGES,
    detect_language,
    run_invariant_pipeline_full,
)
from web3guard.scanner import Finding, Scanner, load_config
from web3guard.utils.fetch import FetchError, fetch_target

LOGGER = logging.getLogger("web3guard.hunt")

#: Findings that went through verification inside the red-team
#: post-verify hook carry this metadata flag so the dedicated
#: verification stage does not spend a second LLM round on them.
_HOOK_VERIFIED_FLAG = "hunt_verified_in_hook"

#: How the report files are named per format.
_REPORT_FILENAMES = {"md": "hunt-report.md", "txt": "hunt-report.txt",
                     "json": "hunt-report.json"}


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def _deep_merge(base: dict[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, Mapping) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def normalize_config(config: Mapping[str, Any] | Path | str | None) -> dict[str, Any]:
    """Load config (path or mapping) and deep-merge the ``[hunt]`` section.

    ``load_config`` merges files shallowly, so a user-supplied ``hunt:``
    block would otherwise wipe the documented defaults. This keeps every
    documented option present unless the user overrides that exact key.
    """
    if isinstance(config, (Path, str)):
        cfg = load_config(Path(config))
    elif isinstance(config, Mapping):
        # A partial mapping merges over the full defaults, mirroring
        # load_config's file semantics — callers only override what they
        # set (e.g. {"hunt": {"fuzz_runs": 64}} keeps every default).
        cfg = _deep_merge(load_config(None), dict(config))
    else:
        cfg = load_config(None)
    from web3guard.scanner import DEFAULT_CONFIG

    hunt_defaults: dict[str, Any] = copy.deepcopy(DEFAULT_CONFIG["hunt"])
    cfg["hunt"] = _deep_merge(hunt_defaults, cfg.get("hunt") or {})
    # Forward fuzz bounds into the ``invariants`` section the phase-2
    # pipeline reads (FuzzBounds.from_config looks at config["invariants"]).
    hunt = cfg["hunt"]
    inv = dict(cfg.get("invariants") or {})
    inv.setdefault("runs", int(hunt.get("fuzz_runs", 256) or 256))
    inv.setdefault("depth", int(hunt.get("fuzz_depth", 15) or 15))
    inv.setdefault("timeout_seconds",
                   int(hunt.get("fuzz_timeout_s", 300) or 300))
    cfg["invariants"] = inv
    return cfg


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class HuntStage:
    """One pipeline stage: did it run, and if not, why not."""

    name: str
    ran: bool
    skipped_reason: str = ""
    notes: list[str] = field(default_factory=list)
    findings: int = 0


@dataclass
class HuntResult:
    """Everything one ``run_hunt`` call produced."""

    target: str
    resolved_path: str = ""
    started_at: str = ""
    finished_at: str = ""
    stages: list[HuntStage] = field(default_factory=list)
    static_findings: list[Finding] = field(default_factory=list)
    ai_findings: list[Finding] = field(default_factory=list)  # pre-verify
    findings: list[Finding] = field(default_factory=list)     # final survivors
    rejected: list[Finding] = field(default_factory=list)    # dropped by verify
    ai_active: bool = False
    offline_notes: list[str] = field(default_factory=list)
    verification_notes: list[str] = field(default_factory=list)
    verification_ledger: str = ""
    history: dict[str, Any] | None = None
    redive_added: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    cost_usd: float = 0.0
    llm_calls: int = 0
    error: str = ""
    report_paths: dict[str, str] = field(default_factory=dict)
    #: Weakness-hunt round, target 2: explicit "could not check" verdicts
    #: (compile/render failures in the invariant stage). Rendered loudly in
    #: the plain-English report — never a silent "no findings".
    inconclusive: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.error

    def stage(self, name: str) -> HuntStage | None:
        for stage in self.stages:
            if stage.name == name:
                return stage
        return None

    def to_dict(self) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        # Keep the JSON report focused; the full per-stage note lists
        # already live in ``stages``.
        return data


# ---------------------------------------------------------------------------
# Target resolution + contract discovery
# ---------------------------------------------------------------------------


def _resolve_target(target: str, workdir: Path) -> Path:
    """Resolve any supported target shape to a local directory."""
    return fetch_target(target, workdir=workdir)


def _contract_files(root: Path, limit: int) -> list[Path]:
    """Solidity/Vyper/Cairo sources under ``root`` (deterministic order)."""
    suffixes = {".sol", ".vy", ".cairo"}
    skip_dirs = {".git", ".web3guard", "node_modules", ".svn", "__pycache__",
                 "lib", ".foundry"}
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        if any(part in skip_dirs or part.startswith(".") and part != path.name
               for part in path.relative_to(root).parts[:-1]):
            continue
        try:
            if detect_language(path) not in SUPPORTED_LANGUAGES:
                continue
        except Exception:  # noqa: BLE001 - one odd file must not stop us
            continue
        found.append(path)
        if len(found) >= limit:
            break
    return found


def _fingerprint(finding: Finding) -> str:
    """Same identity scheme as :meth:`Scanner._fingerprint` (staticmethod)."""
    return Scanner._fingerprint(finding)  # noqa: SLF001


# ---------------------------------------------------------------------------
# Stage: static scan
# ---------------------------------------------------------------------------


def _static_scan(resolved: Path, cfg: dict[str, Any], workdir: Path,
                 min_severity: str, notes: list[str]) -> list[Finding]:
    """Static pattern scan via the existing Scanner, AI layers switched off.

    The hunt runs its own AI stages (red-team, invariant synthesis,
    verification) through the free-tier router, so the static stage is
    deliberately discovery-only: no double AI spend, no double findings.
    """
    static_cfg = dict(cfg)
    static_cfg.update({
        "enable_ai_analysis": False,
        "enable_exploit": False,
        "enable_self_critique": False,
        "enable_redteam": False,
        "enable_differential": False,
        "use_ai_planning": False,
        "enable_attack_sequence_brainstorm": False,
    })
    scanner = Scanner(config=static_cfg, workdir=workdir)
    result = scanner.scan([str(resolved)], min_severity=min_severity)
    for target_result in result.targets:
        if target_result.error:
            notes.append(f"static scan: target error: {target_result.error}")
    findings = [f for f in result.all_findings
                if f.status != "REJECTED"]
    for finding in findings:
        finding.metadata.setdefault("hunt_source", "static")
    return findings


# ---------------------------------------------------------------------------
# Stage: invariants + fuzz
# ---------------------------------------------------------------------------


def _invariant_stage(resolved: Path, cfg: dict[str, Any],
                     max_contracts: int) -> tuple[list[Finding], list[str], list[str]]:
    """Run the invariant pipeline over the target's contracts.

    Returns (findings, notes, inconclusive): ``inconclusive`` carries the
    weakness-hunt round's explicit "could not check" verdicts (compile /
    render failures) so they can reach the report loudly instead of
    reading as a clean "no findings".
    """
    findings: list[Finding] = []
    notes: list[str] = []
    inconclusive: list[str] = []
    contracts = _contract_files(resolved, max_contracts)
    if not contracts:
        notes.append("invariant stage: no Solidity/Vyper/Cairo contracts "
                     "found under the target; nothing to fuzz.")
        return findings, notes, inconclusive
    for contract in contracts:
        run_notes: list[str] = []
        try:
            pipeline_result = run_invariant_pipeline_full(
                contract, cfg, notes=run_notes)
        except Exception as exc:  # noqa: BLE001 - never break the hunt
            msg = (f"invariant pipeline crashed on {contract.name} ({exc}); "
                   "continuing without it.")
            LOGGER.exception(msg)
            notes.append(msg)
            inconclusive.append(
                f"{contract.name}: the invariant pipeline crashed ({exc}); "
                "this contract was NOT checked."
            )
            continue
        for finding in pipeline_result.findings:
            finding.metadata["hunt_source"] = "invariants"
            findings.append(finding)
        for note in run_notes:
            notes.append(f"{contract.name}: {note}")
        inconclusive.extend(pipeline_result.inconclusive)
    return findings, notes, inconclusive


# ---------------------------------------------------------------------------
# Stage: AI red-team (opt-in)
# ---------------------------------------------------------------------------


def _hypothesis_to_finding(h: Any, *, target: str, file: str,
                           language: str) -> Finding:
    """Convert a surviving red-team hypothesis to a canonical Finding.

    Mirrors the conversion in ``Scanner._redteam_chunk`` so hunt findings
    and scan findings share identity, severity, and metadata conventions.
    """
    confidence = float(getattr(h, "confidence", 0.5) or 0.5)
    exploitability = float(getattr(h, "exploitability_score", 0.0) or 0.0)
    if exploitability > 0:
        confidence = (confidence + exploitability) / 2.0
    description = str(getattr(h, "title", "") or "")
    attack_path = getattr(h, "attack_path", "") or []
    if attack_path:
        description += "\nAttack path:\n" + "\n".join(
            f"{i + 1}. {s}" for i, s in enumerate(attack_path))
    defense_note = str(getattr(h, "defense_failure_note", "") or "")
    reasoning = ("Survived defensive refutation. " + defense_note
                 if defense_note else "Survived defensive refutation.")
    finding = Finding(
        target=target,
        language=language,
        file=file,
        function=str(getattr(h, "target_function", "") or ""),
        category=str(getattr(h, "category", "") or "redteam"),
        severity=str(getattr(h, "severity", "MEDIUM") or "MEDIUM"),
        confidence=round(max(0.0, min(1.0, confidence)), 3),
        description=description.strip(),
        reasoning=reasoning.strip(),
    )
    finding.tool_consensus = ["redteam"]
    finding.metadata["hunt_source"] = "redteam"
    finding.metadata["redteam_hypothesis_id"] = getattr(h, "id", "")
    finding.metadata["redteam_primitive"] = getattr(h, "primitive", "")
    finding.metadata["redteam_prerequisites"] = getattr(
        h, "prerequisites", "")
    finding.metadata["redteam_exploitability"] = exploitability
    finding.fingerprint = _fingerprint(finding)
    return finding


def _redteam_stage(resolved: Path, cfg: dict[str, Any], client: Any,
                   target: str, max_files: int, min_severity: str,
                   ledger_path: str | None,
                   hook_reports: list[Any]) -> tuple[list[Finding], list[str]]:
    """Run the attacker->defender->triage loop over the main contracts.

    Wires the phase-3 opt-in hook ``config["redteam_post_verify"]``: every
    surviving hypothesis is converted to a Finding and run through the
    verification gate *before* it becomes a finding — hypotheses whose
    evidence does not hold up are refuted on the spot and never shown.
    """
    from web3guard.ai.redteam import RedTeamAnalyzer

    findings: list[Finding] = []
    notes: list[str] = []
    hunt_cfg = cfg["hunt"]

    def _post_verify(report: Any) -> None:
        interim = [
            _hypothesis_to_finding(h, target=target,
                                   file=str(report.file),
                                   language=str(report.language))
            for h in report.survivors
        ]
        if not interim:
            return
        vrep = verify_findings(
            interim, cfg, client=client,
            ledger_path=ledger_path,
            max_llm_findings=int(
                hunt_cfg.get("verify_max_llm_findings", 64) or 64),
        )
        hook_reports.append(vrep)
        for hypothesis, finding in zip(report.survivors, interim, strict=True):
            finding.metadata[_HOOK_VERIFIED_FLAG] = True
            if finding.status == "REJECTED":
                hypothesis.status = "refuted"
                hypothesis.refutation = (
                    finding.metadata.get("rejection_reason")
                    or "verification rejected this hypothesis")[:500]

    rt_config = {
        "redteam_max_hypotheses": 5,
        "redteam_enable_defense": True,
        "redteam_enable_triage": True,
        "redteam_post_verify": _post_verify,
    }
    analyzer = RedTeamAnalyzer(client, rt_config)
    contracts = _contract_files(resolved, max_files)
    if not contracts:
        notes.append("red-team: no contracts found to analyze.")
        return findings, notes
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    min_rank = order.get(str(min_severity).upper(), 4)
    for contract in contracts:
        try:
            code = contract.read_text(errors="ignore")
        except OSError as exc:
            notes.append(f"red-team: cannot read {contract.name} ({exc})")
            continue
        if not code.strip():
            continue
        language = detect_language(contract)
        try:
            report = analyzer.analyze(
                code, file=str(contract), language=language)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"red-team: analysis failed on {contract.name} "
                         f"({exc}); continuing.")
            continue
        for error in report.errors:
            notes.append(f"red-team {contract.name}: {error}")
        for hypothesis in report.survivors:
            rank = order.get(str(hypothesis.severity).upper(), 4)
            if rank > min_rank:
                continue
            findings.append(_hypothesis_to_finding(
                hypothesis, target=target, file=str(contract),
                language=language))
    return findings, notes


# ---------------------------------------------------------------------------
# Stage: version history
# ---------------------------------------------------------------------------


def _git_tags(repo: Path) -> list[str]:
    """Local git tags, oldest-first best effort. No network is used."""
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "tag", "--list"],
            capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return []
    if out.returncode != 0:
        return []
    tags = [line.strip() for line in out.stdout.splitlines() if line.strip()]
    return sorted(tags, key=_version_key)


def _version_key(tag: str) -> tuple:
    """Best-effort ordering for version-like tags (v1.2.3, 2.0, ...)."""
    parts: list[Any] = []
    for chunk in re.split(r"[.\-+_]", tag.lstrip("vV")):
        parts.append(int(chunk) if chunk.isdigit() else chunk)
    return (0, tuple(parts)) if parts and isinstance(parts[0], int) else (1, tag)


def _history_stage(repo: Path, cfg: dict[str, Any], workdir: Path,
                   history_report: Path | None,
                   since_tag: str | None) -> tuple[dict[str, Any] | None,
                                                  list[dict[str, Any]],
                                                  list[str]]:
    """Audit-report ingestion + per-version verdicts + re-dive queue."""
    notes: list[str] = []
    tags = _git_tags(repo)
    if not tags:
        notes.append("history: the target is not a git repo with tags, so "
                     "there is no version history to compare.")
        return None, [], notes
    if since_tag:
        if since_tag in tags:
            tags = tags[tags.index(since_tag) + 1:]
        else:
            notes.append(f"history: --since-tag {since_tag!r} not found "
                         f"among tags; comparing all {len(tags)} tags.")
    report_path = history_report or None
    cfg_report = str(cfg["hunt"].get("audit_report") or "").strip()
    if report_path is None and cfg_report:
        report_path = Path(cfg_report)
    if report_path is not None and not report_path.is_file():
        notes.append(f"history: audit report not found: {report_path}; "
                     "continuing without report-based verdicts.")
        report_path = None
    if report_path is None and len(tags) < 2:
        notes.append("history: only one version tag found and no audit "
                     "report was supplied — nothing to compare.")
        return None, [], notes

    versions = tags
    summary: dict[str, Any] = {"versions": versions, "tags": tags}
    redive_added: list[dict[str, Any]] = []
    if report_path is not None:
        try:
            audit = parse_report(report_path)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"history: could not parse audit report "
                         f"{report_path} ({exc}).")
            return None, [], notes
        summary["report_title"] = audit.title
        summary["report_auditor"] = audit.auditor
        summary["report_findings"] = len(audit.findings)
        if not audit.findings:
            notes.append(f"history: no findings parsed from {report_path}; "
                         "version verdicts need at least one audit finding.")
            return summary, [], notes
        all_verdicts: list[Any] = []
        timelines: dict[str, dict[str, str]] = {}
        for audit_finding in audit.findings:
            try:
                verdicts = walk_versions(audit_finding, repo, versions)
            except Exception as exc:  # noqa: BLE001
                notes.append(f"history: verdict walk failed for "
                             f"{audit_finding.id} ({exc}).")
                continue
            all_verdicts.extend(verdicts)
            for verdict in verdicts:
                timelines.setdefault(audit_finding.id, {})[
                    verdict.version] = verdict.verdict
        summary["verdicts"] = summarize_verdicts(all_verdicts, versions)
        summary["timelines"] = timelines
        summary["per_finding"] = [
            {"id": f.id, "title": f.title, "severity": f.severity,
             "timeline": timelines.get(f.id, {})}
            for f in audit.findings
        ]
        # Re-dive queue: hand every finding's full verdict timeline to the
        # hardened queue's own ``sync_from_history`` entry point, so EVERY
        # BAND-AID / REGRESSED / still-open lead is tracked — mid-history
        # verdicts included, not just the latest version's. (The old code
        # hand-rolled its own latest-version-only logic here; it missed
        # band-aids from earlier versions entirely.)
        queue = RediveQueue(default_queue_path(workdir))
        verdicts_by_finding: dict[str, list[Any]] = {}
        for verdict in all_verdicts:
            verdicts_by_finding.setdefault(verdict.finding_id, []).append(
                verdict)
        for audit_finding in audit.findings:
            items = queue.sync_from_history(
                audit_finding.id,
                verdicts_by_finding.get(audit_finding.id, []),
                audit_finding,
            )
            for item in items:
                redive_added.append({
                    "id": item.id, "finding_id": audit_finding.id,
                    "title": audit_finding.title, "reason": item.reason,
                })
        summary["redive_count"] = len(redive_added)
    else:
        notes.append("history: no audit report supplied — reporting tag "
                     "list only. Pass --history-report <report.md> for "
                     "per-version fix verdicts.")
    return summary, redive_added, notes


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def run_hunt(
    target: str,
    config: Mapping[str, Any] | Path | str | None = None,
    *,
    workdir: Path | str | None = None,
    out_dir: Path | str | None = None,
    formats: Sequence[str] | None = None,
    skip_static: bool = False,
    skip_invariants: bool = False,
    skip_redteam: bool = False,
    skip_verify: bool = False,
    skip_history: bool = False,
    history_report: Path | str | None = None,
    since_tag: str | None = None,
    min_severity: str = "LOW",
    redteam: str | None = None,     # auto | on | off (overrides config)
    history: str | None = None,     # auto | on | off (overrides config)
    router_env: Mapping[str, str] | None = None,  # tests only: key discovery
    router_client: Any = None,      # tests only: prebuilt client
    progress: Callable[[str], None] | None = None,
) -> HuntResult:
    """Run the full hunt pipeline over ``target``.

    Stages run in order: static scan, invariant synthesis + fuzz,
    AI red-team, verification, version history. Every stage is optional.
    Never raises on stage-internal failures — the worst case is a stage
    marked skipped with notes explaining why.
    """
    cfg = normalize_config(config)
    hunt_cfg = cfg["hunt"]
    workdir_path = Path(workdir) if workdir else Path.cwd()
    workdir_path.mkdir(parents=True, exist_ok=True)
    started = datetime.datetime.now(datetime.UTC).isoformat()
    result = HuntResult(target=target, started_at=started)
    say = progress or (lambda _msg: None)

    # -- resolve ------------------------------------------------------
    try:
        resolved = _resolve_target(target, workdir_path)
    except FetchError as exc:
        result.error = str(exc)
        result.finished_at = datetime.datetime.now(datetime.UTC).isoformat()
        result.notes.append(
            f"Could not resolve the target ({exc}). Check the path or URL "
            "for typos — an unscanned target must never look like a clean "
            "scan.")
        if out_dir is not None:
            write_hunt_report(result, Path(out_dir),
                              formats=formats or ["md", "txt", "json"])
        return result
    result.resolved_path = str(resolved)

    # -- AI router (built once, shared by every AI stage) -------------
    client = router_client
    if client is None:
        env = dict(os.environ) if router_env is None else dict(router_env)
        client = build_router_client(cfg, env=env)
    result.ai_active = bool(getattr(client, "is_active", False))
    if not result.ai_active:
        reason = str(getattr(client, "inactive_reason", "AI inactive")
                     or "AI inactive")
        emit_offline_warning(reason)
        note = client.offline_report_note() if hasattr(
            client, "offline_report_note") else f"AI offline: {reason}"
        result.offline_notes.append(note)
        result.notes.append(
            "AI stages are OFF because no API keys were found. The scan "
            "still ran on pattern matching, hand-written rules, and local "
            "fuzzing — but the AI red-team, AI-written rules, and the "
            "AI debate over findings were skipped. To turn them on, add a "
            "free API key (see docs/HUNT.md).")

    ledger_path = str(hunt_cfg.get("verification_ledger_path") or "").strip() \
        or None

    # -- stage: static ------------------------------------------------
    if skip_static or not hunt_cfg.get("enable_static", True):
        result.stages.append(HuntStage(
            name="static", ran=False,
            skipped_reason="skipped by --skip-static / config"))
    else:
        say("stage 1/5: static pattern scan")
        stage = HuntStage(name="static", ran=True)
        try:
            result.static_findings = _static_scan(
                resolved, cfg, workdir_path, min_severity, stage.notes)
            stage.findings = len(result.static_findings)
        except Exception as exc:  # noqa: BLE001
            stage.ran = False
            stage.skipped_reason = f"static scan crashed: {exc}"
            LOGGER.exception("static stage failed")
        result.stages.append(stage)

    # -- stage: invariants --------------------------------------------
    if skip_invariants or not hunt_cfg.get("enable_invariants", True):
        result.stages.append(HuntStage(
            name="invariants", ran=False,
            skipped_reason="skipped by --skip-invariants / config"))
    else:
        say("stage 2/5: invariant synthesis + fuzzing")
        stage = HuntStage(name="invariants", ran=True)
        try:
            inv_findings, inv_notes, inv_inconclusive = _invariant_stage(
                resolved, cfg,
                int(hunt_cfg.get("max_invariant_contracts", 5) or 5))
            stage.notes.extend(inv_notes)
            stage.findings = len(inv_findings)
            result.ai_findings.extend(inv_findings)
            # Weakness-hunt round, target 2: "could not check" verdicts are
            # first-class — they reach the report loudly, never as silence.
            result.inconclusive.extend(inv_inconclusive)
        except Exception as exc:  # noqa: BLE001
            stage.ran = False
            stage.skipped_reason = f"invariant stage crashed: {exc}"
            LOGGER.exception("invariant stage failed")
        result.stages.append(stage)

    # -- stage: red-team ----------------------------------------------
    rt_mode = (redteam or str(hunt_cfg.get("redteam", "auto"))).lower()
    rt_wanted = (rt_mode == "on") or (rt_mode == "auto" and result.ai_active)
    if skip_redteam or rt_mode == "off":
        reason = ("skipped by --skip-redteam / config"
                  if (skip_redteam or rt_mode == "off")
                  else "skipped")
        result.stages.append(HuntStage(name="redteam", ran=False,
                                       skipped_reason=reason))
    elif not rt_wanted:
        result.stages.append(HuntStage(
            name="redteam", ran=False,
            skipped_reason=("AI red-team skipped: no API keys found "
                            "(mode=auto). Static findings, template "
                            "invariants, and machine verification still ran.")))
    else:
        say("stage 3/5: AI red-team")
        stage = HuntStage(name="redteam", ran=True)
        hook_reports: list[Any] = []
        try:
            rt_findings, rt_notes = _redteam_stage(
                resolved, cfg, client, target,
                int(hunt_cfg.get("max_redteam_files", 5) or 5),
                min_severity, ledger_path, hook_reports)
            stage.notes.extend(rt_notes)
            stage.findings = len(rt_findings)
            result.ai_findings.extend(rt_findings)
            for hook_report in hook_reports:
                result.llm_calls += int(
                    getattr(hook_report, "llm_calls", 0) or 0)
                result.verification_notes.extend(
                    getattr(hook_report, "notes", []) or [])
                if not result.verification_ledger:
                    result.verification_ledger = str(
                        getattr(hook_report, "ledger_path", "") or "")
        except Exception as exc:  # noqa: BLE001
            stage.ran = False
            stage.skipped_reason = f"red-team stage crashed: {exc}"
            LOGGER.exception("red-team stage failed")
        result.stages.append(stage)

    # -- stage: verification ------------------------------------------
    pending = [f for f in result.ai_findings
               if str(getattr(f, "status", "POTENTIAL")) == "POTENTIAL"
               and not f.metadata.get(_HOOK_VERIFIED_FLAG)]
    # Findings already verified inside the red-team hook count as
    # verified: they were checked, just earlier.
    hook_verified = [f for f in result.ai_findings
                     if f.metadata.get(_HOOK_VERIFIED_FLAG)]
    if skip_verify or not hunt_cfg.get("enable_verify", True):
        result.stages.append(HuntStage(
            name="verify", ran=False,
            skipped_reason="skipped by --skip-verify / config"))
        kept = [f for f in pending if f.status == "POTENTIAL"]
        result.notes.append(
            "Verification was skipped, so AI-produced findings are shown "
            "unreviewed (status POTENTIAL). Re-run without --skip-verify "
            "to have them machine-checked first.")
    else:
        say("stage 4/5: verification")
        stage = HuntStage(name="verify", ran=True)
        try:
            vrep = verify_findings(
                pending, cfg, client=client, ledger_path=ledger_path,
                max_llm_findings=int(
                    hunt_cfg.get("verify_max_llm_findings", 64) or 64))
            stage.notes.extend(vrep.notes)
            result.verification_notes.extend(vrep.notes)
            result.llm_calls += int(getattr(vrep, "llm_calls", 0) or 0)
            if not result.verification_ledger:
                result.verification_ledger = str(
                    getattr(vrep, "ledger_path", "") or "")
            kept = list(vrep.kept)
            stage.findings = len(vrep.dropped)
            if vrep.ai_inactive:
                result.offline_notes.append(
                    "AI debate over findings was skipped (no API keys); "
                    "machine-evidence re-runs still applied.")
        except Exception as exc:  # noqa: BLE001
            stage.ran = False
            stage.skipped_reason = f"verification crashed: {exc}"
            LOGGER.exception("verification stage failed")
            kept = [f for f in pending if f.status == "POTENTIAL"]
        result.stages.append(stage)
    survivors = [f for f in result.static_findings] + [
        f for f in kept if f.status != "REJECTED"]
    # De-duplicate by fingerprint while preserving order.
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in survivors:
        fingerprint = finding.fingerprint or _fingerprint(finding)
        finding.fingerprint = fingerprint
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        unique.append(finding)
    result.findings = unique
    result.rejected = [f for f in result.ai_findings
                       if f.status == "REJECTED"]
    _ = hook_verified  # already counted inside ai_findings / rejected

    # -- stage: history -----------------------------------------------
    hist_mode = (history or str(hunt_cfg.get("history", "auto"))).lower()
    hist_report_path = Path(history_report) if history_report else None
    cfg_report = str(hunt_cfg.get("audit_report") or "").strip()
    hist_available = (hist_report_path is not None) or bool(cfg_report)
    hist_wanted = hist_mode == "on" or (hist_mode == "auto")
    if skip_history or hist_mode == "off":
        result.stages.append(HuntStage(
            name="history", ran=False,
            skipped_reason="skipped by --skip-history / config"))
    elif hist_mode == "auto" and not hist_available and not resolved.is_dir():
        result.stages.append(HuntStage(
            name="history", ran=False,
            skipped_reason="history skipped: no audit report supplied and "
                           "the target is not a local git repo"))
    elif not hist_wanted:
        result.stages.append(HuntStage(
            name="history", ran=False, skipped_reason="skipped"))
    else:
        say("stage 5/5: version history")
        stage = HuntStage(name="history", ran=True)
        try:
            summary, redive_added, hist_notes = _history_stage(
                resolved, cfg, workdir_path, hist_report_path, since_tag)
            stage.notes.extend(hist_notes)
            result.history = summary
            result.redive_added = redive_added
            if summary is None:
                stage.skipped_reason = "; ".join(hist_notes) or \
                    "no version history available"
                stage.ran = False
        except Exception as exc:  # noqa: BLE001
            stage.ran = False
            stage.skipped_reason = f"history stage crashed: {exc}"
            LOGGER.exception("history stage failed")
        result.stages.append(stage)

    # -- costs ----------------------------------------------------------
    try:
        tracker = client.cost_tracker() \
            if hasattr(client, "cost_tracker") else None
        if tracker is not None:
            result.cost_usd = float(tracker.total_cost() or 0.0)
    except Exception:  # noqa: BLE001
        result.cost_usd = 0.0

    result.finished_at = datetime.datetime.now(datetime.UTC).isoformat()
    if out_dir is not None:
        write_hunt_report(result, Path(out_dir),
                          formats=formats or ["md", "txt", "json"])
    return result


# ---------------------------------------------------------------------------
# Plain-English reporting
# ---------------------------------------------------------------------------


_CATEGORY_PLAIN: dict[str, str] = {
    "reentrancy": "a function that sends money before updating its own records, so an attacker can call back in and withdraw twice",
    "reentrancy-eth": "a function that sends money before updating its own records, so an attacker can call back in and withdraw twice",
    "access-control": "a sensitive function that anyone on the internet can call, not just the owner or an authorized user",
    "missing-access-control": "a sensitive function that anyone on the internet can call, not just the owner or an authorized user",
    "unprotected": "a sensitive function that anyone on the internet can call, not just the owner or an authorized user",
    "integer-overflow": "math that can wrap around past its maximum value, letting an attacker turn a small number into a huge one (or vice versa)",
    "unchecked-call": "a call to another contract whose failure is silently ignored, so the contract keeps going as if it succeeded",
    "unchecked-return": "a call to another contract whose failure is silently ignored, so the contract keeps going as if it succeeded",
    "tx-origin": "using the original transaction sender for authorization, which a malicious contract can abuse to impersonate you",
    "timestamp-dependence": "relying on the block timestamp for important logic, which miners can nudge a little in their favor",
    "front-running": "logic whose outcome changes depending on transaction ordering, letting attackers jump ahead of victims",
    "dos": "a pattern that can make a function permanently unusable (denial of service), e.g. by making it always run out of gas",
    "unbounded-loop": "a loop over a list that can grow without limit, eventually making the function too expensive to ever run",
    "centralization": "a single privileged account that can change critical rules or drain funds with no checks",
    "price-manipulation": "a price or exchange rate read from somewhere an attacker can temporarily distort",
    "oracle-manipulation": "a price or exchange rate read from somewhere an attacker can temporarily distort",
    "flash-loan": "logic that can be abused within a single transaction using a large temporary (flash) loan",
    "erc20-approval": "token approval handling that can leave stale allowances attackers can spend",
    "erc4626": "a vault accounting issue where share prices can be manipulated, especially on the first deposit",
    "invariant-violation": "a broken business rule the fuzzer proved false by running thousands of random transaction sequences",
    "redteam": "an attack idea dreamed up by the AI playing the attacker's side",
}


def _plain_category(category: str) -> str:
    key = (category or "").strip().lower().replace("_", "-").replace(" ", "-")
    if key in _CATEGORY_PLAIN:
        return _CATEGORY_PLAIN[key]
    for known, text in _CATEGORY_PLAIN.items():
        if known in key or key in known:
            return text
    return "a suspicious code pattern worth a human look"


def _severity_word(severity: str) -> str:
    return {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
            "LOW": "low", "INFO": "informational"}.get(
                str(severity).upper(), str(severity).lower())


def _status_meaning(status: str) -> str:
    status = str(status).upper()
    if status == "CONFIRMED EXPLOIT":
        return ("CONFIRMED EXPLOIT — the tool re-ran the attack itself and "
                "it worked. This is as close to proof as automation gets.")
    if status == "REJECTED":
        return ("REJECTED — the tool checked this and threw it away "
                "(it is not shown as a live finding).")
    return ("POTENTIAL — it looks suspicious to the scanner but was not "
            "proven with a working demonstration. Worth a human look; it "
            "could still turn out to be a false alarm.")


def _evidence_meaning(finding: Finding) -> str:
    ver = finding.metadata.get("verification") or {}
    tier = str(ver.get("tier", "") or "")
    if tier == "machine":
        return ("Machine-checked: the tool re-ran the exact attack steps "
                "and got the same result.")
    if tier == "adversarial":
        decision = str(ver.get("decision", "") or "")
        if decision == "keep":
            return ("Debated by AI: one AI argued the bug is real, another "
                    "argued it is a false alarm, and the judge sided with "
                    "keeping it.")
        return "Reviewed by the AI debate process."
    if finding.metadata.get("machine_check"):
        return ("Comes with a machine-checkable proof (e.g. the exact "
                "transaction sequence that breaks a rule).")
    return ""


def _finding_title(finding: Finding) -> str:
    desc = (finding.description or "").strip()
    if (finding.category or "").lower() == "invariant-violation" and desc:
        # "Foundry invariant fuzzing broke 'tmpl-x': <rule statement>" ->
        # lead with the broken rule in plain words.
        rule = desc.split(":", 1)[1].strip() if ":" in desc else desc
        rule = rule.split(".")[0].strip()
        if rule:
            return f"Broken business rule: {rule[:140]}"
    first = desc.split("\n")[0]
    if first and len(first) <= 140:
        return first
    category = (finding.category or "issue").replace("-", " ").replace("_", " ")
    where = finding.function or finding.file.split("/")[-1]
    return f"{category} in {where}" if where else category


def _fmt_list(items: Sequence[str]) -> str:
    return "\n".join(f"- {item}" for item in items)


def render_hunt_markdown(result: HuntResult) -> str:
    """Plain-English markdown report for a non-technical reader."""
    lines = ["# Web3Guard Hunt Report", ""]
    lines.append(f"**Target:** `{result.target}`")
    if result.resolved_path:
        lines.append(f"**Scanned code:** `{result.resolved_path}`")
    lines.append(f"**Date:** {result.started_at[:10]}")
    lines.append("")
    if result.error:
        lines.append("> **The target could not be scanned.**")
        lines.append(">")
        lines.append(f"> {result.error}")
        lines.append("")
        lines.append("This usually means a typo in the path or URL. "
                     "A target that was never scanned must never look "
                     "like a clean scan, so double-check the target and "
                     "run again.")
        lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    # -- what ran -----------------------------------------------------
    lines.append("## What I checked, and what I skipped")
    lines.append("")
    lines.append("Think of the hunt as five separate inspectors. "
                 "Here is which ones showed up for work:")
    lines.append("")
    for stage in result.stages:
        if stage.ran:
            lines.append(
                f"- **{stage.name}**: ran"
                + (f" — {stage.findings} finding(s)" if stage.name != "verify"
                   else f" — {stage.findings} thrown away"))
        else:
            lines.append(f"- **{stage.name}**: skipped — {stage.skipped_reason}")
        for note in stage.notes[:4]:
            clean = note.split(": ", 1)[-1] if ": " in note[:60] else note
            lines.append(f"  - {clean[:220]}")
    lines.append("")
    for note in result.offline_notes:
        for line in note.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith(">"):
                lines.append(stripped)
            else:
                lines.append(f"> {stripped}")
    if result.offline_notes:
        lines.append("")
    for note in result.notes:
        if "API" in note or "AI" in note:
            continue
        lines.append(f"- Note: {note}")
    lines.append("")

    # -- what could NOT be checked --------------------------------------
    # Weakness-hunt round, target 2: a compile/render failure anywhere in
    # the pipeline is an explicit INCONCLUSIVE verdict. It must NEVER read
    # as a clean "no findings" — this section makes that impossible.
    if result.inconclusive:
        lines.append(f"## What I could NOT check ({len(result.inconclusive)})")
        lines.append("")
        lines.append("These targets could not be fuzz-tested — usually the "
                     "test setup failed to compile, which is a problem with "
                     "the test rig, not proof your code is broken. **A "
                     "missing check is not a clean bill of health:** treat "
                     "everything below as unknown, not safe.")
        lines.append("")
        for inc in result.inconclusive:
            lines.append(f"- {inc[:400]}")
        lines.append("")

    # -- findings ------------------------------------------------------
    lines.append(f"## What I found ({len(result.findings)})")
    lines.append("")
    if not result.findings:
        lines.append("No surviving findings. That means either the code "
                     "looks clean to every inspector that ran, or the "
                     "inspectors that could have found something were "
                     "among the skipped ones above — check the skip "
                     "reasons before celebrating.")
        if result.inconclusive:
            lines.append("")
            lines.append("**Important:** the \"What I could NOT check\" "
                         "section above lists targets that were never "
                         "actually tested. \"No findings\" does not cover "
                         "them.")
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for finding in sorted(result.findings,
                          key=lambda f: order.get(str(f.severity).upper(), 5)):
        sev = _severity_word(finding.severity)
        lines.append(f"### [{finding.severity}] {_finding_title(finding)}")
        lines.append("")
        lines.append(f"In plain terms, this is {_plain_category(finding.category)}.")
        lines.append("")
        lines.append(f"- **Where:** `{finding.file}`"
                    + (f" (function `{finding.function}`)"
                       if finding.function else ""))
        lines.append(f"- **How bad:** {sev}")
        lines.append(f"- **Status:** {_status_meaning(finding.status)}")
        meaning = _evidence_meaning(finding)
        if meaning:
            lines.append(f"- **Why trust it:** {meaning}")
        source = finding.metadata.get("hunt_source", "")
        if source:
            lines.append(f"- **Found by:** {source}")
        lines.append("")
    lines.append("")

    # -- rejected ------------------------------------------------------
    if result.rejected:
        lines.append(
            f"## What I double-checked and threw away ({len(result.rejected)})")
        lines.append("")
        lines.append("These looked suspicious at first but did not survive "
                     "verification, so they are not counted as findings. "
                     "Every decision is also written to the local audit "
                     "ledger"
                     + (f" (`{result.verification_ledger}`)"
                        if result.verification_ledger else "")
                     + ".")
        lines.append("")
        for finding in result.rejected[:25]:
            reason = (finding.metadata.get("rejection_reason")
                      or "evidence did not hold up")[:220]
            lines.append(
                f"- {_finding_title(finding)} "
                f"(`{finding.file}`): {reason}")
        if len(result.rejected) > 25:
            lines.append(f"- …and {len(result.rejected) - 25} more "
                         "(see the JSON report).")
        lines.append("")

    # -- history --------------------------------------------------------
    if result.history:
        hist = result.history
        lines.append("## What changed between versions")
        lines.append("")
        versions = hist.get("versions", [])
        if hist.get("report_title"):
            lines.append(f"Audit report: *{hist['report_title']}*"
                         + (f" by {hist['report_auditor']}"
                            if hist.get("report_auditor") else ""))
            lines.append("")
        per_version = (hist.get("verdicts") or {}).get("per_version", {})
        for version in versions:
            counts = per_version.get(version, {})
            if not counts:
                lines.append(f"- **{version}**: compared "
                             f"({sum(counts.values())} audit issues tracked)")
                continue
            bits = []
            if counts.get("fixed"):
                bits.append(f"{counts['fixed']} fully fixed")
            if counts.get("band_aid"):
                bits.append(f"{counts['band_aid']} patched only on the surface")
            if counts.get("still_open"):
                bits.append(f"{counts['still_open']} still open")
            if counts.get("regressed"):
                bits.append(f"{counts['regressed']} came back after being fixed")
            lines.append(f"- **{version}**: "
                         + (", ".join(bits) if bits else "no audit issues tracked"))
        lines.append("")
        lines.append("A quick decoder for the verdicts: **fully fixed** "
                     "means the risky pattern is gone; **patched only on "
                     "the surface** means the exact reported spot was "
                     "patched but the same risky pattern still exists "
                     "somewhere else (this is the one to chase); **still "
                     "open** means nothing changed; **came back** means "
                     "it was fixed once and the problem returned.")
        lines.append("")
        for item in hist.get("per_finding", [])[:20]:
            timeline = item.get("timeline", {})
            if not timeline:
                continue
            trail = ", ".join(
                f"{ver}: {plain_verdict(timeline[ver])}" for ver in versions
                if ver in timeline)
            lines.append(f"- *{item.get('title', item.get('id'))}* "
                         f"({item.get('severity', '')}): {trail}")
        if len(hist.get("per_finding", [])) > 20:
            lines.append(f"- …and {len(hist['per_finding']) - 20} more "
                         "(see the JSON report).")
        lines.append("")

    # -- re-dive ---------------------------------------------------------
    if result.redive_added:
        lines.append("## Worth a second look")
        lines.append("")
        lines.append("These are old audit issues that were only "
                     "surface-patched, came back, or are still open — "
                     "the highest-value places to dig deeper:")
        lines.append("")
        for item in result.redive_added:
            lines.append(f"- {item.get('title', item.get('finding_id'))}: "
                         f"{item.get('reason', '')}")
        lines.append("")

    # -- next steps ------------------------------------------------------
    lines.append("## What to do next")
    lines.append("")
    steps: list[str] = []
    sev_counts: dict[str, int] = {}
    for finding in result.findings:
        sev_counts[finding.severity] = sev_counts.get(finding.severity, 0) + 1
    if sev_counts.get("CRITICAL") or sev_counts.get("HIGH"):
        n = sev_counts.get("CRITICAL", 0) + sev_counts.get("HIGH", 0)
        steps.append(
            f"Start with the {n} critical/high finding(s) above — have a "
            "developer confirm each one, then fix and re-run the hunt to "
            "confirm the fix.")
    elif result.findings:
        steps.append("No critical or high findings survived. Review the "
                     "remaining findings with a developer and decide which "
                     "are worth fixing.")
    else:
        steps.append("No surviving findings. If any inspector was skipped "
                     "above, consider enabling it for a deeper pass.")
    if not result.ai_active:
        steps.append("Turn on the AI inspectors: get a free API key "
                     "(Google AI Studio or Groq both have free tiers), put "
                     "it in your environment as described in docs/HUNT.md, "
                     "and re-run — the AI red-team and the AI debate over "
                     "findings only run with keys present.")
    if result.history is None:
        steps.append("If this project had a past audit report, re-run with "
                     "`--history-report <report.md>` to get per-version "
                     "fix verdicts (what was truly fixed vs. just patched "
                     "on the surface).")
    if result.redive_added:
        steps.append("Work through the 'Worth a second look' list above — "
                     "surface-patched and regressed issues are where bug "
                     "bounties most often hide.")
    steps.append("Nothing in this report was sent anywhere, and nothing "
                 "will be: this tool never submits findings to bounty "
                 "programs. Filing a report is always your decision, made "
                 "by hand.")
    lines.append(_fmt_list(steps))
    lines.append("")
    lines.append("## Costs")
    lines.append("")
    lines.append(f"Total AI spend for this hunt: **${result.cost_usd:.4f}** "
                 f"({result.llm_calls} AI calls). The free-tier providers "
                 "cost $0 by default.")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_hunt_text(result: HuntResult) -> str:
    """Plain-text variant of the markdown report (chat-friendly)."""
    md = render_hunt_markdown(result)
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", md)
    text = re.sub(r"^#{1,4} ", "", text, flags=re.MULTILINE)
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"^> ?", "", text, flags=re.MULTILINE)
    return text.rstrip() + "\n"


def hunt_report_dict(result: HuntResult) -> dict[str, Any]:
    """Machine-readable report: full findings incl. machine evidence."""
    return {
        "hunt": {
            "target": result.target,
            "resolved_path": result.resolved_path,
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "ai_active": result.ai_active,
            "cost_usd": result.cost_usd,
            "llm_calls": result.llm_calls,
            "error": result.error,
            "offline_notes": result.offline_notes,
            "notes": result.notes,
            "inconclusive": result.inconclusive,
            "verification_notes": result.verification_notes,
            "verification_ledger": result.verification_ledger,
        },
        "stages": [dataclasses.asdict(s) for s in result.stages],
        "findings": [dataclasses.asdict(f) for f in result.findings],
        "rejected": [dataclasses.asdict(f) for f in result.rejected],
        "ai_findings_pre_verify": len(result.ai_findings),
        "history": result.history,
        "redive_added": result.redive_added,
        "report_paths": result.report_paths,
    }


def write_hunt_report(
    result: HuntResult,
    out_dir: Path | str,
    formats: Sequence[str] | None = None,
) -> dict[str, Path]:
    """Write the hunt report files; returns {format: path}."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    wanted = [str(f).lower() for f in (formats or ["md", "txt", "json"])]
    written: dict[str, Path] = {}
    renderers: dict[str, Callable[[HuntResult], str]] = {
        "md": render_hunt_markdown,
        "txt": render_hunt_text,
        "json": lambda r: json.dumps(hunt_report_dict(r), indent=2,
                                     default=str) + "\n",
    }
    for fmt in wanted:
        alias = "md" if fmt == "markdown" else fmt
        if alias not in renderers:
            raise ValueError(f"unsupported hunt report format: {fmt!r}")
        path = out / _REPORT_FILENAMES[alias]
        path.write_text(renderers[alias](result), encoding="utf-8")
        written[alias] = path
    result.report_paths = {k: str(v) for k, v in written.items()}
    return written


# ---------------------------------------------------------------------------
# Trigger consumer: `web3guard watch`
# ---------------------------------------------------------------------------


def _trigger_target(trigger: Any) -> str | None:
    """Local code path for a trigger, or None when it is address-only."""
    if getattr(trigger, "kind", "") == "git_tag":
        return getattr(trigger, "repo_path", "") or None
    return None


def drain_trigger_queue(
    workdir: Path | str,
    config: Mapping[str, Any] | Path | str | None = None,
    *,
    max_triggers: int = 0,
    hunt_kwargs: dict[str, Any] | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Consume the phase-5 upgrade-trigger queue with the hunt pipeline.

    Safe to run repeatedly: triggers are claimed via the queue's ``pop``
    (never double-delivered), processed results are recorded per
    trigger-id (never double-processed), and a crash between claim and
    completion re-queues the trigger on the next run. Never submits
    anything anywhere — results are local report files only.
    """
    from web3guard.discovery.targeting_state import open_targeting_state
    from web3guard.discovery.upgrade_watch import TriggerQueue, UpgradeTrigger

    say = progress or (lambda _msg: None)
    workdir_path = Path(workdir)
    state = open_targeting_state(workdir_path)
    queue = TriggerQueue(state)
    hunt_kwargs = dict(hunt_kwargs or {})

    # Crash recovery: triggers claimed but never finished get re-queued.
    orphan_prefix = "watch:processing:"
    try:
        processing_keys = [
            key for key in _state_keys(state)
            if key.startswith(orphan_prefix)]
    except Exception:  # noqa: BLE001
        processing_keys = []
    requeued = 0
    for key in processing_keys:
        raw = state.get(key)
        state.delete(key)
        if isinstance(raw, dict):
            try:
                queue.push(UpgradeTrigger.from_dict(raw))
                requeued += 1
            except Exception:  # noqa: BLE001
                LOGGER.warning("dropping unparseable orphan trigger %s", key)

    summary: dict[str, Any] = {
        "requeued_orphans": requeued,
        "processed": 0,
        "skipped": 0,
        "errors": 0,
        "results": [],
    }
    while True:
        if max_triggers and summary["processed"] + summary["skipped"] \
                + summary["errors"] >= max_triggers:
            break
        trigger = queue.pop()
        if trigger is None:
            break
        trigger_id = trigger.trigger_id
        done_key = f"watch:done:{trigger_id}"
        if state.get(done_key):
            summary["skipped"] += 1  # already processed: never do it twice
            continue
        state.set(f"watch:processing:{trigger_id}", trigger.to_dict())
        target = _trigger_target(trigger)
        started_ts = time.time()
        record: dict[str, Any] = {
            "trigger_id": trigger_id,
            "kind": trigger.kind,
            "project": trigger.project,
            "old_version": trigger.old_version,
            "new_version": trigger.new_version,
        }
        try:
            if target is None:
                record.update({
                    "status": "skipped",
                    "reason": ("address-only trigger (proxy upgrade): no "
                               "local code to scan. Resolve the new "
                               "implementation to source and run "
                               "`web3guard hunt <path>` manually."),
                })
                summary["skipped"] += 1
            else:
                say(f"watch: hunting {trigger.project} "
                    f"({trigger.old_version} -> {trigger.new_version})")
                hunt_out = (workdir_path / "hunt-reports" / "watch" /
                            f"{trigger.project}-{trigger_id}")
                result = run_hunt(
                    target, config, workdir=workdir_path,
                    out_dir=hunt_out, **hunt_kwargs)
                record.update({
                    "status": "completed",
                    "findings": len(result.findings),
                    "rejected": len(result.rejected),
                    "reports": result.report_paths,
                    "error": result.error,
                })
                summary["processed"] += 1
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("watch: hunt failed for trigger %s", trigger_id)
            record.update({"status": "error", "reason": str(exc)[:500]})
            summary["errors"] += 1
        record["elapsed_seconds"] = round(time.time() - started_ts, 1)
        state.set(f"watch:result:{trigger_id}", record)
        state.delete(f"watch:processing:{trigger_id}")
        state.set(done_key, {"at": time.time(), "status": record["status"]})
        try:
            state.record_event(
                "watch_trigger_processed", key=trigger.project,
                payload={"trigger_id": trigger_id,
                         "status": record["status"]})
        except Exception:  # noqa: BLE001
            pass
        summary["results"].append(record)
    return summary


def _state_keys(state: Any) -> list[str]:
    """Best-effort listing of this namespace's keys in the StateStore.

    Keys are returned *without* the namespace prefix, matching what
    :meth:`StateStore.get`/:meth:`StateStore.set` expect.
    """
    try:
        local = state._store.local
        rows = local.query_all("SELECT k FROM state_kv")
    except Exception:  # noqa: BLE001
        return []
    namespace = str(getattr(state, "_ns", "") or "")
    prefix = f"{namespace}:" if namespace else ""
    keys: list[str] = []
    for row in rows or []:
        full = str(row["k"]) if isinstance(row, dict) else str(row[0])
        if prefix and full.startswith(prefix):
            full = full[len(prefix):]
        keys.append(full)
    return keys


def _trigger_id_for(summary: dict[str, Any]) -> str:
    digest = hashlib.sha256(
        json.dumps(summary, sort_keys=True, default=str).encode()
    ).hexdigest()
    return digest[:16]

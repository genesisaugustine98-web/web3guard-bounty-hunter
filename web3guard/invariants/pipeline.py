"""End-to-end invariant pipeline (Phase 2 orchestration, Phase 6 multi-language).

:func:`run_invariant_pipeline` is the single entry point phase 7 will call::

    findings = run_invariant_pipeline(contract_path, config)

Steps: read source -> detect language -> synthesize invariants (LLM +
templates) -> proof-gate stage 1 (validate rules pre-render) -> render a
language-specific fuzz project (ghost-state harness when temporal templates
apply) -> fuzz it sandboxed -> proof-gate stage 2 (no finding without
machine proof) -> return :class:`Finding` objects.

The pipeline NEVER requires AI keys and NEVER fails a scan: every
degradation (AI inactive, toolchain missing, compile failure, timeout) is a
loud skip with a note, never an exception escaping to the caller.
"""

from __future__ import annotations

import logging
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from web3guard.ai.router import build_router_client
from web3guard.invariants import cairo_harness as _cairo_harness  # noqa: F401
from web3guard.invariants import proof_gate as _proof_gate
from web3guard.invariants import templates as _templates
from web3guard.invariants import vyper_harness as _vyper_harness  # noqa: F401
from web3guard.invariants.fuzz import (
    discover_forge,
    run_echidna_fallback,
    run_fuzz_campaign,
)

# The two imports above are load-bearing: importing the harness modules
# runs their ``register_renderer(...)`` calls, which is what makes
# render_project("vyper"/"cairo", ...) resolve.
from web3guard.invariants.fuzz_cairo import run_cairo_campaign
from web3guard.invariants.fuzz_vyper import run_vyper_campaign
from web3guard.invariants.harness import (
    extract_contract_name,
    render_project,
    write_project,
)
from web3guard.invariants.models import (
    CampaignResult,
    FuzzBounds,
    Invariant,
    PipelineResult,
)
from web3guard.invariants.synthesize import synthesize_invariants
from web3guard.scanner import Finding

LOGGER = logging.getLogger("web3guard.invariants.pipeline")

#: Languages with a registered harness renderer AND a runnable local
#: toolchain (Phase 6). Renderer registration = language support; toolchain
#: detection = execution. Anything else degrades to an honest skip.
SUPPORTED_LANGUAGES = ("solidity", "vyper", "cairo")

#: File suffix -> language key. Suffixes mapped to "" are recognized but
#: have no runnable harness yet (see web3guard/invariants/LANGUAGE_GAPS.md).
_SUFFIX_LANGUAGES = {
    ".sol": "solidity",
    ".vy": "vyper",
    ".cairo": "cairo",
    ".move": "",
    ".clar": "",
    ".fc": "",
    ".func": "",
    ".rs": "",
    ".ts": "",
}


def detect_language(contract_path: Path) -> str:
    """Map a contract file to a renderer language key ("" if unsupported)."""
    return _SUFFIX_LANGUAGES.get(contract_path.suffix.lower(), "")


def _safe_contract_name(path: Path, language: str, source: str) -> str:
    """Best-effort contract name: Solidity parses its own; others use the file stem."""
    if language == "solidity":
        return extract_contract_name(source)
    stem = re.sub(r"\W", "_", path.stem) or "Target"
    if stem[0].isdigit():
        stem = "C_" + stem
    return stem


def run_invariant_pipeline_full(
    contract_path: str | Path,
    config: Mapping[str, Any] | None,
    *,
    notes: list[str] | None = None,
) -> PipelineResult:
    """Run the full pipeline; return findings plus run notes and metadata."""
    result = PipelineResult()
    note_sink: list[str] = notes if notes is not None else []
    result.notes = note_sink

    path = Path(contract_path)
    if not path.is_file():
        msg = f"invariant pipeline: contract not found: {path}; skipping."
        LOGGER.warning(msg)
        note_sink.append(msg)
        return result
    try:
        source = path.read_text(errors="ignore")
    except OSError as exc:
        msg = f"invariant pipeline: cannot read {path} ({exc}); skipping."
        LOGGER.warning(msg)
        note_sink.append(msg)
        return result
    if not source.strip():
        msg = f"invariant pipeline: {path} is empty; skipping."
        LOGGER.warning(msg)
        note_sink.append(msg)
        return result

    language = detect_language(path)
    if language not in SUPPORTED_LANGUAGES:
        if language == "" and path.suffix.lower() in _SUFFIX_LANGUAGES:
            msg = (
                f"invariant pipeline: {path.suffix} contracts recognized but "
                "no runnable invariant harness exists yet "
                "(see web3guard/invariants/LANGUAGE_GAPS.md); skipping."
            )
        else:
            msg = (
                f"invariant pipeline: no harness renderer for "
                f"{path.suffix or 'unknown'} files "
                f"(supported: {', '.join(SUPPORTED_LANGUAGES)}); skipping."
            )
        LOGGER.info(msg)
        note_sink.append(msg)
        return result

    contract_name = _safe_contract_name(path, language, source)
    label = f"{path.name}:{contract_name}"

    # 1. Synthesize invariants (templates always; LLM when keys exist).
    client = build_router_client(config)
    synthesis = synthesize_invariants(
        source, client, config, contract_name=contract_name, language=language,
    )
    note_sink.extend(synthesis.notes)

    # 1b. Proof gate, stage 1 (Phase 3): validate every rule BEFORE it can
    # reach the fuzzer. Mechanically-bad rules (unknown functions, tautologies)
    # are quarantined LOUDLY instead of killing the campaign at compile time.
    validation = _proof_gate.validate_rules(
        synthesis.invariants,
        source,
        language=language,
        ghost_ids=_templates.GHOST_TEMPLATE_IDS,
        handler_refs=_templates.handler_reference_names(),
        body_ids=_templates.BODY_TEMPLATE_IDS,
    )
    for q in validation.quarantined:
        msg = (
            f"invariant rule '{q.invariant_id}' QUARANTINED pre-render: "
            f"{q.reason} — the rule will not run."
        )
        LOGGER.warning(msg)
        note_sink.append(msg)
        result.quarantined_rules.append(
            {"invariant_id": q.invariant_id, "reason": q.reason, "stage": q.stage}
        )
    note_sink.extend(validation.notes)
    invariants = validation.valid
    result.invariants = invariants
    if not invariants:
        msg = (
            f"invariant pipeline: no invariants applied to {label} "
            "(no matching templates and no AI output"
            + (
                f"; {len(validation.quarantined)} rule(s) quarantined"
                if validation.quarantined
                else ""
            )
            + "); skipping fuzzing."
        )
        LOGGER.info(msg)
        note_sink.append(msg)
        return result
    LOGGER.info(
        "invariant pipeline: %d invariant(s) for %s (ai_used=%s, quarantined=%d)",
        len(invariants), label, synthesis.ai_used, len(validation.quarantined),
    )

    # 1c. Resolve ghost templates (Phase 3): drop ghost rules whose tracked
    # calls cannot be wired safely; they would otherwise desync accounting.
    invariants, ghost_notes = _templates.resolve_ghost_templates(invariants, source)
    note_sink.extend(ghost_notes)
    if not invariants:
        msg = (
            f"invariant pipeline: no runnable invariants for {label} "
            "(all rules quarantined or unresolvable); skipping fuzzing."
        )
        LOGGER.info(msg)
        note_sink.append(msg)
        return result
    ghost_mode = language == "solidity" and _templates.needs_ghost_mode(invariants)
    if ghost_mode:
        n_ghost = sum(1 for i in invariants if i.id in _templates.GHOST_TEMPLATE_IDS)
        note_sink.append(
            f"invariant pipeline: ghost-state harness active for {label} "
            f"({n_ghost} temporal invariant(s)): calls are routed through a "
            "handler that keeps ghost variables in lockstep, so properties "
            "like 'withdrawn never exceeds deposited' are checkable."
        )

    # 2. Render the language-specific fuzz project. A ValueError means the
    #    source cannot be turned into a runnable harness (e.g. a Cairo file
    #    without #[starknet::contract]) — an honest skip, not a crash.
    bounds = FuzzBounds.from_config(config)
    try:
        if ghost_mode:
            files, render_notes = _templates.render_ghost_project(
                source, contract_name, invariants, bounds,
            )
            note_sink.extend(render_notes)
        else:
            files = render_project(
                language, source, contract_name, invariants, bounds,
            )
    except ValueError as exc:
        msg = (
            f"invariant pipeline: cannot build a {language} fuzz project "
            f"for {label} ({exc}); skipping."
        )
        LOGGER.warning(msg)
        note_sink.append(msg)
        return result

    # 3. Fuzz with the language's toolchain (honest skip when missing).
    with tempfile.TemporaryDirectory(prefix="web3guard-invariants-") as tmp:
        project_dir = Path(tmp)
        campaign: CampaignResult | None
        findings: list[Finding]
        if language == "vyper":
            campaign, findings = _run_vyper_campaign(
                project_dir, files, invariants, bounds, config,
                contract_path=str(path), contract_name=contract_name,
                target_label=label, notes=note_sink,
            )
        elif language == "cairo":
            campaign, findings = _run_cairo_campaign(
                project_dir, files, invariants, bounds, config,
                contract_path=str(path), contract_name=contract_name,
                target_label=label, notes=note_sink,
            )
        else:
            campaign, findings = _run_solidity_campaign(
                project_dir, files, invariants, bounds, config,
                contract_path=str(path), contract_name=contract_name,
                target_label=label, notes=note_sink,
            )
        # Phase 3 proof gate, stage 2: no rule becomes a finding without
        # machine proof. Also detect rules that were already false at
        # deployment (bad RULE, not a bug) and quarantine them instead of
        # mislabeling the outcome as "did not compile".
        baseline_ids = _proof_gate.extract_baseline_failures(
            campaign.raw_stdout if campaign else "", invariants,
        )
        for bid in baseline_ids:
            msg = (
                f"invariant rule '{bid}' QUARANTINED post-campaign: violated "
                "at deployment with an empty call sequence — the rule "
                "contradicts the contract's own construction, so it cannot "
                "indicate a bug. No finding emitted."
            )
            LOGGER.warning(msg)
            note_sink.append(msg)
            result.quarantined_rules.append(
                {
                    "invariant_id": bid,
                    "reason": "violated at deployment (empty call sequence)",
                    "stage": "post-campaign",
                }
            )
        if baseline_ids:
            # The campaign compiled fine (forge said so); drop the misleading
            # generic note the runner may have added.
            note_sink[:] = [
                n for n in note_sink if "did not compile; see logs" not in n
            ]
        findings = _proof_gate.apply_proof_gate(
            findings, invariants, campaign,
            notes=note_sink, target_label=label,
        )
        result.campaign = campaign
        result.findings.extend(findings)
    return result


def _run_solidity_campaign(
    project_dir: Path,
    files: Mapping[str, str],
    invariants: list[Invariant],
    bounds: FuzzBounds,
    config: Mapping[str, Any] | None,
    *,
    contract_path: str,
    contract_name: str,
    target_label: str,
    notes: list[str],
) -> tuple[CampaignResult | None, list[Finding]]:
    """Forge preferred; echidna fallback; honest skip otherwise (Phase 2)."""
    if discover_forge(config):
        campaign, findings = run_fuzz_campaign(
            project_dir,
            files,
            invariants,
            bounds,
            config,
            contract_path=contract_path,
            contract_name=contract_name,
            target_label=target_label,
            notes=notes,
        )
        return campaign, findings
    write_project(project_dir, files)
    echo_findings = run_echidna_fallback(
        project_dir,
        contract_name,
        config,
        contract_path=contract_path,
        target_label=target_label,
        timeout=bounds.timeout_seconds,
    )
    if not echo_findings:
        msg = (
            "invariant pipeline: neither forge nor echidna is installed; "
            "fuzz campaign SKIPPED (static-only results stand). "
            "Install Foundry to ~/workspace/tools/foundry or set "
            "WEB3GUARD_FORGE_BIN."
        )
        LOGGER.warning(msg)
        notes.append(msg)
    return None, echo_findings


def _run_vyper_campaign(
    project_dir: Path,
    files: Mapping[str, str],
    invariants: list[Invariant],
    bounds: FuzzBounds,
    config: Mapping[str, Any] | None,
    *,
    contract_path: str,
    contract_name: str,
    target_label: str,
    notes: list[str],
) -> tuple[CampaignResult, list[Finding]]:
    """Titanoboa campaign; honest skip when the venv is absent (Phase 6)."""
    return run_vyper_campaign(
        project_dir,
        files,
        invariants,
        bounds,
        config,
        contract_path=contract_path,
        contract_name=contract_name,
        target_label=target_label,
        notes=notes,
    )


def _run_cairo_campaign(
    project_dir: Path,
    files: Mapping[str, str],
    invariants: list[Invariant],
    bounds: FuzzBounds,
    config: Mapping[str, Any] | None,
    *,
    contract_path: str,
    contract_name: str,
    target_label: str,
    notes: list[str],
) -> tuple[CampaignResult, list[Finding]]:
    """snforge campaign; honest skip when the toolchain is absent (Phase 6)."""
    return run_cairo_campaign(
        project_dir,
        files,
        invariants,
        bounds,
        config,
        contract_path=contract_path,
        contract_name=contract_name,
        target_label=target_label,
        notes=notes,
    )


def run_invariant_pipeline(
    contract_path: str | Path,
    config: Mapping[str, Any] | None,
    *,
    notes: list[str] | None = None,
) -> list[Finding]:
    """Run the invariant pipeline; return findings (phase 7 entry point).

    ``notes`` optionally collects human-readable run notes (skips,
    degradations) for the report. Never raises on pipeline-internal
    failures — worst case it returns [] with notes explaining why.
    """
    try:
        return run_invariant_pipeline_full(
            contract_path, config, notes=notes,
        ).findings
    except Exception as exc:  # noqa: BLE001 - the scan must survive us
        msg = f"invariant pipeline crashed ({exc}); continuing without it."
        LOGGER.exception(msg)
        if notes is not None:
            notes.append(msg)
        return []


__all__ = ["SUPPORTED_LANGUAGES", "run_invariant_pipeline", "run_invariant_pipeline_full"]

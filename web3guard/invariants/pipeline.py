"""End-to-end invariant pipeline (Phase 2 orchestration).

:func:`run_invariant_pipeline` is the single entry point phase 7 will call::

    findings = run_invariant_pipeline(contract_path, config)

Steps: read source -> synthesize invariants (LLM + templates) -> render a
Foundry project -> fuzz it sandboxed -> return :class:`Finding` objects.

The pipeline NEVER requires AI keys and NEVER fails a scan: every
degradation (AI inactive, forge missing, compile failure, timeout) is a
loud skip with a note, never an exception escaping to the caller.
"""

from __future__ import annotations

import logging
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from web3guard.ai.router import build_router_client
from web3guard.invariants.fuzz import (
    discover_forge,
    run_echidna_fallback,
    run_fuzz_campaign,
)
from web3guard.invariants.harness import (
    extract_contract_name,
    render_project,
    write_project,
)
from web3guard.invariants.models import (
    FuzzBounds,
    PipelineResult,
)
from web3guard.invariants.synthesize import synthesize_invariants
from web3guard.scanner import Finding

LOGGER = logging.getLogger("web3guard.invariants.pipeline")

#: Languages with a registered harness renderer (Phase 6 extends this).
SUPPORTED_LANGUAGES = ("solidity",)


def detect_language(contract_path: Path) -> str:
    """Map a contract file to a renderer language key."""
    if contract_path.suffix.lower() == ".sol":
        return "solidity"
    return ""


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
        msg = (
            f"invariant pipeline: no harness renderer for {path.suffix or 'unknown'} "
            f"files yet (Solidity only in phase 2; more languages in phase 6); skipping."
        )
        LOGGER.info(msg)
        note_sink.append(msg)
        return result

    contract_name = extract_contract_name(source)
    label = f"{path.name}:{contract_name}"

    # 1. Synthesize invariants (templates always; LLM when keys exist).
    client = build_router_client(config)
    synthesis = synthesize_invariants(
        source, client, config, contract_name=contract_name,
    )
    note_sink.extend(synthesis.notes)
    result.invariants = synthesis.invariants
    if not synthesis.invariants:
        msg = (
            f"invariant pipeline: no invariants applied to {label} "
            "(no matching templates and no AI output); skipping fuzzing."
        )
        LOGGER.info(msg)
        note_sink.append(msg)
        return result
    LOGGER.info(
        "invariant pipeline: %d invariant(s) for %s (ai_used=%s)",
        len(synthesis.invariants), label, synthesis.ai_used,
    )

    # 2. Render the Foundry project.
    bounds = FuzzBounds.from_config(config)
    files = render_project(
        language, source, contract_name, synthesis.invariants, bounds,
    )

    # 3. Fuzz (forge preferred; echidna fallback; honest skip otherwise).
    with tempfile.TemporaryDirectory(prefix="web3guard-invariants-") as tmp:
        project_dir = Path(tmp)
        if discover_forge(config):
            campaign, findings = run_fuzz_campaign(
                project_dir,
                files,
                synthesis.invariants,
                bounds,
                config,
                contract_path=str(path),
                contract_name=contract_name,
                target_label=label,
                notes=note_sink,
            )
            result.campaign = campaign
            result.findings.extend(findings)
        else:
            write_project(project_dir, files)
            echo_findings = run_echidna_fallback(
                project_dir,
                contract_name,
                config,
                contract_path=str(path),
                target_label=label,
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
                note_sink.append(msg)
            else:
                result.findings.extend(echo_findings)
    return result


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

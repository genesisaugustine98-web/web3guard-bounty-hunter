"""End-to-end invariant pipeline (Phase 2 orchestration, Phase 6 multi-language).

:func:`run_invariant_pipeline` is the single entry point phase 7 will call::

    findings = run_invariant_pipeline(contract_path, config)

Steps: read source -> detect language -> synthesize invariants (LLM +
templates) -> render a language-specific fuzz project -> fuzz it sandboxed
-> return :class:`Finding` objects.

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

    # 2. Render the language-specific fuzz project. A ValueError means the
    #    source cannot be turned into a runnable harness (e.g. a Cairo file
    #    without #[starknet::contract]) — an honest skip, not a crash.
    bounds = FuzzBounds.from_config(config)
    try:
        files = render_project(
            language, source, contract_name, synthesis.invariants, bounds,
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
                project_dir, files, synthesis.invariants, bounds, config,
                contract_path=str(path), contract_name=contract_name,
                target_label=label, notes=note_sink,
            )
        elif language == "cairo":
            campaign, findings = _run_cairo_campaign(
                project_dir, files, synthesis.invariants, bounds, config,
                contract_path=str(path), contract_name=contract_name,
                target_label=label, notes=note_sink,
            )
        else:
            campaign, findings = _run_solidity_campaign(
                project_dir, files, synthesis.invariants, bounds, config,
                contract_path=str(path), contract_name=contract_name,
                target_label=label, notes=note_sink,
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

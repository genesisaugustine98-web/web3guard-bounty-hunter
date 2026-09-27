"""Adaptive industry-tool capability and SCA adapters.

The scanner detects what is available, selects tools based on target contents,
and normalizes outputs into Web3Guard findings without retaining secret-bearing
payloads.
"""
from __future__ import annotations

import json
import logging
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from web3guard.discovery.base import safe_run_subprocess

LOGGER = logging.getLogger("web3guard.sota_tools")


@dataclass(frozen=True)
class ToolCapability:
    name: str
    binary: str
    installed: bool
    role: str
    mode: str = "automatic"
    notes: str = ""


def _installed(binary: str) -> bool:
    return shutil.which(binary) is not None


def capabilities() -> list[ToolCapability]:
    specs = (
        ("slither", "slither", "EVM static analysis"),
        ("aderyn", "aderyn", "EVM static analysis"),
        ("mythril", "myth", "EVM symbolic analysis"),
        ("echidna", "echidna-test", "EVM fuzzing/invariants"),
        ("gitleaks", "gitleaks", "secret detection"),
        ("semgrep", "semgrep", "multi-language code analysis"),
        ("osv-scanner", "osv-scanner", "dependency/SCA"),
        ("trivy", "trivy", "filesystem/dependency/IaC scanning"),
        ("gosec", "gosec", "Go security analysis"),
        ("staticcheck", "staticcheck", "Go static analysis"),
        ("codeql", "codeql", "deep dataflow analysis; CI-heavy"),
        ("nuclei", "nuclei", "authorized web/network template scanning"),
        ("zap", "zap.sh", "authorized web application scanning"),
        ("forge", "forge", "Solidity/Vyper build and PoC runner"),
        ("anchor", "anchor", "Solana/Anchor tests"),
        ("scarb", "scarb", "Cairo tests"),
        ("clarinet", "clarinet", "Clarity tests"),
        ("blueprint", "blueprint", "TON/FunC tests"),
        ("aptos", "aptos", "Move tests"),
    )
    out: list[ToolCapability] = []
    for name, binary, role in specs:
        mode = "automatic"
        notes = ""
        if name in {"codeql", "nuclei", "zap"}:
            mode = "opt-in"
            notes = "Invoked only by an explicit operator-controlled workflow."
        out.append(ToolCapability(name, binary, _installed(binary), role, mode, notes))
    return out


def capability_dicts() -> list[dict[str, object]]:
    return [c.__dict__.copy() for c in capabilities()]


def relevant_automatic_tools(target_path: Path) -> list[str]:
    names: list[str] = []
    files = {p.name.lower() for p in target_path.rglob("*") if p.is_file()}
    suffixes = {p.suffix.lower() for p in target_path.rglob("*") if p.is_file()}
    if any(x in files for x in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")):
        names.append("osv-scanner")
    if {"cargo.lock", "cargo.toml"} & files or ".rs" in suffixes:
        names.append("osv-scanner")
    if any(x in files for x in ("go.mod", "go.sum")) or ".go" in suffixes:
        names.extend(["osv-scanner", "gosec", "staticcheck"])
    if any(p.name.lower().endswith(".tf") for p in target_path.rglob("*") if p.is_file()):
        names.append("trivy")
    if any(x in files for x in ("dockerfile", "docker-compose.yml", "docker-compose.yaml")):
        names.append("trivy")
    return list(dict.fromkeys(names))


def _temp_json(prefix: str) -> Path:
    d = Path(tempfile.mkdtemp(prefix=f"web3guard-{prefix}-"))
    d.chmod(0o733)
    return d / f"{prefix}.json"


def _parse_osv(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for result in data.get("results", []) if isinstance(data, dict) else []:
        if not isinstance(result, dict):
            continue
        records = result.get("packages") or []
        if not records and result.get("package"):
            records = [{"package": result.get("package"), "vulnerabilities": result.get("vulnerabilities", [])}]
        for record in records:
            if not isinstance(record, dict):
                continue
            pkg = record.get("package") or {}
            for vuln in record.get("vulnerabilities", []) or []:
                if not isinstance(vuln, dict):
                    continue
                severity = "HIGH" if vuln.get("severity") else "MEDIUM"
                out.append({
                    "engine": "osv-scanner",
                    "category": "dependency-vulnerability",
                    "severity": severity,
                    "title": str(vuln.get("id") or "OSV vulnerability"),
                    "description": f"{pkg.get('name','unknown')} is affected by {vuln.get('id','an OSV-listed vulnerability')}",
                    "file": str(pkg.get("purl") or pkg.get("name") or "dependency"),
                    "line": 0,
                    "confidence": 0.94,
                    "raw": {"id": vuln.get("id"), "package": pkg.get("name"), "ecosystem": pkg.get("ecosystem")},
                })
    return out


def _parse_trivy(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for result in data.get("Results", []) if isinstance(data, dict) else []:
        target = result.get("Target", "filesystem") if isinstance(result, dict) else "filesystem"
        for vuln in result.get("Vulnerabilities", []) if isinstance(result, dict) else []:
            if not isinstance(vuln, dict):
                continue
            severity = str(vuln.get("Severity") or "MEDIUM").upper()
            if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
                severity = "MEDIUM"
            out.append({
                "engine": "trivy",
                "category": "dependency-vulnerability",
                "severity": severity,
                "title": str(vuln.get("VulnerabilityID") or "Trivy vulnerability"),
                "description": f"{vuln.get('PkgName','unknown')} {vuln.get('InstalledVersion','')} is affected by {vuln.get('VulnerabilityID','a known vulnerability')}",
                "file": str(target),
                "line": 0,
                "confidence": 0.92,
                "raw": {"id": vuln.get("VulnerabilityID"), "pkg": vuln.get("PkgName"), "severity": severity},
            })
    return out


def _parse_gosec_json(text: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(text)
    except Exception:
        return []
    issues = data.get("Issues", []) if isinstance(data, dict) else []
    out: list[dict[str, Any]] = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        sev = str(issue.get("severity") or "MEDIUM").upper()
        if sev not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            sev = "MEDIUM"
        out.append({
            "engine": "gosec",
            "category": "go-security",
            "severity": sev,
            "title": str(issue.get("rule_id") or "gosec issue"),
            "description": str(issue.get("details") or "gosec reported a security issue"),
            "file": str(issue.get("file") or "unknown"),
            "line": int(str(issue.get("line") or "0").split(":", 1)[0] or 0),
            "confidence": 0.9 if str(issue.get("confidence") or "HIGH").upper() == "HIGH" else 0.75,
            "raw": {"rule_id": issue.get("rule_id"), "file": issue.get("file"), "line": issue.get("line")},
        })
    return out


def _parse_staticcheck_jsonl(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        try:
            item = json.loads(line)
        except Exception:
            continue
        if not isinstance(item, dict):
            continue
        pos = item.get("location") or {}
        out.append({
            "engine": "staticcheck",
            "category": "go-static-analysis",
            "severity": "LOW",
            "title": str(item.get("code") or "staticcheck"),
            "description": str(item.get("message") or "staticcheck reported an issue"),
            "file": str(pos.get("file") or "unknown"),
            "line": int(pos.get("line") or 0),
            "confidence": 0.85,
            "raw": {"code": item.get("code"), "location": pos},
        })
    return out


def run_sca_suite(target_path: Path, *, timeout: int = 240) -> list[dict[str, Any]]:
    """Run lightweight SCA tools that are installed and relevant to a target."""
    findings: list[dict[str, Any]] = []
    available = {c.name: c.installed for c in capabilities()}
    for name in relevant_automatic_tools(target_path):
        if not available.get(name, False):
            continue
        try:
            if name == "osv-scanner":
                output = _temp_json("osv")
                rc, _, err = safe_run_subprocess(
                    ["osv-scanner", "scan", "source", "-r", str(target_path),
                     "--format", "json", "--output-file", str(output)],
                    cwd=target_path, timeout=timeout,
                )
                if output.is_file():
                    findings.extend(_parse_osv(output))
                elif rc not in (0, 1):
                    LOGGER.warning("osv-scanner failed: %s", err[-500:])
                shutil.rmtree(output.parent, ignore_errors=True)
            elif name == "trivy":
                output = _temp_json("trivy")
                rc, _, err = safe_run_subprocess(
                    ["trivy", "fs", "--format", "json", "--output", str(output),
                     "--scanners", "vuln,misconfig", str(target_path)],
                    cwd=target_path, timeout=timeout,
                )
                if output.is_file():
                    findings.extend(_parse_trivy(output))
                elif rc not in (0, 1):
                    LOGGER.warning("trivy failed: %s", err[-500:])
                shutil.rmtree(output.parent, ignore_errors=True)
            elif name == "gosec":
                rc, stdout, err = safe_run_subprocess(
                    ["gosec", "-fmt", "json", "./..."],
                    cwd=target_path, timeout=timeout,
                )
                findings.extend(_parse_gosec_json(stdout))
                if rc not in (0, 1):
                    LOGGER.warning("gosec failed: %s", err[-500:])
            elif name == "staticcheck":
                rc, stdout, err = safe_run_subprocess(
                    ["staticcheck", "-f", "json", "./..."],
                    cwd=target_path, timeout=timeout,
                )
                findings.extend(_parse_staticcheck_jsonl(stdout))
                if rc not in (0, 1):
                    LOGGER.warning("staticcheck failed: %s", err[-500:])
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("%s failed: %s", name, exc)
    return findings

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from web3guard.ai.cost import CostTracker
from web3guard.ai.provider import ChatResponse
from web3guard.reports import ReportBuilder
from web3guard.sandbox._generic import GenericSandbox
from web3guard.scanner import Finding, Scanner, ScanResult, load_config
from web3guard.security import SandboxGuard


class FakeAIClient:
    def __init__(self, responses: list[str]) -> None:
        self.responses = iter(responses)
        self._cost = CostTracker()

    def chat(self, *args: object, **kwargs: object) -> ChatResponse:
        return ChatResponse(content=next(self.responses), provider="fake", model="fake")

    def cost_tracker(self) -> CostTracker:
        return self._cost


def test_scanner_runs_offline_and_writes_reports(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "Example.sol").write_text(
        "pragma solidity ^0.8.24; contract Example { function ping() external {} }",
        encoding="utf-8",
    )
    analysis = json.dumps({
        "status": "vulnerable",
        "category": "access-control",
        "severity": "HIGH",
        "confidence": 0.9,
        "function": "ping",
        "swc_id": "SWC-105",
        "description": "The function is intentionally treated as vulnerable for this test.",
        "reasoning": "Regression fixture.",
        "line_hint": "1",
    })
    cfg = load_config(None)
    cfg.update({
        "enable_exploit": False,
        "enable_discovery": False,
        "enable_self_critique": False,
        "enable_secret_scan": False,
    })
    scanner = Scanner(config=cfg, ai_client=FakeAIClient([analysis]), workdir=tmp_path / "work")

    result = scanner.scan([str(target)], min_severity="LOW")

    assert len(result.all_findings) == 1
    assert len(result.all_findings[0].fingerprint) == 32
    assert (tmp_path / "work" / ".web3guard" / "findings.db").exists()
    paths = scanner.build_report(result, out_dir=tmp_path / "reports")
    assert set(paths) == {"txt", "json", "sarif", "md"}
    sarif = json.loads(paths["sarif"].read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1


def test_report_builder_handles_empty_results(tmp_path: Path) -> None:
    result = ScanResult(started_at="start", finished_at="end", config={})
    paths = ReportBuilder(result).write(tmp_path)
    assert all(path.exists() for path in paths.values())
    assert json.loads(paths["json"].read_text(encoding="utf-8"))["targets"] == []


def test_generic_sandbox_preserves_success_boolean(tmp_path: Path) -> None:
    runner = SimpleNamespace(
        build_command=(),
        test_command_template=("runner", "{test_name}"),
        poc_relative_path="tests/poc.txt",
    )
    adapter = SimpleNamespace(test_runner=runner)
    sandbox = GenericSandbox(adapter, tmp_path, tmp_path)
    sandbox._run = lambda *args, **kwargs: (True, "passed", "")  # type: ignore[method-assign]

    result = sandbox.run(tmp_path, tmp_path / "tests" / "poc.txt")

    assert result.ok is True
    assert result.returncode == 0


def test_sandbox_guard_is_usable_on_current_platform(tmp_path: Path) -> None:
    guard = SandboxGuard()
    report = guard.prepare_subprocess(["python", "--version"], cwd=tmp_path)
    guard.apply_resource_limits()
    assert report.cwd == str(tmp_path.resolve())
    assert "PATH" in report.env


def test_severity_filter_and_fingerprint_are_deterministic() -> None:
    finding = Finding(target="repo", language="solidity", file="A.sol", function="f", category="reentrancy")
    assert Scanner._severity_at_least("HIGH", "MEDIUM")
    assert not Scanner._severity_at_least("LOW", "HIGH")
    assert Scanner._fingerprint(finding) == Scanner._fingerprint(finding)


def test_user_code_filter_is_platform_independent() -> None:
    from web3guard.languages.solidity import SolidityAdapter

    adapter = SolidityAdapter()
    assert not adapter.is_user_code(Path(r"C:\repo\test\Attack.t.sol"))
    assert not adapter.is_user_code(Path(r"C:\repo\lib\Dependency.sol"))
    assert adapter.is_user_code(Path(r"C:\repo\src\Vault.sol"))

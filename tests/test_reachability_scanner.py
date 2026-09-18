"""Scanner integration tests for the reachability pre-filter."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.scanner import Finding, Scanner  # noqa: E402


class _Resp:
    def __init__(self, content: str) -> None:
        self.content = content


class _Cost:
    def summary(self) -> dict[str, object]:
        return {"total_cost_usd": 0.0}


class _NamedFunctionAI:
    def __init__(self, function: str, poc: str) -> None:
        self._function = function
        self._poc = poc
        self.chat_calls: list[dict] = []

    def chat(self, system: str, user: str, **kwargs):
        self.chat_calls.append({"system": system, "user": user, "kwargs": kwargs})
        if kwargs.get("role", "analysis") == "exploit":
            return _Resp(f"```solidity\n{self._poc}\n```")
        return _Resp(json.dumps({
            "status": "vulnerable",
            "category": "reentrancy",
            "severity": "HIGH",
            "confidence": 0.9,
            "function": self._function,
            "description": "reentrancy via external call",
            "reasoning": "call before state update",
            "line_hint": "7-9",
        }))

    def cost_tracker(self) -> _Cost:
        return _Cost()


class _FakeSandbox:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def write_and_run(self, code: str, fingerprint: str, timeout: int = 90):
        self.calls.append((code, fingerprint))
        return True, "impact_gain: 100\nPASSED"


def _poc() -> str:
    return (
        "pragma solidity ^0.8.0;\n"
        'import "forge-std/Test.sol";\n'
        "contract ExploitTest is Test {\n"
        "    function test_exploit() public {\n"
        "        uint before = 100;\n"
        "        uint after = 0;\n"
        "        assert(after < before);\n"
        '        emit log_named_uint("impact_gain", before - after);\n'
        "    }\n"
        "}\n"
    )


_UNREACHABLE = """\
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint) public balances;

    function _helper() internal {
        balances[msg.sender] = 0;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
"""


def _write(tmp_path: Path) -> Path:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "Vault.sol").write_text(_UNREACHABLE, encoding="utf-8")
    return project


def test_unreachable_finding_skips_poc_and_is_rejected(tmp_path: Path, monkeypatch):
    from web3guard import sandbox as sandbox_mod

    fake = _FakeSandbox()
    monkeypatch.setattr(sandbox_mod, "create_sandbox", lambda *a, **k: fake)
    project = _write(tmp_path)
    scanner = Scanner(
        config={"enable_ai_analysis": True, "enable_discovery": False,
                "enable_exploit": True, "max_exploit_attempts": 2,
                "enable_reachability": True},
        workdir=tmp_path / "work",
        ai_client=_NamedFunctionAI("_helper", _poc()),
    )
    result = scanner.scan([str(project) + "|max"])
    findings = result.targets[0].findings
    rejected = [f for f in findings if f.status == "REJECTED"]
    assert rejected, [f.status for f in findings]
    assert fake.calls == []
    assert rejected[0].metadata["reachability"]["verdict"] == "not_reachable"
    assert rejected[0].metadata["rejection_reason"] == "not externally reachable"


def test_reachable_finding_still_runs_poc(tmp_path: Path, monkeypatch):
    from web3guard import sandbox as sandbox_mod

    fake = _FakeSandbox()
    monkeypatch.setattr(sandbox_mod, "create_sandbox", lambda *a, **k: fake)
    project = _write(tmp_path)
    scanner = Scanner(
        config={"enable_ai_analysis": True, "enable_discovery": False,
                "enable_exploit": True, "max_exploit_attempts": 2,
                "enable_reachability": True, "enable_differential": False},
        workdir=tmp_path / "work",
        ai_client=_NamedFunctionAI("deposit", _poc()),
    )
    result = scanner.scan([str(project) + "|max"])
    findings = result.targets[0].findings
    assert findings and fake.calls != []
    assert findings[0].metadata["reachability"]["verdict"] == "reachable"


def test_discovery_unreachable_finding_is_rejected(tmp_path: Path, monkeypatch):
    project = _write(tmp_path)
    scanner = Scanner(
        config={"enable_discovery": True, "enable_ai_analysis": False,
                "enable_exploit": False, "enable_reachability": True,
                "use_ai_planning": False, "enable_attack_sequence_brainstorm": False,
                "enable_role_map": False, "enable_secret_scan": False},
        workdir=tmp_path / "work",
        ai_client=_NamedFunctionAI("_helper", _poc()),
    )
    fake = Finding(target="x", language="solidity", file="Vault.sol",
                   function="_helper", category="reentrancy", severity="HIGH",
                   description="reentrancy", line_hint="7-9")
    monkeypatch.setattr(scanner, "_run_discovery", lambda *a, **k: [fake])
    result = scanner._scan_one(str(project), 100000, min_severity="LOW")
    rejected = [f for f in result.findings if f.status == "REJECTED"]
    assert rejected
    assert rejected[0].metadata["reachability"]["verdict"] == "not_reachable"


def test_reachability_disabled_leaves_finding_untouched(tmp_path: Path, monkeypatch):
    from web3guard import sandbox as sandbox_mod

    fake = _FakeSandbox()
    monkeypatch.setattr(sandbox_mod, "create_sandbox", lambda *a, **k: fake)
    project = _write(tmp_path)
    scanner = Scanner(
        config={"enable_ai_analysis": True, "enable_discovery": False,
                "enable_exploit": True, "max_exploit_attempts": 1,
                "enable_reachability": False},
        workdir=tmp_path / "work",
        ai_client=_NamedFunctionAI("_helper", _poc()),
    )
    result = scanner.scan([str(project) + "|max"])
    findings = result.targets[0].findings
    assert findings and fake.calls != []
    assert "reachability" not in findings[0].metadata

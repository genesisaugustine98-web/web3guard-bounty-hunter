"""Tests for the two-phase scan output.

Phase 1 emits raw (offline discovery/static) findings with no AI calls.
Phase 2 emits AI findings. The two phases are driven by two config keys
-- ``enable_ai_analysis`` and ``enable_discovery`` -- which the CLI
exposes as ``--discovery-only`` and ``--ai-only`` flags.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest  # noqa: E402

from web3guard.scanner import Scanner  # noqa: E402
from web3guard.languages import TargetLanguage  # noqa: E402


class FakeCostTracker:
    def summary(self) -> dict[str, object]:
        return {"total_cost_usd": 0.0}


class FakeAIClient:
    """Records calls and always reports a vulnerable finding."""

    def __init__(self) -> None:
        self.chat_calls: list[tuple[str, str]] = []

    def chat(self, system: str, user: str, **kwargs):
        self.chat_calls.append((system, user))
        return _resp(
            status="vulnerable",
            category="reentrancy",
            severity="HIGH",
            confidence=0.9,
            function="withdraw",
            description="reentrancy via external call",
            reasoning="call happens before state update",
            line_hint="10-20",
        )

    def cost_tracker(self) -> FakeCostTracker:
        return FakeCostTracker()


class _resp:
    def __init__(self, **fields) -> None:
        import json
        self.content = json.dumps(fields)


# ---------------------------------------------------------------------------
# Config wiring
# ---------------------------------------------------------------------------


def test_defaults_enable_both_phases():
    scanner = Scanner.from_config(None, workdir=Path("/tmp/web3guard-test-wd-x"))
    assert scanner.config.get("enable_discovery", True) is True
    assert scanner.config.get("enable_ai_analysis", True) is True


def test_discovery_only_config_disables_ai_analysis():
    cfg = {"enable_ai_analysis": False, "enable_discovery": True}
    scanner = Scanner(config=cfg, workdir=Path("/tmp/web3guard-test-wd-x"),
                      ai_client=FakeAIClient())
    assert scanner.config["enable_ai_analysis"] is False


def test_ai_only_config_disables_discovery():
    cfg = {"enable_ai_analysis": True, "enable_discovery": False}
    scanner = Scanner(config=cfg, workdir=Path("/tmp/web3guard-test-wd-x"),
                      ai_client=FakeAIClient())
    assert scanner.config["enable_discovery"] is False


# ---------------------------------------------------------------------------
# Phase behavior on a real bundled vulnerable contract
# ---------------------------------------------------------------------------


@pytest.fixture
def vulnerable_target() -> Path:
    """A tiny Solidity contract with a real reentrancy bug."""
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="web3guard-2phase-"))
    (d / "Vault.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Vault {\n"
        "    mapping(address => uint) public balances;\n"
        "    function withdraw() public {\n"
        "        uint amt = balances[msg.sender];\n"
        "        (bool ok, ) = msg.sender.call{value: amt}(\"\");\n"
        "        balances[msg.sender] = 0;\n"
        "    }\n"
        "    function deposit() public payable {\n"
        "        balances[msg.sender] += msg.value;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    return d


def test_discovery_only_produces_findings_without_ai(vulnerable_target: Path):
    import tempfile
    with tempfile.TemporaryDirectory() as wd:
        cfg = {"enable_ai_analysis": False, "enable_discovery": True}
        fake = FakeAIClient()
        scanner = Scanner(config=cfg, workdir=Path(wd), ai_client=fake)
        result = scanner.scan([str(vulnerable_target) + "|max"])
        assert fake.chat_calls == []
        assert len(result.targets) == 1
        assert len(result.targets[0].findings) > 0


def test_ai_only_runs_ai_and_finds_reentrancy(vulnerable_target: Path):
    import tempfile
    with tempfile.TemporaryDirectory() as wd:
        cfg = {"enable_ai_analysis": True, "enable_discovery": False}
        fake = FakeAIClient()
        scanner = Scanner(config=cfg, workdir=Path(wd), ai_client=fake)
        result = scanner.scan([str(vulnerable_target) + "|max"])
        assert fake.chat_calls != []
        assert len(result.targets) == 1
        cats = [f.category for f in result.targets[0].findings]
        assert "reentrancy" in cats


def test_discovery_only_finding_language_tagged(vulnerable_target: Path):
    import tempfile
    with tempfile.TemporaryDirectory() as wd:
        cfg = {"enable_ai_analysis": False, "enable_discovery": True}
        fake = FakeAIClient()
        scanner = Scanner(config=cfg, workdir=Path(wd), ai_client=fake)
        result = scanner.scan([str(vulnerable_target) + "|max"])
        langs = {f.language for f in result.targets[0].findings}
        assert langs <= {TargetLanguage.SOLIDITY.value}

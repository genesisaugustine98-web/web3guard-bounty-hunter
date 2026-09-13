"""Real-Forge differential regression: patched copy must reject the PoC."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.scanner import Scanner  # noqa: E402
from tests.test_exploit_e2e_foundry import (  # noqa: E402
    _GOOD_POC,
    _REENTRANCY_FIXTURE,
    ScriptedExploitAI,
)


@pytest.mark.skipif(shutil.which("forge") is None, reason="forge not installed")
def test_real_differential_confirms_reentrancy(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    shutil.copy2(_REENTRANCY_FIXTURE, target / "ReentrancyVault.sol")
    work = tmp_path / "work"
    work.mkdir()
    cfg = {
        "enable_ai_analysis": True,
        "enable_discovery": False,
        "enable_exploit": True,
        "max_exploit_attempts": 2,
        "enable_differential": True,
    }
    s = Scanner(config=cfg, workdir=work, ai_client=ScriptedExploitAI(_GOOD_POC))
    result = s.scan([str(target) + "|max"])
    findings = result.targets[0].findings
    assert len(findings) == 1, [f.category for f in findings]
    f = findings[0]
    assert f.status == "CONFIRMED EXPLOIT", (f.status, f.exploit_log)
    assert f.metadata.get("differential") == "confirmed"
    assert f.metadata.get("impact_gain", 0) > 0

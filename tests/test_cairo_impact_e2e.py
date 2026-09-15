"""Real-`scarb` impact confirmation for Cairo.

Proves the Cairo harness runs a PoC at runtime, that the scanner confirms
only when the PoC emits an ``impact_gain``/``impact_loss`` marker, and that
a marker-less PoC is rejected by the syntactic pre-filter.

Skips when `scarb` is not installed.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.languages import cairo_lang  # noqa: E402
from web3guard.scanner import Finding, Scanner  # noqa: E402

_FIXTURE = PROJECT_ROOT / "test_contracts" / "cairo_reward"

_CAIRO_POC = """\
mod reward;

#[cfg(test)]
mod lib {
    use super::reward;

    #[test]
    fn test_exploit() {
        let before: u64 = 0;
        let after: u64 = reward::credit_refund(before, 100);
        assert!(after > 100, "no impact");
        println!("impact_gain: {}", after - 100);
    }
}
"""

_CAIRO_POC_NO_MARKER = """\
mod reward;

#[cfg(test)]
mod lib {
    use super::reward;

    #[test]
    fn test_exploit() {
        let after: u64 = reward::credit_refund(0, 100);
        assert!(after > 100, "no impact");
    }
}
"""


class _Resp:
    def __init__(self, content: str) -> None:
        self.content = content


class _PoCClient:
    """Returns a fixed Cairo PoC for the exploit role."""

    def __init__(self, poc: str) -> None:
        self._poc = poc

    def chat(self, system: str, user: str, **kwargs):
        return _Resp(f"```cairo\n{self._poc}\n```")


class _Chunk:
    file = "reward.cairo"
    content = (Path(_FIXTURE) / "src" / "reward.cairo").read_text()
    context = "(none)"


def _run(tmp_path: Path, poc: str) -> Finding:
    work = tmp_path / "work"
    work.mkdir()
    scanner = Scanner(
        config={
            "enable_ai_analysis": True,
            "enable_discovery": False,
            "enable_exploit": True,
            "max_exploit_attempts": 1,
            "enable_differential": False,
        },
        workdir=work,
        ai_client=_PoCClient(poc),
    )
    finding = Finding(target=str(_FIXTURE), language="cairo",
                      file="reward.cairo", category="arithmetic")
    scanner._generate_poc(cairo_lang.CairoAdapter(), finding, _Chunk(), _FIXTURE)
    return finding


@pytest.mark.skipif(shutil.which("scarb") is None, reason="scarb not installed")
def test_cairo_impact_confirms(tmp_path: Path) -> None:
    finding = _run(tmp_path, _CAIRO_POC)
    assert finding.status == "CONFIRMED EXPLOIT", (finding.status, finding.exploit_log)
    assert finding.metadata.get("impact_gain") == 100


@pytest.mark.skipif(shutil.which("scarb") is None, reason="scarb not installed")
def test_cairo_markerless_poc_not_confirmed(tmp_path: Path) -> None:
    finding = _run(tmp_path, _CAIRO_POC_NO_MARKER)
    assert "CONFIRMED" not in finding.status, finding.status

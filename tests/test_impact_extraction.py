"""Impact evidence is parsed from Foundry log output."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from web3guard.languages.solidity import extract_impact_solidity


def test_no_logs_returns_none() -> None:
    assert extract_impact_solidity("1 passed; 0 failed") is None


def test_gain_confirms() -> None:
    out = "Ran 1 test ...\nimpact_gain: 2000000000000000000\n[PASS]"
    ev = extract_impact_solidity(out)
    assert ev is not None and ev.gain == 2 * 10**18 and ev.confirmed


def test_zero_gain_is_not_confirmed() -> None:
    ev = extract_impact_solidity("impact_gain: 0")
    assert ev is not None and not ev.confirmed


def test_loss_confirms() -> None:
    ev = extract_impact_solidity("impact_loss: 42")
    assert ev is not None and ev.loss == 42 and ev.confirmed

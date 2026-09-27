from pathlib import Path

import pytest

from web3guard.ai.cost import CostTracker
from web3guard.utils.secrets import iter_secret_matches, redact_sensitive_text


def test_unknown_model_pricing_fails_closed():
    tracker = CostTracker(max_cost_usd=10.0)
    with pytest.raises(ValueError, match="unknown LLM model pricing"):
        tracker.cost_for("provider/brand-new-model", 10, 10)


def test_zero_cost_ceiling_is_disabled():
    tracker = CostTracker(max_cost_usd=0.0)
    rec = tracker.record(
        provider="test",
        model="gpt-4o",
        prompt_tokens=1000,
        completion_tokens=1000,
    )
    assert rec.cost_usd > 0
    assert tracker.total_cost() > 0


def test_secret_text_is_redacted():
    secret = "github_pat_" + "A" * 45
    assert secret not in redact_sensitive_text(secret)
    assert "<redacted:github_fine_grained_pat>" in redact_sensitive_text(secret)
    matches = list(iter_secret_matches(secret))
    assert matches
    assert matches[0].kind == "github_fine_grained_pat"


def test_secret_scan_never_returns_value(tmp_path: Path):
    p = tmp_path / "config.txt"
    value = "sk-proj-" + "B" * 40
    p.write_text(value)
    from web3guard.utils.secrets import scan_path
    finding = scan_path(tmp_path)[0]
    assert value not in str(finding)
    assert "redacted" in str(finding).lower()

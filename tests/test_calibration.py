"""Calibration harness tests: real analyzers, no fakes of the measured layer."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

REACHABILITY_CORPUS = PROJECT_ROOT / "bench" / "reachability" / "corpus.json"


def test_corpus_root_key_resolves_relative_to_manifest(tmp_path: Path) -> None:
    from web3guard.bench.corpus import load_corpus, validate_corpus

    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "Vault.sol").write_text("contract Vault {}", encoding="utf-8")
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    manifest = manifests / "corpus.json"
    manifest.write_text(json.dumps({
        "name": "root-key",
        "root": "../fixtures",
        "units": [{"path": "Vault.sol", "language": "solidity",
                   "vulnerabilities": []}],
    }), encoding="utf-8")

    corpus = load_corpus(manifest)
    assert corpus.root == fixtures.resolve()
    assert (corpus.root / corpus.units[0].path).is_file()
    assert validate_corpus(manifest) == []


def test_pipeline_rejects_unreachable_keeps_inherited() -> None:
    from web3guard.bench.pipeline import make_reachability_analyzer

    root = PROJECT_ROOT / "test_contracts" / "reachability"
    kept = make_reachability_analyzer()(root)
    names = {Path(issue.file).name for issue in kept}
    assert "InheritedReentrancy.sol" in names
    assert "UnreachableReentrancy.sol" not in names


def test_pipeline_fails_open_for_unknown_language(tmp_path: Path) -> None:
    from web3guard.bench.pipeline import make_reachability_analyzer

    (tmp_path / "Thing.clar").write_text(
        "(define-public (withdraw) (ok true))", encoding="utf-8")
    kept = make_reachability_analyzer()(tmp_path)
    assert isinstance(kept, list)


def test_calibrate_l1_rejects_unreachable_and_keeps_recall() -> None:
    from web3guard.bench import default_corpus, load_corpus
    from web3guard.bench.calibration import calibrate_l1

    main = default_corpus()
    reach = load_corpus(REACHABILITY_CORPUS)
    result = calibrate_l1(main_corpus=main, reachability_corpus=reach)

    assert result.status == "measured", result.reason
    assert result.data["precision_delta"] > 0
    assert result.data["recall_delta"] == 0
    assert result.data["filtered"]["precision"] == 1.0
    rejected = {item["file"] for item in result.data["rejected"]}
    assert any("UnreachableReentrancy" in f for f in rejected)

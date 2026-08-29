"""Precision/recall gate over the in-repo benchmark corpus.

Runs the real ``web3guard bench`` CLI (not a fake) so the corpus
manifest, detector behavior, and metric floors are all exercised. Any
later fixture addition must keep this gate green.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "web3guard" / "bench" / "corpus.json"


def _bench(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "web3guard", "bench",
         "--corpus", str(CORPUS), *args],
        capture_output=True, text=True, cwd=REPO,
    )


def test_corpus_manifest_is_valid() -> None:
    r = _bench("--validate")
    assert r.returncode == 0, r.stdout + r.stderr


def test_corpus_precision_recall_floors() -> None:
    r = _bench("--fail-below", "1.0,1.0")
    assert r.returncode == 0, r.stdout + r.stderr

"""Tests for the v3.6.1 dead-code cleanup and accel wiring.

Covers:
- ``python -m web3guard.accel`` entry point exists.
- ``accelerator().secret_matches`` parity contract (Python path here,
  Rust wrapper tested with a fake native module).
- ``RustAccelerator`` hash truncation + mnemonic-rule union.
- ``extract_imports`` signature/semantics parity (Python vs Rust path).
- Gitleaks builtin fallback routes through the accelerator unchanged.
- Removed dead code stays removed (guards against quiet reintroduction).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from web3guard.accel import PythonAccelerator, accelerator

# A syntactically valid (dummy) AWS access key — matches SECRET_PATTERNS.
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
# 12 lowercase words — passes the BIP39 mnemonic heuristics.
MNEMONIC = ("abandon ability able about above absent absorb abstract absurd "
            "abuse access accident")


def test_accel_package_is_executable() -> None:
    """python -m web3guard.accel must dispatch to the CLI (regression:
    accel_cli existed but the package had no __main__)."""
    import importlib.util

    spec = importlib.util.find_spec("web3guard.accel.__main__")
    assert spec is not None, "web3guard.accel.__main__ missing"


def test_secret_matches_python_path_shape() -> None:
    accel = accelerator()
    hits = accel.secret_matches(f"key = {AWS_KEY}\n")
    assert hits and hits[0]["rule"] == "aws_access_key"
    assert hits[0]["match"] == AWS_KEY
    assert hits[0]["line"] == 1


def test_secret_matches_includes_validated_mnemonic() -> None:
    """Rule coverage must be identical across native/python paths — the
    mnemonic rule is validated Python-side, so every path must include it."""
    accel = accelerator()
    text = f'seed: "{MNEMONIC}"\n'
    rules = {h["rule"] for h in accel.secret_matches(text)}
    assert "mnemonic" in rules


def test_rust_wrapper_truncates_hashes_to_24() -> None:
    """Native returns full digests; callers must see 24-char hashes
    (graph persistence expects the Python reference format)."""

    class FakeNative:
        def hash_files(self, paths: list[str]) -> dict[str, str]:
            out = {}
            for p in paths:
                out[p] = hashlib.sha256(p.encode()).hexdigest()
            return out

        def scan_secrets(self, content: str) -> list[dict]:
            return []

    from web3guard.accel import RustAccelerator

    accel = RustAccelerator(FakeNative())
    got = accel.hash_files(["a.sol"])
    assert len(next(iter(got.values()))) == 24


def test_rust_wrapper_unions_mnemonic_matches() -> None:
    """Native excludes the mnemonic rule; the wrapper must add it back."""

    class FakeNative:
        def scan_secrets(self, content: str) -> list[dict]:
            # Simulates the native 7-rule set: finds the AWS key only.
            hits = []
            if AWS_KEY in content:
                hits.append({"rule": "aws_access_key", "match": AWS_KEY,
                             "line": 1})
            return hits

    from web3guard.accel import RustAccelerator

    accel = RustAccelerator(FakeNative())
    text = f'{AWS_KEY}\nseed: "{MNEMONIC}"\n'
    rules = {h["rule"] for h in accel.scan_secrets(text)}
    assert rules == {"aws_access_key", "mnemonic"}


def test_extract_imports_python_all_matches_deduped() -> None:
    """Python path: every pattern match, deduped, first-seen order —
    not just the first match per pattern (v3.6.1 follow-up fix)."""
    src = (
        'import "@openzeppelin/contracts/token/ERC20.sol";\n'
        'import {SafeMath} from "./math.sol";\n'
        'import "@openzeppelin/contracts/token/ERC20.sol";\n'  # duplicate
        'import "math/big.sol";\n'
    )
    got = PythonAccelerator().extract_imports(src)
    assert got == [
        "@openzeppelin/contracts/token/ERC20.sol",
        "./math.sol",
        "math/big.sol",
    ]


def test_extract_imports_signatures_aligned() -> None:
    """Both accelerator paths must take source *content* — the Rust
    wrapper previously declared ``crate_dir`` and forwarded it verbatim,
    silently changing what the argument meant."""
    import inspect

    from web3guard.accel import RustAccelerator

    for cls in (PythonAccelerator, RustAccelerator):
        params = list(inspect.signature(cls.extract_imports).parameters)
        assert params == ["self", "content"], f"{cls.__name__}: {params}"


def test_rust_wrapper_extract_imports_takes_content() -> None:
    """RustAccelerator must forward the *text*, matching the native
    ``fn extract_imports(content: &str)`` entry point."""

    class FakeNative:
        def extract_imports(self, content: str) -> list[str]:
            # Native implements the Rust subset only (use / mod decls).
            return ["std::io"] if "use std::io;" in content else []

    from web3guard.accel import RustAccelerator

    accel = RustAccelerator(FakeNative())
    assert accel.extract_imports("use std::io;\n") == ["std::io"]
    assert accel.extract_imports("fn main() {}\n") == []


def test_gitleaks_builtin_scan_routes_through_accel(tmp_path: Path) -> None:
    from web3guard.discovery.gitleaks_engine import GitleaksEngine

    (tmp_path / "leak.env").write_text(f"AWS_KEY={AWS_KEY}\n", encoding="utf-8")
    engine = GitleaksEngine()
    if engine.is_installed():  # real gitleaks present: fallback not exercised
        return
    results = engine.run(tmp_path)
    secret_hits = [r for r in results if r.category == "secret-leak"]
    assert secret_hits, "builtin scan produced no secret findings"
    assert any(AWS_KEY in (r.description or "") for r in secret_hits)


def test_removed_dead_code_stays_removed() -> None:
    """These were deleted as unreferenced in the v3.6.1 audit; re-adding
    them requires a caller, not just a resurrection."""
    import importlib

    routing = importlib.util.find_spec("web3guard.routing")
    assert routing is None, "web3guard.routing was deleted; do not resurrect"

    resilience = importlib.import_module("web3guard.utils.resilience")
    assert not hasattr(resilience, "is_retryable_http")

    bounty = importlib.import_module("web3guard.utils.bounty")
    assert not hasattr(bounty, "routes_for_target")


def test_python_reference_hasher_agrees_with_accel_format() -> None:
    accel = PythonAccelerator()
    p = Path(__file__)
    got = accel.hash_files([str(p)])
    assert len(got[str(p)]) == 24

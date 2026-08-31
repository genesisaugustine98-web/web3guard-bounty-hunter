"""End-to-end smoke tests for non-Foundry sandboxes.

Each test runs the generic sandbox against a real fixture with a canned
PoC. Tests SKIP when the toolchain binary is not installed locally, so
the suite stays green on machines without the toolchains; CI installs
them via scripts/setup-toolchains.sh.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.sandbox import create_sandbox  # noqa: E402
from web3guard.languages import clarity_lang, cairo_lang, func_lang, move_lang  # noqa: E402


def _sandbox_run(adapter, target_dir: str, poc: str) -> tuple[bool, str]:
    import tempfile
    target = PROJECT_ROOT / target_dir
    workdir = Path(tempfile.mkdtemp(prefix="wb-sandbox-"))
    sandbox = create_sandbox(adapter, target, workdir)
    if sandbox is None:
        return False, "sandbox init failed"
    return sandbox.write_and_run(poc, "smoke")


def _require(adapter, binary: str) -> None:
    if shutil.which(binary) is None:
        pytest.skip(f"{binary} not installed locally")


def test_clarity_sandbox_smoke() -> None:
    _require(clarity_lang.ClarityAdapter(), "clarinet")
    ok, out = _sandbox_run(
        clarity_lang.ClarityAdapter(),
        "test_contracts/vulnerable",
        'Clarinet.test({ name: "exploit_test", async fn(chain: any, accounts: any) {} });',
    )
    assert ok, out


def test_cairo_sandbox_smoke() -> None:
    _require(cairo_lang.CairoAdapter(), "scarb")
    ok, out = _sandbox_run(
        cairo_lang.CairoAdapter(),
        "test_contracts/vulnerable",
        "mod lib { #[test] fn it_passes() {} }",
    )
    assert ok, out


def test_func_sandbox_smoke() -> None:
    _require(func_lang.FunCAdapter(), "blueprint")
    ok, out = _sandbox_run(
        func_lang.FunCAdapter(),
        "test_contracts/vulnerable",
        "describe('exploit', () => { it('passes', () => {}); });",
    )
    assert ok, out


def test_move_sandbox_smoke() -> None:
    _require(move_lang.MoveAdapter(), "aptos")
    ok, out = _sandbox_run(
        move_lang.MoveAdapter(),
        "test_contracts/vulnerable",
        "#[test] fun test_exploit() { let _x = 1; assert!(_x == 1, 0); }",
    )
    assert ok, out

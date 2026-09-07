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

from web3guard.languages import cairo_lang, clarity_lang, func_lang, move_lang  # noqa: E402
from web3guard.sandbox import create_sandbox  # noqa: E402


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
        '(define-public (exploit-proof)\n'
        '    (begin (asserts! true "noop")\n'
        '          (ok true)))\n',
    )
    assert ok, out


def test_cairo_sandbox_smoke() -> None:
    _require(cairo_lang.CairoAdapter(), "scarb")
    ok, out = _sandbox_run(
        cairo_lang.CairoAdapter(),
        "test_contracts/vulnerable",
        "#[cfg(test)] mod lib { #[test] fn it_passes() {} }",    )
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
        "test_contracts/move_smoke",
        "#[test_only]\n"
        "module move_smoke::exploit {\n"
        "    use move_smoke::sale;\n"
        "    #[test]\n"
        "    fun test_exploit() {\n"
        "        let paid = sale::quote(1000, 10000, 1000);\n"
        "        assert!(paid == 10000, 1);\n"
        "    }\n"
        "}\n",
    )
    assert ok, out

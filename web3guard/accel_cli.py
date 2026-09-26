"""Build helpers for the optional Rust acceleration module.

The accelerator is **optional**: the scanner runs everywhere with the
pure-Python fallback. These helpers just make the native build a
one-command affair when a Rust toolchain is available.

Usage (from the repo root)::

    python -m web3guard.accel build       # maturin develop --release
    python -m web3guard.accel status      # which accelerator is active?
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

CRATE_DIR = Path(__file__).resolve().parent.parent.parent / "native" / "web3guard-accel"


def _maturin_available() -> bool:
    return shutil.which("maturin") is not None


def cmd_build(_args: argparse.Namespace) -> int:
    if not CRATE_DIR.is_dir():
        print(f"error: crate not found at {CRATE_DIR}", file=sys.stderr)
        return 1
    if not _maturin_available():
        print("error: maturin is not installed. Run `pip install maturin` "
              "and have a Rust toolchain (rustup) available.", file=sys.stderr)
        return 1
    print(f"Building {CRATE_DIR} (release)...")
    rc = subprocess.call(["maturin", "develop", "--release"], cwd=CRATE_DIR)
    if rc == 0:
        print("OK — restart Python to pick up web3guard_accel.")
    return rc


def cmd_status(_args: argparse.Namespace) -> int:
    from web3guard.accel import accelerator
    accel = accelerator()
    print(f"active accelerator: {accel.kind}")
    if accel.kind == "python":
        print("  (install the native module for faster hashing/scanning:")
        print("   pip install maturin && python -m web3guard.accel build)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="web3guard.accel")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build", help="Build the native extension via maturin")
    sub.add_parser("status", help="Show which accelerator is active")
    args = parser.parse_args(argv)
    if args.cmd == "build":
        return cmd_build(args)
    return cmd_status(args)


if __name__ == "__main__":
    raise SystemExit(main())

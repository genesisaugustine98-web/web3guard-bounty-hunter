#!/usr/bin/env python3
"""Deterministic integration gate: required toolchains + zero unexpected skips."""
from __future__ import annotations
import argparse, os, shutil, subprocess, sys, xml.etree.ElementTree as ET
from pathlib import Path

REQUIRED_TOOLS = {
    "forge": "Foundry exploit/differential/build tests",
    "clarinet": "Clarity sandbox tests",
    "scarb": "Cairo impact tests",
    "blueprint": "TON/FunC sandbox tests",
    "aptos": "Move sandbox tests",
}
DEFAULT_TESTS = [
    "tests/test_sandbox_smoke.py",
    "tests/test_exploit_e2e_foundry.py",
    "tests/test_differential_e2e_foundry.py",
    "tests/test_cairo_impact_e2e.py",
    "tests/test_build_profile.py",
    "tests/test_foundry_build_repro.py",
    "tests/test_impact_extraction.py",
    "tests/test_differential.py",
    "tests/test_calibration.py::test_calibrate_l2_golden_cases",
]

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--junit", type=Path, default=Path("test-results/required-integration.xml"))
    ap.add_argument("tests", nargs="*", default=DEFAULT_TESTS)
    args = ap.parse_args()
    missing = [(name, why) for name, why in REQUIRED_TOOLS.items() if shutil.which(name) is None]
    if missing:
        for name, why in missing:
            print(f"::error::Required integration capability missing: {name} ({why})")
        return 2
    args.junit.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    cmd = [sys.executable, "-m", "pytest", "-q", "-rs", f"--junitxml={args.junit}", *args.tests]
    proc = subprocess.run(cmd, env=env, check=False)
    if proc.returncode:
        return proc.returncode
    try:
        root = ET.parse(args.junit).getroot()
    except Exception as exc:
        print(f"::error::Unable to parse JUnit result: {exc}")
        return 3
    skipped = sum(int(s.attrib.get("skipped", "0") or 0) for s in root.iter("testsuite"))
    failures = sum(int(s.attrib.get("failures", "0") or 0) for s in root.iter("testsuite"))
    errors = sum(int(s.attrib.get("errors", "0") or 0) for s in root.iter("testsuite"))
    print(f"Required integration summary: skipped={skipped} failures={failures} errors={errors}")
    return 4 if skipped else 0

if __name__ == "__main__":
    raise SystemExit(main())

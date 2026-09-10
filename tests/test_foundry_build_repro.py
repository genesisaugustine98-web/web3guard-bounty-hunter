"""The sandbox must preserve the target's remappings and solc pin."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.sandbox.build_system import detect_build_profile  # noqa: E402
from web3guard.sandbox.foundry import FoundrySandbox  # noqa: E402
from web3guard.languages.solidity import SolidityAdapter  # noqa: E402

_FIXTURE = PROJECT_ROOT / "test_contracts/remapping_project"


@pytest.mark.skipif(shutil.which("forge") is None, reason="forge not installed")
def test_sandbox_uses_target_remappings(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    target = tmp_path / "target"
    shutil.copytree(_FIXTURE, target)
    sb = FoundrySandbox(SolidityAdapter(), target, work)
    root = sb.setup(target)
    toml = (root / "foundry.toml").read_text()
    assert "mylib/=lib/mylib/" in toml
    assert 'solc_version = "0.8.20"' in toml
    assert "ffi = false" in toml

    poc = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.13;\n"
        'import "forge-std/Test.sol";\n'
        'import {Consumer} from "../src/Consumer.sol";\n'
        "contract ExploitTest is Test {\n"
        "    function test_autonomous_exploit() public {\n"
        "        Consumer c = new Consumer();\n"
        "        assertEq(c.sum(2, 3), 5);\n"
        "    }\n"
        "}\n"
    )
    ok, out = sb.write_and_run(poc, "remap")
    assert ok, out
    assert "1 passed" in out


def test_detect_profile_matches_fixture() -> None:
    p = detect_build_profile(_FIXTURE)
    assert p.kind == "foundry"
    assert "mylib/=lib/mylib/" in p.remappings


def test_vendored_lib_is_copied(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    target = tmp_path / "target"
    shutil.copytree(_FIXTURE, target)
    sb = FoundrySandbox(SolidityAdapter(), target, work)
    root = sb.setup(target)
    # lib/mylib was vendored from the target, not created by forge init.
    assert (root / "lib" / "mylib" / "contracts" / "Helper.sol").is_file()


_HARDHAT = PROJECT_ROOT / "test_contracts/hardhat_project"


@pytest.mark.skipif(shutil.which("forge") is None, reason="forge not installed")
def test_hardhat_oz_import_compiles(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    target = tmp_path / "target"
    shutil.copytree(_HARDHAT, target)
    sb = FoundrySandbox(SolidityAdapter(), target, work)
    root = sb.setup(target)
    toml = (root / "foundry.toml").read_text()
    assert "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/" in toml
    assert (root / "lib" / "openzeppelin-contracts" / "contracts" / "Ownable.sol").is_file()
    ok, out = sb.write_and_run(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.13;\n"
        'import "forge-std/Test.sol";\n'
        'import {Owned} from "../src/Consumer.sol";\n'
        "contract ExploitTest is Test {\n"
        "    function test_autonomous_exploit() public {\n"
        "        Owned o = new Owned();\n"
        "        assertEq(o.ownerOf(), address(this));\n"
        "    }\n"
        "}\n",
        "hardhat",
    )
    assert ok, out
    assert "1 passed" in out

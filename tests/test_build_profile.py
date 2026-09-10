"""Unit tests for build-system detection."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from web3guard.sandbox.build_system import BuildProfile, detect_build_profile


def test_plain_project(tmp_path: Path) -> None:
    (tmp_path / "Foo.sol").write_text("contract Foo {}")
    p = detect_build_profile(tmp_path)
    assert p.kind == "plain"
    assert p.remappings == ()


def test_foundry_project_reads_remappings_and_solc(tmp_path: Path) -> None:
    (tmp_path / "foundry.toml").write_text(
        '[profile.default]\n'
        'src = "contracts"\n'
        'solc_version = "0.8.20"\n'
        'remappings = ["mylib/=lib/mylib/"]\n'
    )
    (tmp_path / "remappings.txt").write_text("other/=lib/other/\n")
    p = detect_build_profile(tmp_path)
    assert p.kind == "foundry"
    assert p.src_dir == "contracts"
    assert "mylib/=lib/mylib/" in p.remappings
    assert "other/=lib/other/" in p.remappings
    assert p.solc_version == "0.8.20"


def test_hardhat_project_derives_oz_remapping(tmp_path: Path) -> None:
    (tmp_path / "hardhat.config.js").write_text(
        "module.exports = { solidity: '0.8.19' };\n"
    )
    (tmp_path / "node_modules" / "@openzeppelin" / "contracts").mkdir(parents=True)
    p = detect_build_profile(tmp_path)
    assert p.kind == "hardhat"
    assert p.solc_version == "0.8.19"
    assert any(r.startswith("@openzeppelin/contracts/=") for r in p.remappings)


def test_truffle_and_brownie_kinds(tmp_path: Path) -> None:
    truffle = tmp_path / "truffle"
    truffle.mkdir()
    (truffle / "truffle-config.js").write_text("module.exports = {};")
    assert detect_build_profile(truffle).kind == "truffle"
    brownie = tmp_path / "brownie"
    brownie.mkdir()
    (brownie / "brownie-config.yaml").write_text("project_structure: {}")
    assert detect_build_profile(brownie).kind == "brownie"


def test_render_keeps_remappings_and_pins_solc() -> None:
    from web3guard.sandbox.build_system import render_foundry_toml

    p = BuildProfile(kind="foundry", solc_version="0.8.20",
                     remappings=("mylib/=lib/mylib/",), via_ir=True)
    out = render_foundry_toml(p)
    assert 'solc_version = "0.8.20"' in out
    assert 'remappings = ["mylib/=lib/mylib/"]' in out
    assert "via_ir = true" in out


def test_render_always_hardens_ffi_and_fs() -> None:
    from web3guard.sandbox.build_system import render_foundry_toml

    out = render_foundry_toml(BuildProfile(kind="foundry", remappings=("a/=b/",)))
    assert "ffi = false" in out
    assert "fs_permissions = []" in out
    assert "solc_version" not in out  # no pin when unknown

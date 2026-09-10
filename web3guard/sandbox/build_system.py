"""Detect how a target repository builds, so the sandbox can reproduce it.

The sandbox runs ``forge``, so the only thing that must survive the copy is
*import resolution*: remappings, the pinned solc version, ``via_ir``, and the
vendored dependency trees. Native ``src``/``contracts`` layout does not matter
because user code is copied flat under ``src/`` preserving relative structure.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_REMAPPING_LINE = re.compile(r"^\s*(?P<prefix>[^=#\s]+)\s*=\s*(?P<target>[^#\s]+)\s*$")
_HARDHAT_SOLC = re.compile(r"solidity\s*:\s*[\"']([^\"']+)[\"']")
_SOLC_EXACT = re.compile(r"^\d+\.\d+\.\d+$")


@dataclass(frozen=True)
class BuildProfile:
    kind: str = "plain"                      # foundry | hardhat | truffle | brownie | plain
    src_dir: str = "src"
    test_dir: str = "test"
    libs: tuple[str, ...] = ("lib",)
    remappings: tuple[str, ...] = ()
    solc_version: str | None = None
    via_ir: bool = False


def detect_build_profile(target_path: Path) -> BuildProfile:
    if (target_path / "foundry.toml").is_file():
        return _from_foundry(target_path)
    if (target_path / "hardhat.config.js").is_file() or \
       (target_path / "hardhat.config.ts").is_file():
        return _from_hardhat(target_path)
    if (target_path / "truffle-config.js").is_file():
        return BuildProfile(kind="truffle", src_dir="contracts", test_dir="test")
    if (target_path / "brownie-config.yaml").is_file():
        return BuildProfile(kind="brownie", src_dir="contracts", test_dir="tests")
    return BuildProfile(kind="plain")


def _from_foundry(target_path: Path) -> BuildProfile:
    data: dict = {}
    try:
        import tomllib
        data = tomllib.loads((target_path / "foundry.toml").read_text(errors="ignore"))
    except Exception:  # noqa: BLE001 - malformed toml falls back to defaults
        data = {}
    prof = data.get("profile", {}).get("default", {}) if isinstance(data, dict) else {}
    remappings = list(prof.get("remappings", ()) or ())
    rt = target_path / "remappings.txt"
    if rt.is_file():
        for line in rt.read_text(errors="ignore").splitlines():
            m = _REMAPPING_LINE.match(line)
            if m:
                remappings.append(f"{m.group('prefix')}={m.group('target')}")
    solc = prof.get("solc_version") or prof.get("solc")
    solc = str(solc) if solc else None
    if solc and not _SOLC_EXACT.match(solc):
        solc = None  # ranges are not valid for foundry's solc_version
    return BuildProfile(
        kind="foundry",
        src_dir=str(prof.get("src", "src")),
        test_dir=str(prof.get("test", "test")),
        libs=tuple(prof.get("libs", ["lib"]) or ["lib"]),
        remappings=tuple(remappings),
        solc_version=solc,
        via_ir=bool(prof.get("via_ir", False)),
    )


def _from_hardhat(target_path: Path) -> BuildProfile:
    text = ""
    for name in ("hardhat.config.ts", "hardhat.config.js"):
        p = target_path / name
        if p.is_file():
            text = p.read_text(errors="ignore")
            break
    m = _HARDHAT_SOLC.search(text)
    solc = m.group(1) if m and _SOLC_EXACT.match(m.group(1)) else None
    remappings: list[str] = []
    oz = target_path / "node_modules" / "@openzeppelin" / "contracts"
    if oz.is_dir():
        remappings.append("@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/")
    return BuildProfile(
        kind="hardhat", src_dir="contracts", test_dir="test",
        libs=("lib", "node_modules"), remappings=tuple(remappings),
        solc_version=solc,
    )


def render_foundry_toml(profile: BuildProfile) -> str:
    """Render a hardened foundry.toml that preserves import resolution."""
    lines = [
        "# Web3Guard-managed foundry.toml. Regenerated every run.",
        "[profile.default]",
        'src = "src"',
        'out = "out"',
        'libs = ["lib"]',
        'test = "test"',
        "optimizer = true",
        "optimizer_runs = 200",
    ]
    if profile.solc_version:
        lines.append(f'solc_version = "{profile.solc_version}"')
    if profile.via_ir:
        lines.append("via_ir = true")
    if profile.remappings:
        rendered = ", ".join(f'"{r}"' for r in profile.remappings)
        lines.append(f"remappings = [{rendered}]")
    lines += [
        "fs_permissions = []",
        "ffi = false",
        "verbosity = 1",
    ]
    return "\n".join(lines) + "\n"

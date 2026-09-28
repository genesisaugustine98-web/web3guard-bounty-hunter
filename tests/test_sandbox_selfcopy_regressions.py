"""Regression: sandbox copy loop must not copy the sandbox into itself.

The sandbox root is created via ``mkdtemp`` *inside* ``self.workdir``.
When the workdir overlaps the target tree (scanner scanning its own
cwd, unit tests pointing both at the same ``tmp_path``), a *lazy*
``target_path.rglob("*")`` would discover the files the sandbox had
just written into its own ``src/`` and copy them back in — nesting
``web3guard-foundry-X/src/web3guard-foundry-X/src/...`` until path
lengths explode. The fix freezes the file list via
:func:`web3guard.sandbox.base.snapshot_target_files` *before* the root
exists and additionally filters anything inside the root while copying.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from web3guard.sandbox._generic import GenericSandbox
from web3guard.sandbox.base import (
    is_path_within,
    snapshot_target_files,
)
from web3guard.sandbox.foundry import FoundrySandbox


class _Runner:
    name = "foundry"


class _Adapter:
    language = "solidity"
    test_runner = _Runner()


def _make_generic(tmp_path: Path) -> GenericSandbox:
    sb = GenericSandbox.__new__(GenericSandbox)
    sb.adapter = _Adapter()
    sb.target_path = tmp_path
    sb.workdir = tmp_path
    sb.language = "solidity"
    sb.file_globs = (".sol",)
    sb.skip_globs = ()
    sb.skip_suffixes = ()
    sb.poc_filename = "exploit.t.sol"
    sb.poc_suffix = ".sol"
    sb.build_timeout = 10
    sb.test_timeout = 10
    from web3guard.security import SandboxGuard, SandboxPolicy

    sb.guard = SandboxGuard(SandboxPolicy())
    sb._root = None
    return sb


def _no_init(self, cmd: list, *, cwd: Path, timeout: int):
    return True, "", ""


def _capture_init(self, cmd: list, *, cwd: Path, timeout: int):
    _no_init(self, cmd, cwd=cwd, timeout=timeout)
    # Forge init would create this directory in the real flow.
    (cwd / "src").mkdir(parents=True, exist_ok=True)
    return True, "", ""


def test_snapshot_is_frozen_before_root_exists(tmp_path: Path) -> None:
    """snapshot_target_files() must not see files created after it ran."""
    (tmp_path / "Vault.sol").write_text("contract Vault {}", encoding="utf-8")
    files = snapshot_target_files(tmp_path)
    # "Sandbox" appears after the snapshot: it must NOT be in the list.
    sneaky = tmp_path / "web3guard-foundry-x" / "src" / "Vault.sol"
    sneaky.parent.mkdir(parents=True)
    sneaky.write_text("contract Vault {}", encoding="utf-8")
    names = {fp.name for fp in files}
    assert "Vault.sol" in names
    assert not any(is_path_within(fp, tmp_path / "web3guard-foundry-x")
                   for fp in files)


def test_generic_sandbox_does_not_nest_itself(tmp_path: Path) -> None:
    """GenericSandbox.setup() with workdir == target copies each file once."""
    (tmp_path / "Vault.sol").write_text("contract Vault {}", encoding="utf-8")
    (tmp_path / "Lib.sol").write_text("library Lib {}", encoding="utf-8")
    sb = _make_generic(tmp_path)
    # Patch init to create a sandbox "src/" like the real runner would,
    # and the copy loop runs after that — the historical trigger.
    type(sb)._run = _capture_init  # type: ignore[method-assign]
    root = sb.setup(tmp_path)
    type(sb)._run = _no_init  # type: ignore[method-assign]
    copied = sorted(
        fp.relative_to(root).as_posix()
        for fp in root.rglob("Vault.sol")
    )
    assert copied == ["Vault.sol"], copied  # no Vault.sol/src/Vault.sol/...
    assert (root / "Lib.sol").is_file()


def test_foundry_sandbox_does_not_nest_itself(tmp_path: Path) -> None:
    """FoundrySandbox.setup() with workdir == target copies each file once."""
    (tmp_path / "Vault.sol").write_text("contract Vault {}", encoding="utf-8")
    sb = FoundrySandbox(adapter=_Adapter(), target_path=tmp_path,
                        workdir=tmp_path)
    type(sb)._run = _capture_init  # type: ignore[method-assign]
    root = sb.setup(tmp_path)
    type(sb)._run = _no_init  # type: ignore[method-assign]
    copied = sorted(
        fp.relative_to(root).as_posix()
        for fp in root.rglob("Vault.sol")
    )
    assert copied == ["src/Vault.sol"], copied
    # foundry.toml rendered exactly once, at the sandbox root.
    assert (root / "foundry.toml").is_file()
    assert not (root / "src" / "foundry.toml").exists()


def test_foundry_sandbox_copies_vyper_and_skips_tests(tmp_path: Path) -> None:
    """The refactored loop still honors its original skip rules."""
    from web3guard.languages.vyper import VyperAdapter

    (tmp_path / "Vault.vy").write_text("# vyper", encoding="utf-8")
    (tmp_path / "test_x.sol").write_text("contract T {}", encoding="utf-8")
    sb = FoundrySandbox(adapter=VyperAdapter(), target_path=tmp_path,
                        workdir=tmp_path)
    type(sb)._run = _capture_init  # type: ignore[method-assign]
    root = sb.setup(tmp_path)
    type(sb)._run = _no_init  # type: ignore[method-assign]
    assert (root / "src" / "Vault.vy").is_file()
    assert not (root / "src" / "test_x.sol").exists()


def test_symlink_out_of_target_is_still_rejected(tmp_path: Path) -> None:
    """The in-loop symlink check stays meaningful post-refactor."""
    real = tmp_path / "real.sol"
    real.write_text("contract Real {}", encoding="utf-8")
    (tmp_path / "link.sol").symlink_to(real)
    sb = FoundrySandbox(adapter=_Adapter(), target_path=tmp_path,
                        workdir=tmp_path)
    type(sb)._run = _capture_init  # type: ignore[method-assign]
    root = sb.setup(tmp_path)
    type(sb)._run = _no_init  # type: ignore[method-assign]
    assert (root / "src" / "real.sol").is_file()
    assert not (root / "src" / "link.sol").exists()


def _unused(ns: SimpleNamespace) -> None:  # keep import used for typing
    _ = ns

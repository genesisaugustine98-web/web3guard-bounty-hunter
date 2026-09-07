"""Move sandbox — used for both Aptos and Sui."""

from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path

from web3guard.sandbox._generic import GenericSandbox

# Generated when the target ships no Move.toml: a dependency-free Aptos
# package so `aptos move test` can compile self-contained modules/PoCs
# without cloning and building aptos-core's framework.
_DEFAULT_MANIFEST = """\
[package]
name = "web3guard_sandbox"
version = "1.0.0"

[addresses]
web3guard_sandbox = "_"
"""


class MoveSandbox(GenericSandbox):
    """`aptos move test` or `sui move test` for Move packages."""

    language = "move"
    file_globs = (".move",)
    skip_globs = ("/build/", "/.cache/", "/test-only/", "/tests/", "/.git/")
    skip_suffixes = ()
    poc_suffix = ".move"

    def setup(self, target_path: Path) -> Path:
        if self._root is not None:
            return self._root
        root = Path(tempfile.mkdtemp(prefix=f"web3guard-{self.language}-", dir=str(self.workdir)))
        self._build_package(root, target_path)
        self._root = root
        return root

    def _build_package(self, root: Path, target_path: Path) -> None:
        """Lay out a compilable Move package inside the sandbox root.

        - Keeps the target's own ``Move.toml`` when one exists (real Aptos /
          Sui repos declare framework deps and addresses there).
        - Otherwise writes a dependency-free Aptos manifest.
        - Copies the target's ``.move`` modules preserving relative layout
          and relocates any top-level modules under ``sources/`` (the only
          directory Aptos compiles).
        """
        manifest_src = target_path / "Move.toml"
        if manifest_src.is_file():
            shutil.copy2(manifest_src, root / "Move.toml")
        else:
            (root / "Move.toml").write_text(_DEFAULT_MANIFEST, encoding="utf-8")

        for fp in target_path.rglob("*"):
            if not fp.is_file() or fp.suffix != ".move":
                continue
            rel = fp.relative_to(target_path)
            rel_str = "/" + rel.as_posix().lower().strip("/") + "/"
            if any(s in rel_str for s in self.skip_globs):
                continue
            dest = root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(fp, dest)
            except Exception:  # noqa: BLE001
                continue

        sources = root / "sources"
        sources.mkdir(exist_ok=True)
        for fp in sorted(root.glob("*.move")):
            fp.rename(sources / fp.name)

    def run(self, sandbox_path, poc_path, timeout=90):  # noqa: ANN001
        # Move.toml decides the chain: Sui manifests reference the Sui
        # framework, everything else is treated as Aptos.
        is_sui = False
        move_toml = sandbox_path / "Move.toml"
        if move_toml.exists():
            try:
                text = move_toml.read_text(errors="ignore")
                is_sui = bool(
                    re.search(r"(?i)sui(_framework)?\s*=|sui-framework|MystenLabs", text)
                )
            except Exception:  # noqa: BLE001
                pass
        test_cmd = ["sui", "move", "test", "--filter", "test_exploit"] if is_sui \
            else ["aptos", "move", "test", "--filter", "test_exploit"]
        from web3guard.sandbox.base import SandboxResult
        try:
            rc_ok, out, err = self._run(test_cmd, cwd=sandbox_path, timeout=timeout)  # type: ignore[arg-type]
            return SandboxResult(ok=rc_ok, output=out + "\n" + err, error=err if not rc_ok else "", returncode=0 if rc_ok else 1)
        except Exception as e:  # noqa: BLE001
            return SandboxResult(ok=False, output=str(e), error=str(e), returncode=1)

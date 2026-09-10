"""
Foundry sandbox — the canonical Solidity / Vyper test runner.

This is the most-used sandbox in the original scanner, generalized
into a class. It:

1. Initializes a fresh ``forge init`` project.
2. Copies the target's user-code ``.sol`` (and ``.vy`` for Vyper)
   files into ``src/``.
3. Regenerates ``foundry.toml`` from a hardened template (the
   SandboxGuard's contract).
4. Writes the AI's PoC into ``test/AutonomousExploit.t.sol``.
5. Runs ``forge build`` then ``forge test`` and captures output.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from web3guard.languages.base import LanguageAdapter
from web3guard.languages.vyper import VyperAdapter
from web3guard.sandbox.base import SandboxResult
from web3guard.sandbox.build_system import (
    BuildProfile,
    detect_build_profile,
    render_foundry_toml,
)
from web3guard.security import SandboxGuard, SandboxPolicy

LOGGER = logging.getLogger("web3guard.sandbox.foundry")


class FoundrySandbox:
    """Foundry-backed sandbox for Solidity (and Vyper via the vyper profile)."""

    language = "solidity"  # also covers vyper

    def __init__(
        self,
        adapter: LanguageAdapter,
        target_path: Path,
        workdir: Path,
        policy: SandboxPolicy | None = None,
        fork_url: str | None = None,
        build_profile: BuildProfile | None = None,
    ) -> None:
        self.adapter = adapter
        self.target_path = target_path
        self.workdir = workdir
        self.fork_url = fork_url
        self.build_profile = build_profile
        self.guard = SandboxGuard(policy or SandboxPolicy())
        self._root: Path | None = None

    def setup(self, target_path: Path) -> Path:
        """Create a fresh forge init and copy the target's user code into src/."""
        if self._root is not None:
            return self._root
        root = Path(tempfile.mkdtemp(prefix="web3guard-foundry-", dir=str(self.workdir)))
        # forge init
        try:
            self._run(["forge", "init", "--no-git", "--no-commit", "--force", "."], cwd=root, timeout=60)
        except Exception as e:  # noqa: BLE001
            LOGGER.error("forge init failed: %s", e)
            # Continue anyway — a partial sandbox is still useful.
        # Copy user code, skip tests/mocks/libs. Anchor relative paths at the
        # project's own source root so files land directly under sandbox src/
        # (e.g. src/Consumer.sol -> src/Consumer.sol, not src/src/Consumer.sol).
        profile = self.build_profile or detect_build_profile(target_path)
        is_vyper = isinstance(self.adapter, VyperAdapter)
        src_root = target_path / profile.src_dir
        for fp in target_path.rglob("*"):
            if not fp.is_file():
                continue
            rel_str = "/" + fp.relative_to(target_path).as_posix().lower().strip("/") + "/"
            if any(p in rel_str for p in (
                "/test/", "/tests/", "/script/", "/scripts/",
                "/lib/", "/libs/", "/node_modules/", "/.git/",
                "/out/", "/cache/", "/broadcast/",
                "/.vscode/", "/.github/",
            )):
                continue
            name = fp.name.lower()
            if any(name.endswith(s) for s in ("test.sol", "mock.sol", "stub.sol", "fake.sol", "script.sol")):
                continue
            if is_vyper:
                if not (fp.suffix == ".vy" or fp.suffix == ".vyper"):
                    continue
            else:
                if fp.suffix != ".sol":
                    continue
            base = src_root if (src_root.is_dir() and fp.is_relative_to(src_root)) else target_path
            rel = fp.relative_to(base)
            dest = root / "src" / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(fp, dest)
            except Exception as e:  # noqa: BLE001
                LOGGER.debug("copy failed for %s: %s", fp, e)
        # Regenerate foundry.toml from the detected profile, hardening
        # ffi/fs but preserving remappings + solc so imports resolve.
        (root / "foundry.toml").write_text(render_foundry_toml(profile))
        self._vendor_dependencies(target_path, root, profile)
        self._root = root
        return root

    def _vendor_dependencies(self, target_path: Path, root: Path, profile: BuildProfile) -> None:
        """Copy the target's dependency trees so remapped imports resolve.

        For each configured lib dir (e.g. ``lib``, ``node_modules``) copy its
        contents into the sandbox ``lib/`` without clobbering forge-std.
        OpenZeppelin under ``node_modules`` is remapped to
        ``lib/openzeppelin-contracts/contracts`` to match
        :func:`web3guard.sandbox.build_system.detect_build_profile`.
        """
        dest_root = root / "lib"
        dest_root.mkdir(parents=True, exist_ok=True)
        for lib_name in profile.libs:
            src_dir = target_path / lib_name
            if not src_dir.is_dir():
                continue
            if lib_name == "node_modules":
                oz = src_dir / "@openzeppelin" / "contracts"
                if oz.is_dir():
                    dest = dest_root / "openzeppelin-contracts" / "contracts"
                    shutil.copytree(oz, dest, dirs_exist_ok=True)
                continue
            for child in src_dir.iterdir():
                if not child.is_dir():
                    continue
                dest = dest_root / child.name
                shutil.copytree(child, dest, dirs_exist_ok=True)

    def write_poc(self, sandbox_path: Path, code: str, fingerprint: str) -> Path:
        poc_path = sandbox_path / "test" / "AutonomousExploit.t.sol"
        poc_path.parent.mkdir(parents=True, exist_ok=True)
        poc_path.write_text(code)
        return poc_path

    def run(self, sandbox_path: Path, poc_path: Path, timeout: int = 90) -> SandboxResult:
        # Build
        ok, out, err = self._run(["forge", "build", "--via-ir"], cwd=sandbox_path, timeout=timeout)
        if not ok:
            return SandboxResult(
                ok=False, output=out, error=err, returncode=1,
                revert_reason=err[-512:] if err else "",
            )
        # Test
        test_name = "test_autonomous_exploit"
        test_cmd = [
            "forge", "test", "--match-test", test_name, "-vvv",
            "--no-match-path", "lib/**", "--via-ir",
        ]
        if self.fork_url:
            test_cmd.extend(["--fork-url", self.fork_url])
        ok, out, err = self._run(
            test_cmd,
            cwd=sandbox_path, timeout=timeout,
        )
        combined = out + "\n" + err
        if self.fork_url:
            # Foundry may echo the RPC URL (with embedded key) in error
            # output; strip it so credentials never reach reports.
            combined = combined.replace(self.fork_url, "<redacted-fork-url>")
        # Try to extract gas used
        gas_used = None
        import re
        m = re.search(r"gas:\s*(\d+)", combined)
        if m:
            try:
                gas_used = int(m.group(1))
            except ValueError:
                pass
        return SandboxResult(
            ok=ok,
            output=combined,
            error=err if not ok else "",
            returncode=0 if ok else 1,
            gas_used=gas_used,
            revert_reason=self._extract_revert_reason(combined),
        )

    def write_and_run(self, code: str, fingerprint: str, timeout: int = 90) -> tuple[bool, str]:
        """Setup once, then write+run the PoC."""
        try:
            root = self.setup(self.target_path)
            poc = self.write_poc(root, code, fingerprint)
            result = self.run(root, poc, timeout=timeout)
            return result.ok, result.output
        except Exception as e:  # noqa: BLE001
            return False, f"sandbox error: {e}"

    def _run(self, cmd: list[str], *, cwd: Path, timeout: int) -> tuple[bool, str, str]:
        report = self.guard.prepare_subprocess(cmd, cwd=cwd)
        env = report.env
        # Don't expose API keys to the subprocess
        env.pop("NIM_API_KEY", None)
        env.pop("OPENAI_API_KEY", None)
        env.pop("OPENROUTER_API_KEY", None)
        env.pop("GROQ_API_KEY", None)
        env.pop("DEEPSEEK_API_KEY", None)
        env.pop("ANTHROPIC_API_KEY", None)
        try:
            proc = subprocess.run(
                cmd, cwd=report.cwd, env=env,
                capture_output=True, text=True, timeout=timeout,
                preexec_fn=self.guard.apply_resource_limits if sys.platform != "win32" else None,
            )
            return (
                proc.returncode == 0,
                self.guard.truncate_revert_reason(proc.stdout),
                self.guard.truncate_revert_reason(proc.stderr),
            )
        except subprocess.TimeoutExpired:
            return False, "", f"timed out after {timeout}s"
        except FileNotFoundError as e:
            return False, "", f"command not found: {e}"

    @staticmethod
    def _extract_revert_reason(output: str) -> str:
        # Look for ` revert:` or `Error:` markers
        import re
        for pattern in (
            r"revert:\s*([^\n]+)",
            r"Error\((\w+)\)",
            r"Panic\((\d+)\)",
        ):
            m = re.search(pattern, output)
            if m:
                return m.group(1)[:512]
        return ""

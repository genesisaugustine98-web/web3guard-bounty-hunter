"""
Anchor sandbox for Solana / Rust programs.

Initializes a fresh ``anchor init`` project, copies the target's
``programs/`` into it, and runs ``anchor test`` on a TypeScript PoC.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from web3guard.languages.base import LanguageAdapter
from web3guard.sandbox.base import SandboxResult
from web3guard.sandbox.foundry import FoundrySandbox
from web3guard.security import SandboxGuard, SandboxPolicy

LOGGER = logging.getLogger("web3guard.sandbox.anchor")


class AnchorSandbox:
    """Anchor-based sandbox for Solana / Rust programs."""

    language = "rust-solana"

    def __init__(
        self,
        adapter: LanguageAdapter,
        target_path: Path,
        workdir: Path,
        policy: SandboxPolicy | None = None,
    ) -> None:
        self.adapter = adapter
        self.target_path = target_path
        self.workdir = workdir
        self.guard = SandboxGuard(policy or SandboxPolicy())
        self._root: Path | None = None

    def setup(self, target_path: Path) -> Path:
        if self._root is not None:
            return self._root
        root = Path(tempfile.mkdtemp(prefix="web3guard-anchor-", dir=str(self.workdir)))
        try:
            self._run(
                ["anchor", "init", "--no-git", "web3guard-sandbox"],
                cwd=root, timeout=120,
            )
        except Exception as e:  # noqa: BLE001
            LOGGER.error("anchor init failed: %s", e)
        # Move the init's content up
        init_dir = root / "web3guard-sandbox"
        if init_dir.exists():
            for child in init_dir.iterdir():
                shutil.move(str(child), str(root / child.name))
            init_dir.rmdir()
        # Copy the target's programs/ into the sandbox
        target_programs = target_path / "programs"
        if target_programs.is_dir():
            for child in target_programs.iterdir():
                dest = root / "programs" / child.name
                if dest.exists():
                    shutil.rmtree(dest, ignore_errors=True)
                shutil.copytree(child, dest)
        # Copy target's tests/ if present
        target_tests = target_path / "tests"
        if target_tests.is_dir():
            for child in target_tests.iterdir():
                dest = root / "tests" / child.name
                if dest.exists():
                    shutil.rmtree(dest, ignore_errors=True)
                shutil.copytree(child, dest) if child.is_dir() else shutil.copy2(child, dest)
        self._root = root
        return root

    def write_poc(self, sandbox_path: Path, code: str, fingerprint: str) -> Path:
        poc = sandbox_path / "tests" / "exploit.ts"
        poc.parent.mkdir(parents=True, exist_ok=True)
        poc.write_text(code)
        return poc

    def run(self, sandbox_path: Path, poc_path: Path, timeout: int = 120) -> SandboxResult:
        # Build
        ok, out, err = self._run(["anchor", "build"], cwd=sandbox_path, timeout=timeout)
        if not ok:
            return SandboxResult(ok=False, output=out, error=err, returncode=1)
        # Test
        rc, out, err = self._run(
            ["anchor", "test", "--skip-deploy"],
            cwd=sandbox_path, timeout=timeout,
        )
        return SandboxResult(
            ok=rc == 0,
            output=out + "\n" + err,
            error=err if rc != 0 else "",
            returncode=rc,
        )

    def write_and_run(self, code: str, fingerprint: str, timeout: int = 120) -> tuple[bool, str]:
        try:
            root = self.setup(self.target_path)
            poc = self.write_poc(root, code, fingerprint)
            r = self.run(root, poc, timeout=timeout)
            return r.ok, r.output
        except Exception as e:  # noqa: BLE001
            return False, f"anchor sandbox error: {e}"

    def _run(self, cmd: list[str], *, cwd: Path, timeout: int) -> tuple[bool, str, str]:
        report = self.guard.prepare_subprocess(cmd, cwd=cwd)
        env = report.env
        for k in (
            "NIM_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY",
            "GROQ_API_KEY", "DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY",
        ):
            env.pop(k, None)
        try:
            proc = subprocess.run(
                cmd, cwd=report.cwd, env=env,
                capture_output=True, text=True, timeout=timeout,
                preexec_fn=self.guard.apply_resource_limits,
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

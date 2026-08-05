"""
Generic test sandbox used by the less common runners (Scarb, Move,
Clarinet, Blueprint, ts-node).

These are functionally identical: they (1) initialize a fresh
project, (2) copy the target's user code in, (3) write the AI's PoC
to a per-runner path, (4) invoke the runner's test command and
capture output.

The differences are all in the init/build/test commands and the PoC
file location, which are pulled from the adapter's
:class:`TestRunner` description. This generic implementation
re-uses that information rather than special-casing each runner.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from web3guard.languages.base import LanguageAdapter
from web3guard.sandbox.base import SandboxResult
from web3guard.security import SandboxGuard, SandboxPolicy

LOGGER = logging.getLogger("web3guard.sandbox.generic")


class GenericSandbox:
    """A configurable sandbox for any test runner."""

    language = "unknown"
    file_globs: tuple[str, ...] = ()     # file suffixes to copy
    skip_globs: tuple[str, ...] = ()     # substrings to skip
    skip_suffixes: tuple[str, ...] = ()  # filename suffixes to skip
    poc_filename: str = "exploit.t.sol"
    build_timeout: int = 120
    test_timeout: int = 90

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
        root = Path(tempfile.mkdtemp(prefix=f"web3guard-{self.language}-", dir=str(self.workdir)))
        # Init the project
        try:
            self._run(list(self.adapter.test_runner.init_command), cwd=root, timeout=60)
        except Exception as e:  # noqa: BLE001
            LOGGER.error("init command failed for %s: %s", self.language, e)
        # Some runners init into a subdir; flatten it.
        for sub in root.iterdir():
            if sub.is_dir() and sub.name not in ("lib", "node_modules", "programs", "tests", "sources", "contracts", "func"):
                for child in sub.iterdir():
                    if child.is_dir():
                        shutil.copytree(child, root / child.name, dirs_exist_ok=True)
                    else:
                        shutil.copy2(child, root / child.name)
                shutil.rmtree(sub, ignore_errors=True)
                break
        # Copy the target's user code.
        for fp in target_path.rglob("*"):
            if not fp.is_file():
                continue
            rel = fp.relative_to(target_path)
            rel_str = "/" + rel.as_posix().lower().strip("/") + "/"
            if any(s in rel_str for s in self.skip_globs):
                continue
            if fp.suffix not in self.file_globs:
                continue
            if any(fp.name.lower().endswith(s) for s in self.skip_suffixes):
                continue
            # Mirror directory structure
            dest = root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(fp, dest)
            except Exception as e:  # noqa: BLE001
                LOGGER.debug("copy failed for %s: %s", fp, e)
        self._root = root
        return root

    def write_poc(self, sandbox_path: Path, code: str, fingerprint: str) -> Path:
        poc = sandbox_path / self.adapter.test_runner.poc_relative_path
        poc.parent.mkdir(parents=True, exist_ok=True)
        # If the path doesn't have a recognized extension, rename.
        if not poc.suffix:
            poc = poc.with_name(poc.name + self.poc_suffix)
        poc.write_text(code)
        return poc

    poc_suffix: str = ""

    def run(self, sandbox_path: Path, poc_path: Path, timeout: int = 90) -> SandboxResult:
        # Build
        build = list(self.adapter.test_runner.build_command)
        if build:
            ok, out, err = self._run(build, cwd=sandbox_path, timeout=self.build_timeout)
            if not ok:
                return SandboxResult(ok=False, output=out, error=err, returncode=1)
        # Test
        test_name = poc_path.stem
        test_cmd = [c.format(test_name=test_name) for c in self.adapter.test_runner.test_command_template]
        ok, out, err = self._run(test_cmd, cwd=sandbox_path, timeout=timeout)
        return SandboxResult(
            ok=ok,
            output=out + "\n" + err,
            error=err if not ok else "",
            returncode=0 if ok else 1,
        )

    def write_and_run(self, code: str, fingerprint: str, timeout: int = 90) -> tuple[bool, str]:
        try:
            root = self.setup(self.target_path)
            poc = self.write_poc(root, code, fingerprint)
            r = self.run(root, poc, timeout=timeout)
            return r.ok, r.output
        except Exception as e:  # noqa: BLE001
            return False, f"{self.language} sandbox error: {e}"

    def _run(self, cmd: Sequence[str], *, cwd: Path, timeout: int) -> tuple[bool, str, str]:
        report = self.guard.prepare_subprocess(list(cmd), cwd=cwd)
        env = report.env
        for k in (
            "NIM_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY",
            "GROQ_API_KEY", "DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY",
        ):
            env.pop(k, None)
        try:
            proc = subprocess.run(
                list(cmd), cwd=report.cwd, env=env,
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

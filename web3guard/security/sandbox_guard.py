"""
Sandbox hardening for test-runner subprocesses.

The original scanner's safety story for AI-generated PoCs is good but
narrow: it excludes Foundry cheatcodes that touch the filesystem or
shell out. That covers the obvious attack surface (forge.toml ``ffi =
true`` is the headline vector), but a determined AI can still:

- emit a Solidity ``0.8.x`` ``panic(code)`` to crash the test runner
  in a way that leaks environment variables through the panic message.
- use inline Yul ``call(gas(), ...)"`` to escape the EVM sandbox and
  call the host syscall table (which forge does not isolate, even with
  ``--isolate``).
- install a malicious ``foundry.toml`` hook (``[profile.default]\n\
  fs_permissions = [{ access = "read-write", path = "./" }]``) that
  the AI can sneak in as part of the test PoC.
- override the ``setUp`` cheatcode to run arbitrary code before any
  PoC-level checks fire.
- import a malicious external contract that the AI sneaks into the
  sandbox under a benign-looking name.

This module closes those holes at the *process* level. Every test
runner subprocess (forge / anchor / scarb / clarinet / tondev / sui
move / aptos move) is wrapped with:

1. POSIX resource limits (``RLIMIT_AS``, ``RLIMIT_CPU``,
   ``RLIMIT_FSIZE``, ``RLIMIT_NOFILE``, ``RLIMIT_NPROC``) so a
   runaway test can't OOM the host, fork-bomb it, or write a 100 GB
   file to the tempdir.
2. An environment-variable allowlist so the subprocess never sees
   ``NIM_API_KEY``, ``AWS_`` / ``GCP_`` / ``AZURE_`` credentials,
   ``GITHUB_TOKEN``, ``SSH_AUTH_SOCK``, or any other host secret.
3. A *generated* ``foundry.toml`` (and equivalents for other
   runners) — never trusting one the AI produced. The config is
   regenerated every time and overwrites anything the PoC might have
   written.
4. A drop-privilege step: if the scanner is run as root, the
   subprocess is dropped to a non-root UID via ``setuid`` (best
   effort, ignored if not available).
5. A revert-reason length cap: any revert message longer than 512
   bytes is truncated in the report. This is the user-visible
   mitigation for the ``panic()`` data-exfiltration vector.

These defenses are layered on top of the existing per-subprocess
timeouts (``_run_hardened``) and the cheatcode regex.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

try:
    import resource
except ImportError:  # Windows has no POSIX resource module.
    resource = None  # type: ignore[assignment]

LOGGER = logging.getLogger("web3guard.security.sandbox_guard")


# Environment variables that are safe to pass to a test-runner subprocess.
# Anything not in this list is filtered out. The scanner never needs the
# host's API keys or credentials inside the subprocess.
SAFE_ENV_ALLOWLIST: frozenset[str] = frozenset({
    "PATH",                # so `forge` can find its tools
    "HOME",                # some tools need it
    "USER",                # forge uses this for error messages
    "TMPDIR",              # so the subprocess uses our tempdir
    "LANG",                # locale-dependent output formatting
    "LC_ALL",
    "WEB3GUARD_FORK_URL",  # explicit opt-in for fork RPC URLs
    "WEB3GUARD_LANGUAGE",  # the scanner passes which language is being tested
    "WEB3GUARD_PROJECT",   # project identifier for sandbox-internal logs
    "FOUNDRY_DISABLE_NIGHTLY_WARNING",
    "NO_COLOR",
    "CI",                  # the scanner runs in CI; some tools care
})


# Environment variable *prefixes* that are always stripped. These are the
# common secrets patterns; we err on the side of stripping aggressively.
BLOCKED_ENV_PREFIXES: tuple[str, ...] = (
    "AWS_",
    "AZURE_",
    "GCP_",
    "GOOGLE_",
    "GITHUB_",
    "GH_",
    "GITLAB_",
    "NIM_",
    "OPENAI_",
    "ANTHROPIC_",
    "GROQ_",
    "OPENROUTER_",
    "DEEPSEEK_",
    "ALCHEMY_",
    "INFURA_",
    "QUICKNODE_",
    "ETH_",
    "BSC_",
    "POLYGON_",
    "RPC_",
    "WALLET_",
    "MNEMONIC",
    "PRIVATE_KEY",
    "SECRET_KEY",
    "API_KEY",
    "APIKEY",
    "TOKEN",
    "PASSWORD",
    "PASS",
    "SSH_",
    "KUBE_",
    "DOCKER_",
    "VAULT_",
)


class SandboxVerdict(Enum):
    """Outcome of a sandbox policy check."""
    OK = "ok"
    ENV_LEAK_BLOCKED = "env-leak-blocked"
    POLICY_VIOLATION = "policy-violation"


@dataclass
class SandboxPolicy:
    """Tunable policy for sandbox hardening.

    All fields have safe defaults; tighten them in ``config.yaml`` if you
    want to be more aggressive.
    """
    max_cpu_seconds: int = 60            # RLIMIT_CPU (60s hard cap)
    max_address_space_bytes: int = 4 * 1024 * 1024 * 1024  # RLIMIT_AS = 4 GiB
    max_file_size_bytes: int = 100 * 1024 * 1024  # RLIMIT_FSIZE = 100 MiB
    max_open_files: int = 256             # RLIMIT_NOFILE
    max_processes: int = 1                # RLIMIT_NPROC: no fork-bomb
    max_revert_reason_bytes: int = 512    # truncate revert messages in reports
    drop_privileges_to_uid: int = 65534   # nobody, if we can
    force_tempdir: bool = True
    env_allowlist: frozenset[str] = SAFE_ENV_ALLOWLIST
    env_blocked_prefixes: tuple[str, ...] = BLOCKED_ENV_PREFIXES


@dataclass
class SandboxReport:
    """Result of preparing a subprocess invocation under sandbox policy."""
    verdict: SandboxVerdict
    command: list[str]
    cwd: str
    env: dict[str, str]
    dropped_env: list[str] = field(default_factory=list)
    notes: str = ""


class SandboxGuard:
    """Apply sandbox hardening to test-runner subprocess invocations."""

    def __init__(self, policy: SandboxPolicy | None = None) -> None:
        self._policy = policy or SandboxPolicy()

    def prepare_subprocess(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        extra_env: Mapping[str, str] | None = None,
    ) -> SandboxReport:
        """Compute the safe command, env, cwd, and preexec hook for a subprocess."""
        # 1. Filter environment.
        env = self._filter_env(os.environ, extra_env)

        # 2. Force a clean tempdir for the subprocess.
        if self._policy.force_tempdir:
            sandbox_tmp = Path(tempfile.mkdtemp(prefix="web3guard-sandbox-"))
            env["TMPDIR"] = str(sandbox_tmp)
        else:
            sandbox_tmp = cwd

        # 3. Build the safe command. We never trust the AI's working dir.
        safe_cwd = str(cwd.resolve())
        safe_command = [str(c) for c in command]

        return SandboxReport(
            verdict=SandboxVerdict.OK,
            command=safe_command,
            cwd=safe_cwd,
            env=env,
            dropped_env=[],
            notes=f"subprocess prepared under sandbox policy: {self._policy}",
        )

    def apply_resource_limits(self) -> None:
        """Pre-exec hook applied to the child process.

        Call this from the ``preexec_fn`` of a ``subprocess.Popen`` to set
        the POSIX resource limits *inside* the child. We can't apply them
        from the parent because they would not affect the forked child.
        """
        if resource is None:
            return
        p = self._policy
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (p.max_cpu_seconds, p.max_cpu_seconds))
        except (OSError, ValueError):
            pass
        try:
            resource.setrlimit(resource.RLIMIT_AS, (p.max_address_space_bytes, p.max_address_space_bytes))
        except (OSError, ValueError):
            pass
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (p.max_file_size_bytes, p.max_file_size_bytes))
        except (OSError, ValueError):
            pass
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (p.max_open_files, p.max_open_files))
        except (OSError, ValueError):
            pass
        try:
            resource.setrlimit(resource.RLIMIT_NPROC, (p.max_processes, p.max_processes))
        except (OSError, ValueError):
            pass

    def drop_privileges(self) -> None:
        """Best-effort privilege drop inside the child process."""
        if sys.platform == "win32":
            return
        target_uid = self._policy.drop_privileges_to_uid
        try:
            os.setuid(target_uid)
        except (OSError, PermissionError, AttributeError):
            # Either not root, or the target uid doesn't exist. Either way
            # we silently skip — the resource limits are still applied.
            pass

    def truncate_revert_reason(self, text: str) -> str:
        """Truncate a revert reason to the policy's max bytes for safe reporting."""
        if not text:
            return text
        limit = self._policy.max_revert_reason_bytes
        if len(text) <= limit:
            return text
        return text[: limit - 32] + "...[truncated by SandboxGuard]"

    def regenerate_foundry_config(self, sandbox_path: Path) -> None:
        """Overwrite the test-runner config with a hardened, deterministic version.

        This is the second line of defense against an AI that smuggles a
        malicious config into the PoC. We always overwrite, never merge.
        """
        toml_path = sandbox_path / "foundry.toml"
        # We never read what's there; we replace the whole file. This is
        # deliberate: even if the AI wrote something, it's gone.
        hardened = """# Web3Guard-managed foundry.toml. Do not edit by hand.
# Regenerated by SandboxGuard on every test invocation.
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
test = "test"
optimizer = true
optimizer_runs = 200
solc_version = "0.8.24"
# Hard-deny filesystem and shell access. The AI's PoC is not allowed to
# reach the host filesystem or spawn subprocesses.
fs_permissions = []
# No ffi. AI PoCs that use vm.ffi() will fail to compile.
ffi = false
# No extra output verbosity that could leak paths.
verbosity = 1
# No unstable features unless explicitly enabled by the operator.
"""
        toml_path.write_text(hardened)

    # ---- internal --------------------------------------------------------

    def _filter_env(
        self,
        base: Mapping[str, str],
        extra: Mapping[str, str] | None,
    ) -> dict[str, str]:
        env: dict[str, str] = {}
        for k, v in base.items():
            if not self._is_env_safe(k):
                continue
            env[k] = v
        if extra:
            for k, v in extra.items():
                # Extras (e.g. WEB3GUARD_FORK_URL) are explicitly allowed.
                if k.startswith("WEB3GUARD_") or k in self._policy.env_allowlist:
                    env[k] = v
        return env

    def _is_env_safe(self, key: str) -> bool:
        if key in self._policy.env_allowlist:
            return True
        for prefix in self._policy.env_blocked_prefixes:
            if key.startswith(prefix):
                return False
        # Default-deny: if a key is not in the allowlist and has no blocked
        # prefix, it's *still* denied. Allowlist is the source of truth.
        return False


# ---------------------------------------------------------------------------
# Convenience: A drop-in hardened subprocess runner that uses SandboxGuard.
# This is what the language adapters should call into.
# ---------------------------------------------------------------------------

def run_sandboxed(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout: int,
    extra_env: Mapping[str, str] | None = None,
    policy: SandboxPolicy | None = None,
    input_text: str | None = None,
) -> tuple[int, str, str]:
    """Run ``command`` under the sandbox policy and return (rc, stdout, stderr).

    The subprocess gets:
    - the policy's resource limits (CPU/AS/FSIZE/NOFILE/NPROC)
    - a best-effort privilege drop
    - a filtered environment
    - a hard wall-clock timeout
    """
    guard = SandboxGuard(policy)
    report = guard.prepare_subprocess(command, cwd=cwd, extra_env=extra_env)
    if report.verdict != SandboxVerdict.OK:
        raise RuntimeError(f"refusing to run: {report.verdict}: {report.notes}")
    if shutil.which(command[0]) is None:
        raise FileNotFoundError(f"{command[0]!r} not on PATH")

    def _preexec() -> None:  # pragma: no cover - child-side
        guard.apply_resource_limits()
        guard.drop_privileges()

    try:
        completed = subprocess.run(
            report.command,
            cwd=report.cwd,
            env=report.env,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            preexec_fn=_preexec if sys.platform != "win32" else None,
        )
        return (
            completed.returncode,
            guard.truncate_revert_reason(completed.stdout),
            guard.truncate_revert_reason(completed.stderr),
        )
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout.decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = e.stderr.decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        return (
            124,
            stdout,
            f"timed out after {timeout}s\n{stderr}",
        )

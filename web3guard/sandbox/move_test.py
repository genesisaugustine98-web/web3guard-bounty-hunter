"""Move sandbox — used for both Aptos and Sui."""

from __future__ import annotations

from web3guard.sandbox._generic import GenericSandbox


class MoveSandbox(GenericSandbox):
    """`aptos move test` or `sui move test` for Move packages."""

    language = "move"
    file_globs = (".move",)
    skip_globs = ("/build/", "/.cache/", "/test-only/", "/tests/")
    skip_suffixes = ("_test.move",)
    poc_suffix = ".move"

    def run(self, sandbox_path, poc_path, timeout=90):
        # The Move toolchain auto-detects Aptos vs Sui from Move.toml.
        # If Move.toml has [package] with name = ... and edition = ... and
        # build = ..., we use the right CLI.
        move_toml = sandbox_path / "Move.toml"
        is_aptos = True
        if move_toml.exists():
            try:
                text = move_toml.read_text(errors="ignore")
                is_aptos = "Aptos" in text or "aptos" in text
            except Exception:
                pass
        test_cmd = ["aptos", "move", "test", "--filter", "test_exploit"] if is_aptos \
            else ["sui", "move", "test", "--filter", "test_exploit"]
        from web3guard.sandbox.base import SandboxResult
        from web3guard.security import SandboxGuard
        guard = SandboxGuard()
        try:
            proc = self._run(test_cmd, cwd=sandbox_path, timeout=timeout)  # type: ignore[arg-type]
            rc_ok, out, err = proc
            return SandboxResult(ok=rc_ok, output=out + "\n" + err, error=err if not rc_ok else "", returncode=0 if rc_ok else 1)
        except Exception as e:
            return SandboxResult(ok=False, output=str(e), error=str(e), returncode=1)

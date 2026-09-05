"""Scarb sandbox for Cairo (Starknet)."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from web3guard.sandbox._generic import GenericSandbox


class ScarbSandbox(GenericSandbox):
    """`scarb test` for Cairo projects."""

    language = "cairo"
    file_globs = (".cairo",)
    skip_globs = ("/target/", "/.scarb/", "/tests/")
    skip_suffixes = ("_test.cairo",)
    poc_suffix = ".cairo"

    def post_init(self, sandbox_path: Path) -> None:
        manifest = sandbox_path / "Scarb.toml"
        if not manifest.is_file():
            return
        text = manifest.read_text(encoding="utf-8")
        text = self._drop_executable_section(text)
        if "cairo_test" not in text:
            # `#[test]` / `#[cfg(test)]` are provided by the cairo_test plugin
            # (scarb init no longer emits it when --test-runner none). Pin it
            # to the installed scarb release.
            version = self._cairo_test_version()
            if "[dev-dependencies]" not in text:
                if text and not text.endswith("\n"):
                    text += "\n"
                text += "\n[dev-dependencies]\n"
            if not text.endswith("\n"):
                text += "\n"
            text += f'cairo_test = "{version}"\n'
        manifest.write_text(text, encoding="utf-8")

    @staticmethod
    def _drop_executable_section(text: str) -> str:
        """Remove the `[executable]` manifest section.

        `scarb init --test-runner none` scaffolds an executable crate whose
        `#[executable] fn main` lives in the generated module; overwriting
        src/lib.cairo with the PoC orphans that target and fails the build
        with "requested `#[executable]` not found".
        """
        lines = text.splitlines()
        out: list[str] = []
        skipping = False
        for ln in lines:
            s = ln.strip()
            if s.startswith("[executable]") or s.startswith("[executable."):
                skipping = True
                continue
            if skipping and s.startswith("["):
                skipping = False
            if not skipping:
                out.append(ln)
        return "\n".join(out).rstrip() + "\n"

    @staticmethod
    def _cairo_test_version() -> str:
        try:
            out = subprocess.run(
                ["scarb", "--version"], capture_output=True, text=True, timeout=15,
            ).stdout
            m = re.search(r"^scarb\s+(\d+\.\d+\.\d+)", out, re.MULTILINE)
            if m:
                return m.group(1)
        except Exception:  # noqa: BLE001
            pass
        return "2.20.1"

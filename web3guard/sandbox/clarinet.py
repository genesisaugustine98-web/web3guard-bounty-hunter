"""Clarinet sandbox for Clarity (Stacks)."""

from __future__ import annotations

from web3guard.sandbox._generic import GenericSandbox


class ClarinetSandbox(GenericSandbox):
    """`clarinet test` for Stacks / Clarity projects."""

    language = "clarity"
    file_globs = (".clar",)
    skip_globs = ("/tests/", "/.clarinet/", "/settings/", "/contracts/")
    skip_suffixes = ()
    poc_suffix = ".clar"

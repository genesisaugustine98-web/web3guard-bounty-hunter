"""TON Blueprint sandbox for FunC contracts."""

from __future__ import annotations

from web3guard.sandbox._generic import GenericSandbox


class TonBlueprintSandbox(GenericSandbox):
    """`blueprint test` for TON / FunC projects."""

    language = "func"
    file_globs = (".fc",)
    skip_globs = ("/build/", "/.ton/", "/tests/")
    skip_suffixes = ()
    poc_suffix = ".fc"

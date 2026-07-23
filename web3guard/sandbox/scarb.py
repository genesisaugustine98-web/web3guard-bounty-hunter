"""Scarb sandbox for Cairo (Starknet)."""

from __future__ import annotations

from web3guard.sandbox._generic import GenericSandbox


class ScarbSandbox(GenericSandbox):
    """`scarb test` for Cairo projects."""

    language = "cairo"
    file_globs = (".cairo",)
    skip_globs = ("/target/", "/.scarb/", "/tests/")
    skip_suffixes = ("_test.cairo",)
    poc_suffix = ".cairo"

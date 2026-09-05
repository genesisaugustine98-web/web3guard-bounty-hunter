"""Clarinet sandbox for Clarity (Stacks)."""

from __future__ import annotations

from web3guard.sandbox._generic import GenericSandbox


class ClarinetSandbox(GenericSandbox):
    """`clarinet check` for Clarity projects.

    Clarinet removed its JS test runner (`clarinet test`) and offers no
    headless simnet unit-test command in current releases, so PoCs are
    validated by compiling the PoC contract with `clarinet check FILE`.
    """

    language = "clarity"
    file_globs = (".clar",)
    skip_globs = ("/tests/", "/.clarinet/", "/settings/", "/contracts/")
    skip_suffixes = ()
    poc_suffix = ".clar"

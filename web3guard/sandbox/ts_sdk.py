"""TypeScript / JavaScript off-chain SDK sandbox."""

from __future__ import annotations

from web3guard.sandbox._generic import GenericSandbox


class TSSandbox(GenericSandbox):
    """`ts-node` / `tsx` for off-chain TypeScript PoCs."""

    language = "ts-sdk"
    file_globs = (".ts", ".js", ".mjs", ".cjs")
    skip_globs = ("/node_modules/", "/dist/", "/build/", "/tests/", "/test/")
    skip_suffixes = ("test.ts", "test.js", "spec.ts", "spec.js", "test.mjs", "test.cjs")
    poc_suffix = ".ts"

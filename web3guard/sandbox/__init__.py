"""
Sandbox abstractions for running AI-generated PoCs.

The original scanner has a single ``setup_foundry_sandbox`` function
that copies a target's Solidity files into a fresh ``forge init``
project. This module generalizes that pattern: every test runner
(Foundry, Anchor, Scarb, Clarinet, Blueprint, etc.) implements the
:class:`TestSandbox` protocol, and a single factory
(:func:`create_sandbox`) returns the right one for a given
:class:`LanguageAdapter`.
"""

from web3guard.sandbox.base import (
    TestSandbox,
    SandboxResult,
    create_sandbox,
)

__all__ = [
    "TestSandbox",
    "SandboxResult",
    "create_sandbox",
]

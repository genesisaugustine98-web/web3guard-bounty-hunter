"""
Web3Guard Autonomous Exploit Hunter — multi-language, multi-chain smart contract
vulnerability scanner with AI-driven semantic reasoning.

Augmented edition: extends the original Solidity/EVM-only pipeline with
Vyper, Move (Aptos/Sui), Cairo (Starknet), Clarity (Stacks), FunC (TON),
Rust (Solana/Anchor), and TypeScript/JavaScript SDK analysis, plus prompt-
injection defenses, sandbox hardening, deterministic replays, fallback AI
providers, token-cost control, PoC quality scoring, SARIF/Markdown/PDF
reporting, finding lifecycle tracking, and an economic/ROI analyzer.

This is the package entry point. The CLI entry point lives in
``web3guard/cli.py`` and is also exposed as ``python -m web3guard``.
"""

from __future__ import annotations

__version__ = "3.0.0"
__author__ = "Web3Guard Contributors"
__license__ = "MIT"

# Public re-exports for the most common entry points.
from web3guard.scanner import Scanner, ScanResult  # noqa: E402
from web3guard.languages import (  # noqa: E402
    LanguageRegistry,
    TargetLanguage,
    detect_target_language,
)
from web3guard.ai import AIClient, AIProvider  # noqa: E402
from web3guard.reports import ReportBuilder  # noqa: E402
from web3guard.security import (  # noqa: E402
    PromptInjectionGuard,
    SandboxGuard,
)
from web3guard.findings_db import FindingsDB  # noqa: E402

__all__ = [
    "Scanner",
    "ScanResult",
    "LanguageRegistry",
    "TargetLanguage",
    "detect_target_language",
    "AIClient",
    "AIProvider",
    "ReportBuilder",
    "PromptInjectionGuard",
    "SandboxGuard",
    "FindingsDB",
    "__version__",
]

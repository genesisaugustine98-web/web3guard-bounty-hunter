"""
Base types for the language-adapter system.

Every supported target language implements :class:`LanguageAdapter`. The
adapter's job is to answer a small set of well-defined questions about
the target repository:

- which files are user code vs. test/mock/library?
- how do I chunk a file for analysis?
- how do I resolve cross-file context (imports, parent contracts)?
- which discovery engines should I run on this target?
- which test runner do I generate PoCs against?
- which prompt templates should I use to ask the LLM to analyze and
  exploit code in this language?

The intent is to keep the per-language code in one place and to make
adding a new language a matter of writing one subclass.
"""

from __future__ import annotations

import abc
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class TargetLanguage(StrEnum):
    """The set of supported target languages.

    The string value of each member is the canonical lowercase name used
    in reports, configuration, and CLI flags.
    """
    SOLIDITY = "solidity"
    VYPER = "vyper"
    MOVE = "move"
    CAIRO = "cairo"
    CLARITY = "clarity"
    FUNC = "func"
    RUST_SOLANA = "rust-solana"
    TS_SDK = "ts-sdk"
    UNKNOWN = "unknown"


@dataclass
class Chunk:
    """A semantically meaningful chunk of source code for LLM analysis."""
    file: str                 # path relative to the repo root
    chunk_id: int             # 0-based index within the file
    content: str              # the chunk's source code
    kind: str = ""            # free-form label, e.g. "function+storage"
    lines: str = ""           # "10-25" — human-readable line range
    context: str = ""         # cross-file context (imports, parents, etc.)
    language: str = ""        # TargetLanguage value
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class RepoSummary:
    """A cheap, language-agnostic summary of one source file.

    The summary is built up by the adapter's ``summarize_file`` and is
    used for research planning (which files to analyze first) and risk
    scoring.
    """
    file: str
    language: str
    loc: int = 0
    functions: int = 0
    external_calls: int = 0
    state_vars: int = 0
    reads_oracle: bool = False
    moves_value: bool = False
    behind_proxy: bool = False
    has_assembly: bool = False
    uses_inline_pragma: bool = False
    imports: list[str] = field(default_factory=list)
    inherits_from: list[str] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class DiscoveryEngine:
    """Description of a discovery engine to run against a target."""
    name: str                                # e.g. "slither"
    binary: str                              # CLI name to invoke
    invocation: Callable[[Path, int], list[dict[str, Any]]] | None = None
    timeout_seconds: int = 300
    enabled_by_default: bool = True
    # Discovery engines are language-aware: only run the engines whose
    # `supported_languages` includes the target's language.
    supported_languages: tuple[TargetLanguage, ...] = (TargetLanguage.SOLIDITY,)
    notes: str = ""


@dataclass
class TestRunner:
    """Description of a test runner to use for AI-generated PoCs.

    The runner is responsible for:
    - initializing a fresh sandbox project
    - copying the target's user code into the sandbox
    - writing the AI's PoC into the runner's expected location
    - compiling and running the PoC
    - reporting pass/fail with stdout+stderr

    Different runners exist for Foundry (Solidity + Vyper), Anchor
    (Solana), ``aptos move test`` / ``sui move test`` (Aptos + Sui),
    ``scarb test`` (Cairo), ``clarinet test`` (Clarity), and ``tondev``
    / blueprint (FunC).
    """
    name: str                                # e.g. "foundry"
    supported_languages: tuple[TargetLanguage, ...]
    init_command: Sequence[str]              # e.g. ["forge", "init", "--no-git", "--no-commit", "."]
    build_command: Sequence[str]             # e.g. ["forge", "build"]
    test_command_template: Sequence[str]     # e.g. ["forge", "test", "--match-test", "{test_name}"]
    poc_relative_path: str                   # e.g. "test/AutonomousExploit.t.sol"
    has_impact_assertion: Callable[[str], bool] | None = None
    notes: str = ""


class LanguageAdapter(abc.ABC):
    """Abstract base class for a target language.

    Subclasses implement the abstract methods to provide per-language
    behavior. The :class:`LanguageRegistry` constructs one adapter per
    detected language and invokes them in priority order.
    """

    language: TargetLanguage
    extensions: tuple[str, ...]
    priority: int = 100  # lower = higher priority when multiple languages match

    # ---- discovery -------------------------------------------------------

    @abc.abstractmethod
    def detect(self, target_path: Path) -> bool:
        """Return True if this adapter's language is present in the target."""

    @abc.abstractmethod
    def discover_files(self, target_path: Path) -> list[Path]:
        """Return the list of user-code files to analyze.

        The implementation must skip test files, mock files, and
        vendored libraries — these are handled separately by the test
        runner. The default filter (a substring check) is provided as
        a helper: see :func:`_is_user_code`.
        """

    @abc.abstractmethod
    def chunk(self, file_path: Path, max_chars: int) -> list[Chunk]:
        """Split a file into chunks at semantic boundaries."""

    @abc.abstractmethod
    def resolve_context(self, file_path: Path, target_root: Path) -> str:
        """Return related code (imports, parents, etc.) for the file."""

    @abc.abstractmethod
    def summarize(self, file_path: Path, target_root: Path) -> RepoSummary:
        """Build a structural summary of one file."""

    @abc.abstractmethod
    def detect_framework(self, target_path: Path) -> dict[str, Any]:
        """Detect which build tool the target uses (e.g. foundry vs hardhat)."""

    # ---- prompt templates ------------------------------------------------

    @abc.abstractmethod
    def analysis_system_prompt(self) -> str:
        """System prompt for analysis-stage LLM calls in this language."""

    @abc.abstractmethod
    def exploit_user_template(self) -> str:
        """User template for PoC-generation LLM calls in this language."""

    # ---- engines + runner ------------------------------------------------

    @property
    @abc.abstractmethod
    def discovery_engines(self) -> list[DiscoveryEngine]:
        """Discovery engines to run for this language."""

    @property
    @abc.abstractmethod
    def test_runner(self) -> TestRunner:
        """The test runner that backs PoC execution for this language."""

    # ---- helpers ---------------------------------------------------------

    def _is_user_code(self, file_path: Path) -> bool:
        """Default filter: skip tests, mocks, libraries, dependencies.

        Subclasses can override, but the default is correct for most
        languages and respects the original scanner's exclusion list.
        """
        s = "/" + str(file_path).replace("\\", "/").lower().strip("/") + "/"
        for marker in (
            "/test/", "/tests/", "/script/", "/scripts/",
            "/mock", "/mocks/", "/stub", "/stubs/",
            "/lib/", "/libs/", "/node_modules/", "/target/",
            "/build/", "/dist/", "/out/", "/.git/",
        ):
            if marker in s:
                return False
        name = file_path.name.lower()
        for suffix in ("test", "mock", "stub", "fake", "spec"):
            if name.endswith(f".{suffix}"):
                return False
        return True

    def is_user_code(self, file_path: Path) -> bool:
        """Public entry point for the user-code filter (overridable)."""
        return self._is_user_code(file_path)

    # ---- vulnerability catalog ------------------------------------------

    def vulnerability_catalog(self) -> str:
        """Language-specific vulnerability catalog.

        Subclasses override to add language-specific patterns. The
        default returns the generic cross-language catalog.
        """
        return _GENERIC_VULN_CATALOG


# ---------------------------------------------------------------------------
# Generic, language-agnostic vulnerability catalog used as a baseline.
# Subclasses extend it with language-specific patterns.
# ---------------------------------------------------------------------------

_GENERIC_VULN_CATALOG = """\
Generic vulnerability patterns to look for in any smart-contract code:

1.  Reentrancy (any external call before state update, any callback
    hook that can re-enter: ERC-777 tokensToSend/tokensReceived,
    ERC-721 onERC721Received, ERC-1155 onERC1155Received)
2.  Access control (missing onlyOwner, unprotected init/upgrade,
    tx.origin for auth, role confusion, default visibility)
3.  Oracle manipulation (spot price, stale data, single source,
    missing roundID, missing staleness, L2 sequencer assumptions)
4.  Arithmetic (overflow / underflow / truncation / rounding direction)
5.  Token integration (fee-on-transfer, rebasing, missing return,
    SafeERC20 not used, decimals not normalized, permit front-run)
6.  Proxy & upgrade (storage collision, uninitialized impl, UUPS
    missing _authorizeUpgrade, delegatecall to attacker, beacon
    hijack, diamond facet not initialized)
7.  Randomness (block.timestamp / blockhash / difficulty / prevrandao
    as RNG, weak PRNG, modulo of any of the above, Chainlink VRF
    requestId reuse)
8.  Signature & crypto (ecrecover malleability, missing chainid in
    domain separator, missing nonce, EIP-712 typehash collision,
    missing zero-address check on ecrecover result)
9.  Gas griefing (external calls in loops, unbounded iteration,
    returnbomb, missing gas stipends, push/pull revert in callback)
10. Cross-contract trust (hardcoded external address, trusted
    upgradeable external call, third-party oracle assumption)
11. Standard compliance (ERC-20 missing return, ERC-4626 first
    deposit inflation, ERC-3156 lender fee, ERC-777 hooks, Permit2
    witness typehash mismatch, ERC-721/1155 missing callbacks)
12. Time dependence (block.timestamp in time-sensitive logic,
    block.number for time, time-warp bypass)
13. Selfdestruct / selfbalance (force-send ETH, post-Cancun
    selfdestruct, selfdestruct of dependent)
14. Governance (flash-loan vote-buying, quorum manipulation, timelock
    bypass, vote delegation before/after proposal, proposal replay)
15. L2 / cross-chain (sequencer uptime, L1↔L2 message verification,
    finality assumptions, replay across domains)
16. MEV / sandwich (slippage = 0, public mempool exposure, sandwich-
    able reward claims)
17. Account abstraction (EntryPoint validation, paymasterAndData
    manipulation, UserOp replay, validateUserOp return handling,
    handleOps reentrancy, EIP-7702 delegation)
18. Bridge / cross-chain (guardian quorum, header validation, merkle
    proof gaps, message verification on L1, replay protection)
"""

"""
Extended vulnerability catalog.

The original scanner shipped with 17 categories. This module
extends the catalog with the categories that the augmentation
roadmap identified as gaps:

- C1: L2-specific (Optimism, Arbitrum, Base precompiles)
- C2: MEV / sandwich / front-running
- C3: Governance attacks
- C4: Cross-chain / bridge
- C5: ERC-4337 / Account Abstraction
- C6: EIP-7702 delegation
- C7: Token-2022 / SPL extensions

Each entry is sent to the LLM in the analysis prompt and is also
used as a check name in the report. Categories are language-aware
so a Move target doesn't see Solidity-specific patterns.
"""

from __future__ import annotations

from web3guard.languages.base import TargetLanguage

# ---------------------------------------------------------------------------
# Per-language vulnerability catalogs
# ---------------------------------------------------------------------------

CATALOG_BY_LANGUAGE: dict[TargetLanguage, str] = {
    TargetLanguage.SOLIDITY: """
### Solidity / EVM specific patterns

1. Reentrancy (all variants):
   - Classic: external call (`call`/`transfer`/`send`) BEFORE state update
   - Cross-function: state A updated in fn1, external call in fn2 reads stale state
   - Cross-contract: external call to contract B, B re-enters self
   - Read-only: `view` reads state that should have been updated
   - ERC-777/1363/721 callback: `tokensToSend`/`tokensReceived`/`onTransferReceived`/`_checkOnERC721Received`
   - Multi-tenant: single storage slot per user, balance not zeroed before call
   - Governance: `vote()` with onERC721Received hook before `_moveDelegates`
   - Withdrawal drain: many withdrawals before accounting updates

2. Access control:
   - Missing `onlyOwner`
   - Unprotected `initialize()`
   - Unprotected `upgradeTo`
   - Signature replay
   - `tx.origin` for auth
   - Role confusion
   - Payable constructor
   - Default function visibility
   - Uninitialized state
   - Function selector clash (proxy admin functions shadow user fns)

3. Oracle manipulation:
   - Spot price from DEX
   - Stale `latestRoundData`
   - Single-source
   - TWAP too short (1-block window is trivially sandwiched)
   - L2 sequencer uptime
   - Missing roundID check

4. Logic flaws:
   - Wrong comparison (`<` vs `<=`)
   - State machine violation
   - Missing zero-address check
   - Unbounded approval
   - Fee-on-transfer not handled
   - ERC-4626 first deposit
   - Rounding direction
   - Cliff bypass
   - Lockup: timestamp vs block mismatch

5. Arithmetic:
   - Solidity <0.8 overflow
   - `unchecked { }` containing math
   - Precision loss in division
   - Multiplication before division
   - Type truncation
   - Negative literal cast to uint

6. Token integration:
   - Fee-on-transfer (PAXG, USDT)
   - Rebasing tokens (steth, AMPL)
   - ERC-777 hooks
   - ERC-1155 batchTransfer
   - Missing return value (USDT, BNB)
   - `SafeERC20` not used
   - Token decimals not normalized
   - WETH deposit/withdraw race
   - Permit front-running
   - Permit2 witness typehash mismatch

7. DeFi-specific:
   - Slippage bypass (minOut=0)
   - Public mempool exposure (MEV)
   - Liquidation logic
   - Flash loan abuse
   - Reward calculation
   - AMM invariant violation
   - Collateral factor > 1
   - Same asset as collateral in 2 pools
   - Flash-loan vote buying

8. Proxy & upgrade:
   - Storage collision
   - Uninitialized implementation
   - `delegatecall` to attacker addr
   - UUPS missing `_authorizeUpgrade`
   - Transparent proxy selector clash
   - Malicious beacon
   - Diamond facet not initialized
   - Initializer called twice
   - Upgrade to selfdestructing impl

9. Randomness:
   - `block.timestamp` as RNG
   - `blockhash` only valid 256 blks
   - `block.difficulty` / `prevrandao`
   - `keccak256` of block fields
   - Chainlink VRF requestId reused
   - Modulo of any of the above

10. Signature & crypto:
    - `ecrecover` malleability (`v` 27/28)
    - Cross-chain replay (no chainid)
    - Missing nonce
    - EIP-712 domain separator stale
    - EIP-712 typehash collision
    - OpenZeppelin ECDSA not used
    - Sig used as ID
    - `ecrecover` returning `address(0)` not checked

11. Gas griefing:
    - External calls in loops
    - Unbounded iteration
    - Returnbomb
    - Storage growth without pruning
    - Block gas limit dependence
    - Missing gas stipends (`transfer`)
    - Revert in callback (push/pull)

12. L2 / cross-chain (C1):
    - Optimism predeploys (L2 cross-domain messenger, L1 fee vault)
    - Arbitrum precompiles (ArbSys, ArbGasInfo, ArbAggregator, ArbOwner)
    - L2 sequencer uptime assumption
    - L1↔L2 message verification (L1 handler / L2 sender mismatch)
    - Cross-chain replay (no chainid in domain separator)

13. MEV / sandwich / front-running (C2):
    - Slippage set to 0
    - Public mempool exposure
    - Sandwich-able reward claims
    - Oracle updates that hit the mempool
    - Liquidation bots that don't use Flashbots

14. Governance (C3):
    - Flash-loan vote-buying
    - Vote delegation before/after proposal
    - Quorum threshold manipulation
    - Timelock bypass
    - Proposal replay (same proposal ID across instances)
    - Guardian role abuse
    - Multisig threshold changes

15. Cross-chain / bridge (C4):
    - Replay protection across chains (chain ID in domain separator)
    - Outbound message verification on L1
    - Inbound message trust assumptions on L2
    - Bridge finality assumptions
    - Wormhole-style guardian quorum
    - Light client header validation
    - Merkle proof verification gaps

16. Account abstraction / ERC-4337 (C5):
    - EntryPoint validation logic
    - paymasterAndData manipulation
    - UserOperation replay
    - Signature aggregation bugs
    - `validateUserOp` return value handling
    - `handleOps` reentrancy
    - Storage collision in smart accounts
    - Init code deployment attacks

17. EIP-7702 delegation (C7):
    - Phishable delegation
    - Replayable delegation
    - Signature gymnastics
    - Delegation to selfdestruct target

18. Token-2022 / SPL extensions (Solana):
    - Transfer hooks
    - Confidential transfers
    - Permanent delegate
    - Confidential transfer-fee

19. Standard compliance:
    - ERC-20 missing return value
    - ERC-721 onERC721Received missing
    - ERC-1155 batch length check
    - ERC-4626 first deposit
    - ERC-4626 rounding direction
    - ERC-2612 permit front-running
    - ERC-3156 flash loan fee
    - ERC-777 hooks not handled
    - Permit2 witness typehash mismatch
""",

    TargetLanguage.VYPER: """
### Vyper specific patterns

- `raw_call` with unchecked return value
- `init()` re-initialization
- Storage layout differences from Solidity (can break proxy upgrades)
- `@nonpayable`/`@payable` decorator mismatches
- `interface` typing bypass via `msg.sender` casts
- `convert` overflow on integer downcasting
- `slice` bounds miscalculation
- `selfdestruct` in post-Cancun Vyper
- All Solidity patterns (since Vyper compiles to EVM)
""",

    TargetLanguage.MOVE: """
### Move specific patterns

- Missing `acquires` annotation (causes double-borrow abort)
- Ability mismatch (key vs store)
- Capability leaks (resources returned to wrong signer)
- `public(friend)` over-exposure
- Linearizability bugs (parallel execution conflicts)
- Reference semantics violations
- `event::emit_event` failures swallowed
- `coin::merge` overflow
- Coin/resource freeze vulnerabilities
- `randomness` API misuse (Aptos 1.x randomness)
- `timestamp` precision and `epoch` boundaries
""",

    TargetLanguage.CAIRO: """
### Cairo specific patterns

- `get_caller_address()` vs `get_execution_info().caller_addr` confusion
- L1↔L2 messaging bugs (send_message_to_l1 / sync_from_l1 / payload encoding)
- `assert` vs `panic` semantics
- `unsafe` blocks in Sierra lowering
- `syscalls` ordering issues
- Fee estimation bugs
- Component / replaceability pattern misuse
- Storage upgrade / replace_class bugs
""",

    TargetLanguage.CLARITY: """
### Clarity specific patterns

- Post-conditions not used (`withdraw-ft?` etc. without post-condition)
- Trait usage with bad principal
- `contract-call?` return value unchecked
- `as-contract?` misuse
- `tx-sender` vs `contract-caller` confusion
- Bitcoin anchor reorgs
- sBTC signer / Emily implementation bugs
- Time-locked contract bypass via `block-height` miscalculation
""",

    TargetLanguage.FUNC: """
### FunC specific patterns

- Cell overflow (TL-B parsing bugs)
- Missing separation of `recv_internal` vs `recv_external`
- Workchain ID confusion
- Missing `accept()` for message processing
- Missing bounce handling
- Re-entrancy in async message-passing
- `load_msg_addr` slice overflow
- `seqno` replay protection missing
""",

    TargetLanguage.RUST_SOLANA: """
### Solana / Anchor specific patterns

- Missing `owner` check on `AccountInfo`
- Missing signer check
- PDA seed collision / weak seeds
- Account substitution attacks
- Arithmetic on `u64` overflow
- `realloc` truncation / dangling references
- Closing accounts that still have lamports
- `invoke` vs `invoke_signed` confusion
- Missing rent-exemption checks
- Duplicate mutable accounts
- CPI return data unchecked
- Token-2022 extension mishandling
- Compute-budget exhaustion
""",

    TargetLanguage.TS_SDK: """
### TypeScript / JavaScript SDK patterns

- Slippage set to 0
- `amountOutMin` / `amountInMax` not checked
- Permit front-running
- Approval set to MAX_UINT256
- Approve-then-call race
- Replay protection missing in off-chain signature construction
- Hardcoded RPC URLs / private keys / API tokens
- Floating-promise transactions
- L1↔L2 chain ID confusion
- Sign-then-modify pattern
""",
}


def get_catalog(language: TargetLanguage) -> str:
    """Return the language-specific vulnerability catalog."""
    return CATALOG_BY_LANGUAGE.get(language, "")

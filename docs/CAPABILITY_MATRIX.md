# Capability matrix — what this tool does, where, and its honest limits

**Last updated:** 2026-09-25 (post `uncontrolled-payout` port + arithmetic
logic detectors). Every "verified" claim below was produced by a command
in this session and is re-runnable via `make test` / `web3guard bench`.

The pitch in one line: a deterministic, keyless, high-precision
static-analysis funnel for smart-contract vulnerability classes, with an
optional AI semantic layer, wrapped in a secure fetch/scan/report
pipeline. It raises a security team's or bounty hunter's hit rate and
cuts triage time. It is **not** an oracle that finds every bug — no
tool is, and any tool claiming otherwise is selling certainty that does
not exist.

---

## 1. What was added, and why

| Feature | Commit | Why it exists |
|---|---|---|
| mypy root-cause pass (24 errors, 11 modules) | `6b2ffbf` | Typed the optional OpenAI client, narrowed third-party values (getaddrinfo, Slither attrs, tar members), removed 7 stale ignores. Type safety = fewer silent runtime failures on weird inputs. |
| Forge-archive URL routing fix | `ad6eb39` | `scan <github .../archive/....tar.gz>` 404'd in git clone; archive/release/raw URLs now reach the archive transport. Verified end-to-end. |
| `uncontrolled-payout` detector (Solidity) | `38e8332` | First deterministic hook for the "pay what the caller asks, not what the ledger owes" drain class — previously invisible to every pattern detector (proven with a 0-findings experiment on a real airdrop-drain contract). |
| Multi-language port of the payout check | `cecaee2` | Same flaw exists on every chain: Vyper, Rust/Solana (Anchor), Move, Cairo 1, Clarity, TypeScript SDK now share one semantics core with per-language shapes. |
| Fee-basis mismatch + div-before-mul detectors | `796198e` | Two more *proven, paid-out* logic-flaw classes: bps/WAD scale slips and rounding-order extraction in share accounting. The bench gate itself caught (and we fixed) the compensated-math false positive. |

## 2. Detector coverage by language (deterministic layer)

| Language | Categories | Payout logic check | Notes |
|---|---|---|---|
| Solidity | 17+ | yes | deepest set incl. proxy-upgrade combo, 4626, EIP-7702 family |
| Vyper | 3+ | yes | transfer reverts by design; amount-tracking only |
| Rust / Solana (Anchor) | 4+ | yes | `token::transfer`/`mint_to`, AccountInfo substitution, lamport math |
| Move | 2+ | yes | `coin::transfer<CoinType>` 3-arg, missing-acquires, copyable caps |
| Cairo (0 and 1) | 2+ | yes | caller confusion, L1→L2 replay, `.read()` ledger state |
| Clarity | 3+ | yes | `ft-transfer?` vs `(var-get ...)` gates, tx-sender/contract-caller |
| FunC (TON) | 3 | n/a (message-based, no caller-amount idiom) | accept(), recv_external, slice parsing |
| TypeScript SDK | 4+ | yes | slippage-0, unlimited approval, permit, client-side ledger bypass |
| Huff / Yul / asm tiers | unchecked-call, selfdestruct | n/a | stack-machine shapes; no named params to track |

## 3. Verified evidence (this session, re-runnable)

| Check | Result |
|---|---|
| pytest | 342 passed, 12 skipped |
| ruff / mypy | clean (80 files) |
| bench gate | PASS — precision 1.000 / recall 1.000 (in-repo labeled corpus) |
| The DAO @ pre-fix 2016 commit | flags `[HIGH] reentrancy` at the exact exploited line (DAO.sol:584) |
| The DAO @ patched master | no reentrancy flag (guard moved before the call) |
| OpenZeppelin Contracts (full repo) | 0 findings from the new logic detectors; no FP noise on audited core |
| Uniswap v3 core + periphery | 23 findings, 13.0 s wall, zero hits from new logic detectors (their math is correct); deterministic replay identical |
| Aave v3 core | 31 findings, 21.7 s wall, zero new-detector hits (correct: audited WAD/RAY math) |
| Pressure test (fake LLM, real pipeline) | 38 deterministic findings, secrets scanner catches planted key |
| Fetch transports | git, tarball (magic-byte sniffed), zip-slip/link-member refusal — all exercised live |

## 4. Domain coverage and honest status

| Domain | Status |
|---|---|
| Web3 smart contracts (8 languages, 20 dialect tiers) | **verified** — this is the core |
| Exchanges / protocols (source available) | **verified at scale** — Uniswap, Aave, OZ, The DAO |
| On-chain deployed bytecode (no source) | **implemented, not live-exercised** — `0x…`/Blockscout fetch + deployment-verification path needs an RPC endpoint to verify end-to-end |
| IPFS targets | implemented + tested at interface level; gateway fetch not exercised in this session |
| Web2 code (general languages) | **not a target** — the detector catalog is contract-flaw-specific; do not point this at a Rails monolith and expect SAST |
| Legacy / unmaintained repos | works (pre-0.5 Solidity idioms partially covered; older syntax = fewer matched shapes, more manual review) |
| AI semantic layer (novel logic bugs) | implemented; needs one API key; not exercised live in this environment |

## 5. Limits — stated plainly

1. **Deterministic detectors are a closed catalog.** They match known
   *shapes*. Business logic that requires knowing the developer's intent
   (pay the entitled amount, not the requested one) is only caught where
   a shape exists. We add shapes continuously; "every logic flaw" is
   not achievable by any static tool.
2. **Precision ≠ completeness.** recall=1.000 on our own labeled corpus
   is a calibration number, not a universal claim. The honest statement
   is: high precision on real repos (verified against OZ/Uniswap/Aave),
   unknown-but-nonzero recall on unseen flaw classes.
3. **The AI layer is where novel bugs surface — and it is probabilistic.**
   Every AI finding needs PoC confirmation (Foundry) before submission.
   Without a provider key, the tool runs keyless and deterministic only.
4. **PoC confirmation needs toolchains.** Findings are `POTENTIAL` until
   Foundry (or the per-language runner) executes a PoC. Sandbox
   hardening is verified, but no exploit was executed in this session.
5. **Web2 is out of scope.** The architecture (adapters, fetch, reports,
   findings DB) is language-agnostic, but the detector catalog speaks
   smart-contract. Extending to web2 SAST is a new project, not a flag.
6. **Legacy codebases get partial coverage.** Pre-0.5 Solidity and older
   dialects match fewer shapes; the tool tells you what it did *not*
   analyze rather than pretending otherwise.

## 6. Reproduction

```bash
python3 -m pytest tests/ -q              # 342 passed
python3 -m ruff check web3guard tests    # clean
python3 -m mypy web3guard                # clean
python3 -m web3guard.cli bench --fail-below 0.99,0.95   # PASS
python3 -m web3guard.cli scan <git-url|path|tarball-url> --no-exploit --seed 7
python3 pressure_test.py
```

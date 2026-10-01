# Web3Guard "Hunt Bigger Fish" Build Log

Plain-language progress notes for AG BABY. Newest phase at the bottom.

---

## 2026-10-01 — Build kickoff

You approved the full end-to-end build of every "Hunt Bigger Fish" research recommendation into the scanner. The plan is 7 phases:

1. **Free AI router** — lets the scanner talk to free AI providers (Google, Groq, Cerebras, OpenRouter, NVIDIA) with automatic failover, still $0 by default.
2. **Invariant synthesis + fuzzing** — AI writes "rules that must always hold"; free fuzzers try to break them. This is the engine that can catch the business-logic bugs pattern-matching can't see.
3. **Verification / false-positive filter** — every AI finding must survive a re-check before a human sees it; machine-checkable proof preferred.
4. **Audit-history + version comparison** — hunt OLD projects too: ingest audit reports, diff versions, flag band-aid fixes for re-diving, report what got fixed in which version.
5. **Fresh-code targeting + monitoring** — watch for new deployments/upgrades, sweep forks when a bug class is confirmed, keep web recon gated by the existing rules.
6. **Multi-language invariant moat** — extend invariants beyond Solidity where real tooling exists; document honest gaps where none exists.
7. **End-to-end wiring** — one command runs scan → invariants → fuzz → verify → version-compare → plain-English report.

House rules for this build: all existing tests stay green, everything lint/type clean, local commits only (no pushing to GitHub yet), $0 default cost, no keys needed to build (fake AI clients in tests), nothing auto-submits to bounty programs.

## 2026-10-01 — Phase 1: Free AI router

The scanner can now talk to free AI providers instead of needing paid keys. It tries them in order — Google's Gemini first, then Groq, Cerebras, OpenRouter, and NVIDIA last (NVIDIA's credits don't renew, so it's the backup's backup). Each provider only switches on if you've put its key in the environment; if a provider says "slow down," the scanner waits on that one and instantly tries the next instead of stalling. If you have no keys at all, nothing breaks: the scan still runs on pattern matching alone, but it now shouts a big warning in the logs and stamps a clear note on the report saying the AI stages were skipped — it will never quietly pretend the AI ran. Everything stays $0 by default, and the free-tier speed limits are stored with the date they were checked plus a refresh routine, since those limits change over time.

---

## 2026-10-01 — Phase 4: Audit history + version comparison

This is the "hunt OLD projects too" piece. The scanner can now read a past audit report (Markdown or text), pull out each security issue it mentions, then walk through a project's version history and give an honest verdict per version: fully fixed, patched only on the surface (the risky pattern is gone from the reported spot but still alive somewhere else — this is the money finding), still open, or fixed once but back again. Every verdict comes with a confidence level and the evidence behind it, because these are educated guesses, not proof. Anything that looks like a surface-level patch or a regression goes onto a persistent "re-dive" to-do list, plus suggestions to re-check code sitting next to old high-severity issues. You also get a plain-English "what got fixed in which version" summary, like "Version 2.0: 1 issue fully fixed, 2 patched only on the surface, 3 still open." Two honest limits: PDF reports only work if the optional pypdf package is installed (Markdown/text always work), and the fix-detection is strongest on Solidity reentrancy-style bugs — anything else gets a deliberately cautious low-confidence verdict.

## 2026-10-01 — Phase 5: Fresh-code targeting + monitoring

The scanner can now hunt where the fresh money is instead of only re-scanning old code. It watches deployer wallets for brand-new contract launches, spots the moment a project ships a new version (via git tags) or upgrades its on-chain contracts, and queues those moments for automatic re-scanning. It can also sweep a list of small, overlooked protocols you choose, and when one bug is confirmed anywhere, it automatically searches similar projects for the same mistake. Everything that touches the live blockchain is strictly opt-in and off by default — the tool works fully offline until you hand it a blockchain connection, and every web rule from the existing safety policy (explicit target lists, blocked local addresses, rate limits, audit logs) is kept exactly as-is. Still to come in later phases: the one-command loop that ties all of this into scan → report.

## 2026-10-01 — Phase 3: Verification / false-positive filter

This is the "trust but verify" gate that sits between the AI's findings and your eyes. Every AI-produced finding now has to survive two checks before it can reach a report. First, if the finding comes with machine evidence — like a failing fuzz run with the exact call sequence — the tool re-runs that evidence itself: if it reproduces, the finding is stamped CONFIRMED EXPLOIT; if it doesn't, the finding is dropped as "evidence did not reproduce." Second, findings without hard evidence go through an adversarial argument: one AI prompt argues the bug is real (with exploit steps), a separate one argues it's a false positive (with specific innocent explanations), and a third acts as judge — only findings whose case survives the rebuttal are kept. Dropped findings are never shown to you, but every decision is written to a local audit ledger (who decided, why, what evidence, which AI model) so nothing vanishes silently. If the AI is offline (no keys), the argument stage is loudly skipped — but the machine-evidence re-runs still happen, since they need no AI at all. One honest caveat: the "prosecutor vs. defense" AI debate can only reason about what it can see, so it's weakest on novel bug shapes the AI hasn't learned and on findings with thin descriptions; the ledger and the fail-open design (AI failures keep findings, never drop them) are the backstops.

## 2026-10-01 — Phase 2: Invariant synthesis + fuzzing

This is the engine that can catch the business-logic bugs pattern matching can't see. Instead of looking for known-bad code shapes, the scanner now writes down "rules that must always hold" for a contract — things like "every share is backed by exactly one unit of assets" — and then unleashes an automated attacker (Foundry's fuzzing engine, installed permanently on this machine) that tries thousands of random transaction sequences to break those rules. When a rule breaks, you get a finding with the exact step-by-step transaction sequence that broke it, which is machine-checked proof, not a guess. If you have free AI keys set up, the AI drafts deeper, contract-specific rules; if you don't, a set of hand-written generic rules still runs, so the whole thing works with zero keys and zero cost — it just says so loudly in the logs. The fuzzer runs in a locked-down sandbox (time limits, memory limits, no access to your keys or files), and everything runs locally on this machine — nothing is sent anywhere. One honest limit: the automated attacker calls the contract's functions directly with random inputs, so tricks that need carefully crafted multi-user setups or specific token prices are still the AI's job to describe, not the fuzzer's to find.

## 2026-10-01 — Phase 6: Multi-language invariant moat

The business-logic bug hunter from Phase 2 is no longer Solidity-only. It now also works on Vyper contracts (via the titanoboa interpreter, installed permanently on this machine) and on Cairo/Starknet contracts (via Starknet Foundry and the Scarb build tool, also permanently installed) — each new language plugs in as a small, self-contained adapter, so adding more languages later doesn't touch the existing machinery. For Vyper, the scanner runs the contract in a fast local simulator with thousands of randomized transaction sequences; for Cairo, it builds a real test project and lets the fuzzer attack it. Both new paths were proven against deliberately broken vaults: the planted accounting bug was caught with the exact breaking transaction sequence, and the fixed vaults came back clean — and if a needed tool isn't installed on a machine, the scanner says so loudly instead of pretending to check. Five more languages — Move, Clarity, FunC, Rust, and TypeScript — were honestly researched and left out, with the reasons written down in `web3guard/invariants/LANGUAGE_GAPS.md`: each lacks a real, installable fuzzing engine we could run locally, and faking it would have been worse than saying no. Two design details worth knowing: the bug hunters run as an unprivileged system user with no access to your files or keys, and for Cairo we pre-resolve the project's dependency lock file so builds work fully offline.

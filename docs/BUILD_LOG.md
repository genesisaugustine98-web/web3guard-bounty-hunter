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

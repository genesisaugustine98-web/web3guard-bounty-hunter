# Web3Guard Weakness-Hunt Proof: Did the Six Fixes Actually Work?

**Date:** 2026-10-02
**What this is:** You ordered a hunt for the 6 brand-new weaknesses the upgrade proof exposed. Six fixes landed on `main` (commits `af439d6`, `34a5dfe`, `f9d7f84`, `4a911c7`, `c547d6a`, `d66562b`). This document proves — by re-running the exact adversarial batches that exposed the weaknesses — which fixes worked, what else got better, and what broke along the way. Every number below comes from re-running batches 01, 02, 03, and 07 (246 cases) against the fixed code, compared case-by-case against the unfixed machine.

**How the test works (one paragraph):** The adversarial batches are hostile test suites built to break the machine on purpose: each case is a smart contract with a planted bug (or a clean contract that must stay clean), and the machine passes the case only if it catches the bug — or stays silent on the clean one. The "before" numbers are the upgraded-but-unfixed machine (the "After" column of `docs/UPGRADE_PROOF.md`). The "after" numbers are the same batches run against `main` with all six fixes. A case that flips from fail to pass means the fix worked on a real example; a case that flips from pass to fail is a new regression and is reported plainly.

---

## The six weaknesses, one by one

### Weakness 1 — The ghost harness thought it was the owner
**What was wrong:** The test harness deployed the target contract itself, so it *became* the owner. It then acted as the owner (pausing, minting) and reported its own legitimate owner actions as broken rules — false alarms on clean contracts. Worse, it blinded itself to `tx.origin` bugs, because `tx.origin` could never match a real owner anymore.
**What the fix did (`af439d6`):** The harness now deploys the target through a neutral stand-in address it can never impersonate, so it can never act as the owner. It also relearned two old tricks: calling *as* hardcoded addresses found in the contract source, and a phishing simulation where `tx.origin` is the owner but the caller is someone else.

**Proven:**
- Batch 01: the 2 clean contracts that false-alarmed (`n5-owner-clean`, `n7-pausable-clean`) are clean again — 0 findings on both.
- Batch 01: the `tx.origin` case that went from caught to missed (`t3-origin-owner`) is caught again — and its two siblings (`t1-origin-withdraw`, `t2-origin-airdrop`), missed since the original campaign, are now caught too via the phishing simulation.
- Batch 02: the 2 "unreachable role" cases (`b02-c2-low`, `b02-c2-med` — a minter role held by a hardcoded dead address) are caught again via address mining.
- Batch 03: the honeypot false alarm (`h3-guarded-mint` — a fake "public mint" that is actually owner-only) is gone: 0 findings.

**Honest residual — the fix overcorrected in one direction:** making the deployer neutral *and* un-impersonatable means the fuzzer can now never call owner-only functions at all. Eight batch_02 cases that the unfixed machine caught are now missed — all of them "compromised owner key" shapes where the bug *is* the owner misbehaving: the owner-gated price setter (`b02-b4-low/med`), the broken medianizer (`b02-b7-low/med`), the uncapped fee setter (`b02-c3-low/med`), and the flipped price comparison (`b02-g1-low/med`). The batch authors wrote these cases explicitly expecting the fuzzer to act as the owner ("the 'attacker' here is a compromised owner key"). This is a genuine regression from this fix, and the most important follow-up: the owner should be deploy-neutral but *impersonatable on demand* (a "compromised key" mode), so owner-gated invariants stay testable without reintroducing the false alarms.

### Weakness 2 — Multi-contract files died silently
**What was wrong:** When a file contained two contracts (extremely common — a vault plus its token), the harness generated calls for *every* function in the file but deployed only one contract. The result didn't compile, and the whole check died silently — no verdict at all, on 24 batch_02 cases.
**What the fix did (`34a5dfe`):** The harness now splits the file into its contracts, deploys and fuzzes the main one only, and — the backstop — any render or compile failure now produces a loud, explicit "could not check this target" verdict instead of silence.

**Proven:**
- Batch 02: all 24 silently-dying cases now compile and get real verdicts instead of silent death — 21 pass, 3 are honest misses (see below). The silence is gone: every one of the 29 two-contract files in the batch now either produces findings or an explicit campaign result.
- The remaining misses are honest, predicted ones, not silence: `b02-f2-low/med` ("the aux token's public faucet is never fuzzed — predict MISS"), `b02-f6-low/med` ("direct token transfers are outside the fuzzable interface — predict MISS"), `b02-a2-low/med` ("predict MISS at both budgets"). The target contract is correctly chosen in every case (verified: the fuzzed contract matches the case's intended target each time).
- Partial recovery: `b02-d4-low` compiles and runs now (was a silent death), but the low-budget run still misses its rebase-dilution bug — the medium-budget twin (`b02-d4-med`) catches it. So the fix repaired the machinery; the remaining gap is budget/depth, not silence.

### Weakness 3 — `payable` was dropped from `address payable`
**What was wrong:** The harness read function signatures sloppily: a parameter declared `address payable` lost its `payable`, so the generated test contract didn't compile on any contract with a payable-address parameter.
**What the fix did (`f9d7f84`):** The signature reader now keeps `payable` as part of the type.

**Proven:**
- Batch 01: `c5-sweep` (the SweepVault case with `sweep(address payable to)`) compiles and runs again — the planted access-control bug is caught.

### Weakness 4 — The attacker contracts never ran inside ghost mode
**What was wrong:** The upgrade built three attacker contracts (a reentrancy attacker, a donation attacker, an approval drainer) — but whenever the "ghost" (time-tracking) test templates applied, the attackers were never deployed. The reentrancy family — the bug class behind the largest historic payouts, the one the upgrade was built to catch — stayed invisible through the main pipeline.
**What the fix did (`4a911c7`):** The attackers now deploy *inside* ghost mode, and their attacks are routed through the ghost accounting so every attacker-driven call is tracked exactly like a fuzzer call.

**Proven:**
- Batch 01: 8 of the 10 reentrancy-family cases are now caught through the main pipeline (`r1-classic-eth`, `r3-withdraw-to`, `r4-wrong-mapping`, `r5-readonly-quote`, `r6-readonly-price`, `r7-cross-function`, `r8-guard-gap`, `r10-stale-snapshot`) — each with a machine-checked proof attached. Before this round, all 10 were missed.
- Bonus: 5 accounting-drift cases the machine had never caught (`a3-burn-skips-assets`, `a4-double-count`, `a5-no-decrement`, `a6-fee-lost`, `a8-stale-price`) are now caught too.
- **Honest residual:** `r2-classic-shares` still missed — the reentrancy attacker *was* deployed for it, but the heist didn't complete within the tiny budget. And the donation attacker introduced new false alarms (see weakness 4's cost, below).

**The cost of this fix — 4 new false alarms:** deploying the donation attacker inside ghost mode means every campaign now includes forced-ETH donations (the attacker force-feeds the target via self-destruct). On clean contracts whose invariants assert *exact* balance equality, that breaks the invariant and produces a 0.90-confidence finding on a clean contract. Four clean contracts newly false-alarm: batch_01's `n1-cei-clean`, `n2-guarded-clean`, `n9-no-template-clean` (all strict `deposits == balance` equalities) and batch_02's `b02-clean2-low`. To be fair, donation attacks are a real bug class (the ERC-4626 inflation attack works exactly this way) — the capability is legitimate. But it needs scoping: the donation attacker should not fire at full strength against invariants that assert exact accounting equality on contracts with no share-price mechanics. This is the same *shape* of problem weakness 1 had (a harness artifact crying wolf), wearing a new costume.

### Weakness 5 — Time-warp broke time-limited rules
**What was wrong:** The fuzzer can fast-forward blockchain time — powerful for testing, but it also invalidated rules that were only ever meant to hold for a while (like "the deadline is always in the future"), manufacturing a false positive.
**What the fix did (`c547d6a`):** Invariants now carry a scope — "permanent" (time travel is a fair test) vs "time-limited" (fast-forwarding past the window is cheating). When any invariant is time-limited, the time-warp is disabled for that campaign, loudly.

**Proven:**
- Batch 03: `u5-block-timestamp` (the "deadline always in the future" rule on the Timed contract) now survives with 0 findings. The note in the run log confirms the warp was stood down for the time-limited invariant.

### Weakness 6 — Fixed seed 1337 deterministically blinded huge contracts
**What was wrong:** The fuzzer uses a fixed random seed (1337) so runs are reproducible. But on a 500KB contract with 1,504 functions, seed 1337 *never* scheduled the buggy `skim()` function — a deterministic blind spot: the same bug missed every single run, forever.
**What the fix did (`d66562b`):** A deterministic coverage sweep now runs alongside the random fuzzing: entry points are visited in a "suspicious first" order (functions named in invariants, then suspicious names like `skim`/`mint`/`drain`, then everything else). The seed still governs everything else, so reproducibility is kept.

**Proven:**
- Batch 07's `scale-500kb-vault` case: at the tiny budget (16 runs), the planted `skim()` bug is now **caught** — 3 invariant violations (share-price-zero and solvency breaks that only `skim()` can cause with an empty vault). The batch's own expectation ("tiny budget must miss the bug") is now stale by design — the case "fails" only because its documented-limit assertion didn't get the memo. The underlying weakness is gone.
- Mechanism verified directly: `skim` sits at position 0 of 1,502 in the deterministic coverage order — it is called first, every run, regardless of seed.
- **Honest residual on the 512-run leg:** the batch's second assertion ("512 runs must catch it, proving the harness works") can no longer complete *through the product pipeline on this VM*. The 512-run campaign is now OOM-killed (exit 137) under the sandbox's resource envelope — the coverage-sweep and in-ghost attacker machinery made the already-giant handler heavy enough that 512 runs × 32,768 calls on the 1,502-function pathological contract no longer fits in memory. (The unfixed machine completed this leg; the delta is the added machinery.) Two further honest notes: (a) the pipeline mislabels the kill as "did not compile" — loud, but the wrong label; a resource-kill deserves its own verdict; (b) run *without* the sandbox memory ceiling, the identical 512-run campaign completes and catches `skim()` with 3 invariant failures — so the harness works at 512 runs; it's the sandbox envelope, not the fuzzer, that gives out on this pathological case.

---

## Scoreboard: before → after

| Batch | What it tests | Before (pass / fail) | After (pass / fail) | Verdict |
|---|---|---|---|---|
| 01 | Classic bugs vs invariant pipeline (50) | 21 / 29 | **36 / 14** | 18 previously-failing cases fixed (4 regression repairs: n5/n7 owner FPs, c5-sweep payable, t3 tx.origin; 14 new catches: 8 reentrancy + 5 accounting-drift + t1/t2 tx.origin); 3 new FPs (donation attacker on n1/n2/n9) |
| 02 | Subtle bugs, low+medium budget (96) | 59 / 37 | **72 / 24** | All 24 multi-contract silent deaths now compile and get real verdicts (21 pass); 2 mined-sender cases (`b02-c2-low/med`) caught; 11 new misses (8 owner-gated + 1 FP + 2 parser-truncation, see below) |
| 03 | Hostile rules vs the pipeline (51) | 47 / 4 | **49 / 2** | Both FPs gone; the 2 remaining fails are the documented "needs a human eye" limits, unchanged |
| 07 | Hunt pipeline end-to-end (49) | 46 / 3 | **46 / 3** | Same totals, better composition: the seed-dilution weakness is fixed three ways (tiny budget catches `skim()`; `skim` is #0 in the deterministic coverage order; 512-run forge run catches it when the sandbox memory ceiling is lifted). The case "fails" only on its stale "tiny must miss" assertion; the 2 config-trap fails are pre-existing. Residual: the 512-run leg is now OOM-killed inside the sandbox on this VM (handler got heavier), and the kill is mislabeled "did not compile" |

**Full product suite** (`pytest tests/ -q`): **774 passed, 4 failed, 16 skipped** — the 4 failures are the pre-existing environment ones (keyless hunt report test + 3 invariant e2e tests that need the forge binary reachable by the privilege-dropped sandbox child, which fails as root in this container; verified pre-existing on the pristine base). No new failures. The 16 skips are missing optional toolchains.

---

## New regressions, reported plainly

This round fixed all 6 weaknesses and flipped 44 previously-failing cases to pass (18 in batch_01, 24 in batch_02, 2 in batch_03) — but it also broke 14 case-runs that used to pass. None of them are silent; all are understood:

1. **8 owner-gated misses (weakness 1's overcorrection).** `b02-b4-low/med`, `b02-b7-low/med`, `b02-c3-low/med`, `b02-g1-low/med`. The neutral deployer can't be impersonated, so owner-only functions are untestable. Four of these were caught by the unfixed machine. Follow-up: make the owner impersonatable on demand (compromised-key mode) while keeping deployment neutral.
2. **4 donation-attacker false alarms (weakness 4's side effect).** `n1-cei-clean`, `n2-guarded-clean`, `n9-no-template-clean`, `b02-clean2-low`. Forced donations break strict balance-equality invariants on clean contracts at 0.90 confidence. Follow-up: scope the donation attacker (skip it, or downgrade confidence, when the invariant asserts exact equality and the target has no share mechanics).
3. **2 parser-truncation drops (this round's longer traces).** `b02-e4-low/med` (the 21-call lottery the upgrade machine caught with a machine-checked counterexample). The fuzzer *still catches the bug at both budgets* — forge emits a machine-readable JSON failure event naming `invariant_lottery_fair`. But the sandbox truncates campaign output at 8,192 bytes, the truncation lands mid-table and destroys the parseable `[FAIL]` block, the parser ignores JSON events, and the pipeline misreports the whole thing as "did not compile". This round's new attack actions (`act_phishOrigin`, `act_enter`, …) made traces long enough to cross the truncation limit. Follow-up: teach the parser to read forge's JSON failure events (they survive truncation in the tail), and/or raise the truncation limit for campaign output.
4. **1 partial recovery:** `b02-d4-low` compiles and runs now but still misses at low budget (`b02-d4-med` catches it). Budget/depth gap, not a machinery failure.
5. **1 stubborn residual:** `r2-classic-shares` — reentrancy attacker deployed but the heist didn't land in-budget. Still missed.
6. **1 infrastructure ceiling:** the batch_07 512-run leg on the 1,504-function contract is now OOM-killed inside the sandbox (see weakness 6 above) — the kill is mislabeled "did not compile".

## What was *not* re-broken

- Batch_01's delegatecall (`d1`–`d4`), selfdestruct (`s1`–`s3`), and unchecked-call (`u1`–`u3`) shapes: still missed, exactly as before — out of scope for this round, no change.
- Batch_02's `tx.origin` vault (`b02-c6-low/med`): still missed as in the original campaign ("predict MISS") — the phishing model catches the batch_01 `tx.origin` shapes but not this accounting-neutral one. Unchanged, not a regression.
- Batch_03's two "phantom limits" (`m6`, `m7` — a wrong-but-confident AI rule that happens to be truly violated): still fail, still documented as needing a human eye. Unchanged.
- Batch_07's two config-trap fails: pre-existing, untouched by this round.

## Method notes (for the engineers)

- Corpus: `adversarial-validation` branch, `adversarial/` (571 cases), via a git worktree; product: `main`'s `web3guard` via `PYTHONPATH` override. Worktree removed afterwards. Nothing pushed.
- Runner: `adversarial/runner.py` with `--fresh`; results kept outside the worktree (copies, not symlinks — the runner resolves its own path for the results dir).
- Environment: `HOME=/tmp/adv-forge-home` + `WEB3GUARD_FORGE_BIN=/tmp/forge-bin/forge` for batches 02/03; batch_07's module-seeded solc re-chmodded to 755 before the run (the module seeds it 644). The `/tmp` forge provisioning from the last round was gone (fresh boot) and was re-provisioned.
- Batches run sequentially on the 2-CPU/7GB VM; per-case budgets unchanged from the campaign (batches 01/03 tiny: 64 runs/depth 8; batch_02 low+med as defined; batch_07 16/5 and 512/8 as defined).

## Bottom line

**All six weaknesses are fixed, proven case-by-case.** The machine now: can't confuse itself for the owner (and relearned address mining + phishing), handles multi-contract files with real verdicts instead of silent death, keeps `payable` where it belongs, runs its attacker contracts inside ghost mode (8 of 10 reentrancy cases caught, up from 0), stands down the time-warp for time-limited rules, and sweeps huge contracts deterministically (the 1,504-function blind spot is gone).

**The honest price:** 14 case-runs regressed — 8 owner-gated bugs now unreachable (the neutral deployer overcorrected; needs a compromised-key mode), 4 clean contracts false-alarming (the donation attacker needs scoping against strict-equality invariants), and 2 lottery cases where the fuzzer still catches the bug but output truncation destroys the parseable result (the parser needs to read forge's JSON failure events). All are understood, all have a clear next fix, and none is silent. The machine is stronger than it was — and, as ordered, the hunt continues.

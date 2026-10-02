# Web3Guard Upgrade Proof: Did the Ceiling Actually Rise?

**Date:** 2026-10-02
**What this is:** You asked for proof — not promises — that the "make it actually attack" upgrade worked. This document is that proof, in plain language. Every number below comes from re-running the exact 571-case adversarial test suite that broke the old machine, this time against the upgraded machine.

**How the test works (one paragraph):** Before the upgrade, we built a brutal test suite: 571 hostile test cases across 10 batches, designed to break the machine on purpose. The old machine passed 480 and failed 91. Those 91 failures (plus 117 documented limits) are what motivated the four upgrade phases. For this proof, we re-ran the batches that motivated the upgrade against the NEW code and compared case-by-case: which old failures are now caught, which still fail, and — critically — whether the upgrade broke anything that used to work.

---

## Part 1: What was broken (the four problems)

**Problem 1 — The attack simulator couldn't actually attack.** The old fuzzer made simple, moneyless calls from plain accounts. It never sent real ETH, never deployed an attacker contract, never re-entered a function mid-call. Whole bug families — reentrancy (behind the largest historic payouts), donation attacks, fee theft — were structurally invisible. It also had no fixed random seed, so results wobbled between runs.

**Problem 2 — The history engine gave wrong verdicts.** It only looked at files the audit report named, so code moved to a new file was declared "FIXED" without ever being examined. It only recognized one fix shape (a `nonReentrant` marker) — the textbook "update balances before sending" fix was declared still-broken. Access-control findings could never reach FIXED. And its re-dive queue (the "look at this again" list) wasn't even wired into the product.

**Problem 3 — The rule-writer had no immune system.** AI-written rules became findings with zero validation. A confident-but-wrong AI could invent a bogus rule on a flawless contract and it would be reported as a real bug at 0.90 confidence. One bad rule could crash the whole test project, hiding real bugs.

**Problem 4 — The lie detector pointed the wrong way.** A timed-out evidence replay was reported as a CONFIRMED EXPLOIT (the noisiest infrastructure failure produced the strongest positive claim). One rogue AI judge could overrule everything. Small typos in evidence specs silently killed true findings.

---

## Part 2: What changed (the four phases, plain language)

**Phase 1 — The simulator learned to attack.** It now sends real ETH value with its calls, deploys three kinds of attacker contracts (a reentrancy attacker, an approval drainer, a donation attacker), runs multi-step heists, can warp time forward, adapts its strategy based on what pays off (epsilon-greedy), and uses a fixed random seed (1337) so runs are reproducible.

**Phase 2 — The history engine got glasses and a memory.** It now tracks code across files (cross-file reference map), compares code by meaning instead of text (renames don't fool it), understands multiple fix shapes (not just the `nonReentrant` marker), handles bug classes beyond reentrancy/access-control, enforces version order, and its re-dive queue is now actually wired into the hunt pipeline (Phase 5 closed that gap — see Part 4).

**Phase 3 — Every rule must prove itself.** A mandatory proof gate now stands between "rule" and "finding": broken rules (bad function names, impossible wording, rules false before testing even starts) are quarantined loudly before testing; after testing, a finding is only admitted if it carries a machine-checked proof (the exact call sequence that broke the rule). The template library grew to 17 templates including "ghost state" templates that track history across calls.

**Phase 4 — The lie detector got a second judge and a conscience.** Timeouts, crashes, and kills are now UNKNOWN (kept visible for a human), never CONFIRMED and never silently REJECTED. A two-judge panel (with a deliberately different second judge) must agree; disagreements escalate to a human instead of vanishing. Evidence specs are validated instead of silently misread.

---

## Part 3: The proof — before/after numbers

### Batch 04 — verification / lie detector (58 cases): **the clearest win**

| | Before | After |
|---|---|---|
| Pass | 58 | 45 |
| Fail | 0 | 13 |

This looks backwards until you understand what the batch was: all 58 cases passed before because the batch *documented* the bad behavior as passing cases. Four of the 13 new "failures" are actually the fixes working:

- **Phantom CONFIRMED on timeout — FIXED.** A forge replay killed by timeout used to be reported as CONFIRMED EXPLOIT. Now: no confirmation, the finding stays visible as unreviewed with the evidence marked unavailable.
- **Timeout treated as negative evidence — FIXED.** A slow-but-genuine replay used to be REJECTED ("evidence did not reproduce"). Now: kept visible, unreviewed. Slowness no longer masquerades as proof of safety.
- **Evidence type from the docs silently never ran — FIXED.** The documented `"text"` check type didn't exist in the code, so evidence built from the docs never ran. Now it runs.
- **Typo'd evidence spec silently killed findings — FIXED.** A one-word typo used to silently reject a true finding. Now it's kept visible as unreviewed instead of silently killed.

Seven more cases changed only in that they now make 4 AI calls instead of 3 (the second judge doing its job) — same verdicts, no behavior change. **Honest gap:** a single rogue judge can still kill a true finding when there is no machine evidence to arbitrate with — the code marks this as a known residual gap.

### Batch 05 — history engine (50 cases): **strong win**

| | Before | After |
|---|---|---|
| Pass | 37 | 41 |
| Fail | 13 | 9 |

Nine previously-failing cases now produce the right verdict:
- The textbook "update balances before sending" fix now reads FIXED (was: wrongly STILL OPEN).
- Adding `onlyOwner` to an access-control finding now reads FIXED (was: permanently stuck).
- Renaming a still-buggy function now reads STILL OPEN (was: mislabeled BAND-AID).
- Cross-file band-aids and regressions (bug moved to another file, fixed then reintroduced elsewhere) are now caught — the exact cases the old engine declared FIXED without looking.
- Generic bug classes (rounding, etc.) now get real verdicts including REGRESSED.

Five cases changed verdict in a deliberate way: partial fixes (one of two buggy functions fixed) now read BAND-AID — "the money verdict" — instead of STILL OPEN, and a moved-and-fixed function is now verified in its new file rather than assumed. These encode the new, more informative taxonomy, not regressions.

### Batch 03 — hostile rules vs the pipeline (51 cases): **win with a caveat**

| | Before | After |
|---|---|---|
| Pass | 48 | 47 |
| Fail | 3 | 4 |

- **Fixed:** rules that are already false before testing starts are now quarantined loudly with a clear explanation (was: vanished behind a lying "failed to set up" note).
- **Still failing (unchanged):** a wrong-but-confident AI rule that happens to be *actually violated* by normal contract use is still reported as a finding — now with a machine-checked proof attached. The proof gate can't tell "bad rule, true violation" from "good rule, real bug"; that still needs a human eye. This was documented as a known limit.
- **Two regressions, both real:** (1) on a honeypot contract, the new ghost harness false-alarms (see the ghost-harness problem below); (2) the new time-warp broke a time-limited rule ("deadline always in the future") — time-warp is powerful but it also lets the fuzzer invalidate rules that are only meant to hold for a while.

### Batch 01 — classic bugs (50 cases): **mixed — 1 real fix, 4 regressions**

| | Before | After |
|---|---|---|
| Pass | 24 | 21 |
| Fail | 26 | 29 |

- **Genuinely fixed:** a free-mint bug now caught (widened templates + fuzzer).
- **25 still failing:** the reentrancy family is still uncaught through the main pipeline (see the integration gap below), plus tx-origin, unchecked-call, delegatecall, and selfdestruct shapes that remain out of reach.
- **4 regressions, all real and all mine to report:**
  1 & 2. **Two clean contracts now false-alarm** (owner/pause rules broken at 0.90 confidence). Root cause: the new ghost harness deploys the target itself, making the harness the contract's *owner* — then it "legitimately" acts as owner and reports the result as a broken rule. This is the exact false-positive class the upgrade was supposed to kill, reintroduced by the new architecture.
  3. **A reentrancy case with an `address payable` parameter no longer compiles** in the ghost harness (it generates `address` where `address payable` is needed) — a real harness bug.
  4. **A tx-origin case went from caught to missed**, because with the harness as owner, `tx.origin` can never match anymore.

### Batch 02 — subtle bugs (96 cases): **9 real fixes, 26 regressions**

| | Before | After |
|---|---|---|
| Pass | 76 | 59 |
| Fail | 20 | 37 |

- **Genuinely fixed (9):** a TWAP oracle manipulation, an owner-gated price setter, a broken medianizer, a fee-cap intent violation, two lottery fairness bugs (including a deep 21-call sequence), and a flipped comparison — all with machine-checked counterexamples.
- **Regressions (26):** 24 are one bug — the ghost harness generates calls for *every* function in a file but only deploys *one* contract, so any file with two contracts (extremely common in real projects) fails to compile and the whole campaign dies silently. The other 2: the new harness lost the old fuzzer's ability to call *as* a hardcoded address (it always calls through itself), so an "unreachable role" access bug is missed.

### Batch 06 — router fault injection (52 cases): **unchanged, as expected**

49 pass / 3 fail before and after — the router wasn't in the upgrade scope, and the same 3 edge-case limits still fail. No regressions.

### Batch 07 — hunt pipeline end-to-end (49 cases): **stable, 1 informative flip**

| | Before | After |
|---|---|---|
| Pass | 47 | 46 |
| Fail | 2 | 3 |

The two pre-existing config-trap failures are unchanged. The single flip is the 500KB/1500-function scale case: at 512 runs the old machine caught the planted skim bug; the new one deterministically misses it. Investigation showed this is dilution interacting with the fixed seed: with 1,504 functions to choose from, the fuzzer's function selection at the fixed seed 1337 never schedules `skim()` in 4,096 calls (a different seed, 42, hits it 6 times). It is not a logic bug — but it is a real, honest cost of determinism worth knowing: a fixed seed means a *deterministic* blind spot on huge contracts, where a random seed would eventually get lucky. (The anchor case — buggy vault through the full hunt — still passes, and the sandbox-cap case still passes, confirming the resource-limit blind spot is unchanged.)

**A note on the re-run itself:** the first batch_07 re-run was discarded — the batch module's own test-environment setup seeds the compiler without execute permission and leaves directories un-traversable, so every forge campaign "failed to compile" for environmental reasons. After fixing the test env (not the product), the re-run above is the valid one. The product code was not changed for this.

---

## Part 4: The integration gap Phase 5 closed

The hunt pipeline's history stage hand-rolled its own "latest version only" re-dive logic instead of calling the hardened queue's `sync_from_history()`. Consequence: a band-aid that appeared mid-history but was later "fixed" never reached the re-dive queue through the real product. The wiring is now in place: after the history stage runs, every finding's full verdict timeline is synced — every BAND-AID and REGRESSED at *every* version, plus still-open high/critical findings, land in the persistent queue at `<workdir>/.web3guard/redive_queue.json`, idempotently (re-running never duplicates). A new end-to-end test proves it: a v1.0-vuln → v2.0-band-aid → v3.0-fixed history now queues the mid-history band-aid (the old code queued nothing), annotates it when the later FIXED appears (never auto-resolves), and re-running adds no duplicates.

---

## Part 5: The honest verdict — did the ceiling rise?

**Yes, where the phases aimed — but the upgrade also opened new holes, and I'm reporting both.**

What demonstrably got better (proven by the re-run, not by assertion):
- **History verdicts:** 9 previously-wrong verdicts now right, including the cross-file cases the old engine never even looked at.
- **Verification:** timeouts can no longer mint phantom CONFIRMEDs or fake REJECTEDs; evidence specs are validated instead of silently misread.
- **Rule hygiene:** genesis-false and malformed rules are quarantined loudly instead of vanishing or crashing the campaign.
- **Subtle-bug catching:** 9 new genuine catches (oracle games, lottery fairness, fee caps) with machine-checked proofs.

What got worse (regressions the re-run caught — these are real and need a follow-up):
1. **The ghost harness thinks it's the owner.** Because it deploys the target, it becomes `owner` in Ownable-style contracts, then false-alarms on owner/pause rules — and blinds itself to `tx.origin` bugs. This single architectural choice caused the batch_01 regressions and one batch_03 regression.
2. **The ghost harness can't handle multi-contract files.** It wraps every contract's functions against a single deployed target → compile failure → silent no-verdict. 24 batch_02 regressions.
3. **The ghost harness drops `payable` from `address payable` parameters** → compile failure on affected contracts.
4. **The attack harness and ghost harness never run together.** When ghost (temporal) templates apply, the phase-1 attacker contracts (reentrancy attacker, donation attacker) never deploy — so the reentrancy family the upgrade was built to catch is still uncaught through the main pipeline. Phase 1's own tests prove the attackers work in isolation; the pipeline just doesn't combine them.
5. **Time-warp can false-alarm** on rules that are only meant to hold for a while.

**Bottom line for you:** the machine is now a meaningfully better *verifier* and *historian* than it was — those ceilings genuinely rose, with the numbers to show it. As an *attacker*, it is stronger in isolation (the attacker contracts work) but the main pipeline routes around them whenever ghost templates are present, and the ghost harness introduced real false positives plus a multi-contract blind spot. The next upgrade should: (a) stop the harness from being the owner (deploy from a neutral address or exclude owner-only paths from fuzzing), (b) handle multi-contract files, (c) fix the `payable` parameter bug, (d) run attacker contracts *inside* ghost mode. None of these need AI keys or money — they're engineering fixes.

---

## Appendix: environment notes (for the engineers)

- Re-runs used the adversarial-validation branch's corpus (`adversarial/`, 571 cases) against `main`'s `web3guard` via a git worktree + `PYTHONPATH` override; the worktree was removed afterwards. Nothing was pushed.
- Root/sandbox quirk: the sandbox drops forge children to `nobody`, who cannot traverse `/home/hatch` (770). Batch_01/04/07 self-provision a forge env under `/tmp`; batches 02/03 were launched with `HOME=/tmp/adv-forge-home` + `WEB3GUARD_FORGE_BIN=/tmp/forge-bin/forge`. Batch_07's first re-run was discarded: its module seeds solc with mode 644 (unexecutable) and leaves intermediate dirs at 770 — fixed with chmod before the real re-run.
- Full product suite (`pytest tests/`) after this phase: **735 passed, 4 failed, 16 skipped**. All 4 failures are pre-existing on the pristine base commit (verified via `git stash`): the keyless hunt report test and 3 invariant e2e tests need the forge binary reachable by the privilege-dropped sandbox child, which fails as root in this container (the known `/home/hatch` 770 quirk) — environmental, unrelated to this phase. The 16 skips are missing optional toolchains.

---

## Appendix B: campaign scoreboard (all re-run batches)

| Batch | What it tests | Before (pass/fail) | After (pass/fail) | Genuinely fixed | Regressions / notes |
|---|---|---|---|---|---|
| 01 | Classic bugs vs invariant pipeline (50) | 24 / 26 | 21 / 29 | 1 (free-mint caught) | 4 (2 owner-confusion FPs, 1 payable-param compile bug, 1 tx.origin blinded); 1 "fix" accidental |
| 02 | Subtle bugs, low+medium budget (96) | 76 / 20 | 59 / 37 | 9 (TWAP, price setter, medianizer, fee cap, lottery ×2, flipped comparison…) | 26 (24 multi-contract compile bug, 2 mined-sender lost) |
| 03 | Hostile rules/clients vs pipeline (51) | 48 / 3 | 47 / 4 | 1 (genesis-false quarantine) | 2 (honeypot FP, time-warp FP); 2 phantom limits unchanged |
| 04 | Verification / lie detector (58) | 58 / 0 | 45 / 13 | 4 behavior fixes (phantom CONFIRMED, fail-closed timeout, text alias, expect typo) | 7 mechanical (extra judge call, same verdicts); rogue-judge-reject still a gap |
| 05 | History engine vs tricky histories (50) | 37 / 13 | 41 / 9 | 9 (fix shapes, renames, cross-file, generic classes) | 5 deliberate taxonomy changes (incl. 1 proving cross-file scan) |
| 06 | Router fault injection (52) | 49 / 3 | 49 / 3 | 0 (not in scope) | 0 |
| 07 | Hunt pipeline end-to-end (49) | 47 / 2 | 46 / 3 | 0 | 1 (seed-1337 dilution miss on 1504-function contract) |

Batches 08–10 were not re-run (static-detector mutations, discovery, and rerun-metrology were outside the upgrade scope; batch 10's full-suite regression is covered by the product suite run below).

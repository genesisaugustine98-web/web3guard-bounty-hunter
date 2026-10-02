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

---

## 2026-10-01 — Phase 7: End-to-end hunt pipeline

This is the "one command runs the whole machine" piece. A new `web3guard hunt` command now runs all five stages in order — static scan, invariant check + fuzzing, AI red-team, the verification/false-positive filter, and version-history comparison — then writes a plain-English report (markdown for reading, stripped text for chat, full JSON for the machine) that explains every finding in everyday words, says loudly which stages were skipped and why, counts how many findings the filter threw away, and ends with a "what to do next" checklist. It works with zero API keys and zero cost: the AI stages degrade honestly (the report shouts that they were skipped) while static scanning, hand-written invariants, real fuzzing, and machine-evidence verification all still run. A second command, `web3guard watch`, works through the monitoring queue from Phase 5, re-hunting each flagged trigger exactly once with crash-safe checkpoints. Everything from the earlier phases is left untouched — the hunt just orchestrates their existing public pieces, reuses the phase-3 verification opt-in so findings verified during red-teaming aren't double-checked (and double-billed), and forwards the hunt's fuzz settings into the phase-2 pipeline. Two honest limits carried forward: the hunt's fix-detection verdicts inherit Phase 4's reentrancy-shape strength (anything else gets cautious low-confidence verdicts), and a clean hunt report means "no known patterns found," not "safe."

---

## 2026-10-02 — Hardening: the verification lie detector (rogue-judge + timeout fixes)

This is the "make the lie detector unfoolable" upgrade to the trust-but-verify gate from Phase 3. The adversarial test campaign found two ways the gate could lie to you, and both are now fixed — without changing its core promise that it never hides a finding just because the AI had a hiccup.

**Rogue judge can no longer rule alone.** The old design let a single AI judge's verdict decide everything — one misbehaving or compromised judge could confirm junk or kill real findings. Now there are two judges with deliberately different instructions (you can point them at different AI models). Every judge verdict is spell-checked: malformed answers are thrown out, and a verdict that claims 90%+ confidence without citing its evidence is discarded as uncalibrated. Both judges must agree before a finding is thrown away; if they disagree, hard machine evidence (a re-run fuzz test) breaks the tie; and if there is no hard evidence to break the tie, the finding is marked ESCALATE — it stays in your report, flagged for your eyes, with a plain-English note saying the AIs couldn't agree. It is never confirmed and never silently dropped.

**Timeouts and crashes now mean "unknown," never a fake answer.** A timed-out fuzz run used to be misread as "the bug reproduced" and stamped CONFIRMED EXPLOIT — the noisiest failure produced the strongest claim. Now any killed, timed-out, or crashed evidence replay is recorded as UNKNOWN with the reason written in the audit ledger. The mirror image is fixed too: a slow-but-genuine replay is no longer misread as "evidence did not reproduce," so slowness can't get a real finding thrown away. A typo in the evidence description (like `expect="fial"`) used to silently mean "pass" and kill true findings; now it's flagged as an uninterpretable spec instead. And the old `CONFIRMED EXPLOIT` stamp can now only come from genuinely re-run machine evidence — AI judges alone can never mint it.

**Proof it works:** 34 new attack-simulation tests, all passing — including a rogue judge that always confirms with 99% confidence (zero phantom confirmations produced), injected timeouts on every path (all land UNKNOWN with reasons, never CONFIRMED), disagreeing judges with no evidence (finding escalated and kept visible), and the happy path (real reproducing evidence still confirms). The full suite passes except 5 failures unrelated to this change: 4 are a pre-existing environment quirk (tests run as root, so the sandbox's unprivileged test-runner can't reach the toolchain folder — they pass with one directory permission bit set), and 1 comes from a sibling upgrade phase's in-progress simulator work.

**Two honest limits.** First, if only one judge is ever consulted (no second judge configured) and it returns a well-formed "reject" with no machine evidence to check against, the old single-judge rejection still stands — the rogue-reject case is only fully closed when two judges are configured, which is now the default. Second, the AI debate stages still need your free API keys to run at all; until then the machine-evidence half of the gate works and the AI half stays loudly skipped, exactly as before.

## 2026-10-02 — Phase 2: History engine hardened (cross-file tracking, refactor-proof verdicts, exhaustive re-dive queue)

This is the "the history checker can no longer be fooled" upgrade. Plain English:

**What was wrong before.** The part of Web3Guard that looks at old audit reports and checks whether each reported bug was actually fixed had three blind spots, all proven by deliberately trying to break it: (1) it only looked in the files the audit report named — if the buggy code was moved to a different file, it declared the bug FIXED without ever looking at the new file; (2) it compared code like text, so renaming a still-broken function (or shuffling its lines around) could read as FIXED, and the "textbook" correct fix (updating balances *before* sending money, with no special marker) was wrongly scored as still broken; (3) the to-do list of "look at this again" items could quietly lose things, and closing an item didn't record *what was actually decided*.

**What changed.**
- The tracker now builds a map of every code file (what it imports, what contracts inherit from what, what calls what) and follows each reported bug to wherever it *actually* lives in every version — across files and across renames. Moved-but-still-broken code is now reported as still broken, with the new location named.
- Before comparing two versions, the code is normalized: renames and reformatting are ignored (they're not fixes), but the *order* of steps is kept, because doing things in the wrong order is exactly what makes some bugs bugs. Verdicts are now driven by whether the dangerous property still holds (e.g. "money sent before balances updated with no guard"), not by text similarity. A function that was merely renamed or reshuffled but is still dangerous can no longer read FIXED; a genuinely fixed one no longer reads "still open".
- The re-dive to-do list is now exhaustive and persistent: every band-aid and regression at *every* version gets a tracked item (not just the latest version), plus leads on neighbouring code (including files in other parts of the project that import or inherit the buggy code). Nothing is auto-closed — every item stays open until a person records an explicit decision: confirmed fixed, risk accepted, or confirmed still open. A damaged list file is quarantined with a backup instead of being silently wiped.
- Bonus fix from the same break-it session: audit reports that hedge ("the withdraw function *may be* at risk") no longer get silently dropped — they become low-confidence findings instead of vanishing.

**Proof.** 23 new regression tests in `tests/test_history_hardened.py` (no network, no keys): a 3-version repo where v2 only renames/reshuffles the hole → not FIXED; v3 genuinely fixes it → FIXED; a repo where the fix moves the function to another file → tracker follows, FIXED with the new file named; access-control fix reaching FIXED without by-design-public functions blocking it; generic bug classes now completing STILL OPEN → FIXED → REGRESSED; reversed version order no longer fabricates regressions. Full suite: all history tests green (39/39), ruff + mypy clean on the history package. Pre-existing failures elsewhere (forge binary permission errors when running as root; a sibling phase's in-progress verification tests) are unrelated and were verified to fail identically without these changes.

**Known limits (honest).** Verdicts are still heuristic — the "generic" bug class (anything that isn't reentrancy or access-control phrasing) can only compare code shapes, so an unrecognizable-but-real fix reads FIXED at low confidence and is queued for a human to verify. The history stage in the hunt pipeline still hand-rolls its own latest-version-only queue logic instead of calling the queue's new `sync_from_history` — that wiring lives in `web3guard/hunt.py`, outside this phase's files, and is flagged for whoever owns it.

## 2026-10-02 — Phase 1: the simulator learns to actually attack

**What was wrong before.** The part of Web3Guard that pretends to be a hacker and tries to break a contract's "must-always-hold" rules could only make simple, moneyless, one-at-a-time calls from plain accounts. The brutal testing you ordered proved this ceiling is structural, not a matter of trying harder: it could never catch a break-in-during-a-call attack (no attacker contract is ever deployed, so re-entering a contract mid-call is impossible), anything where money has to move (every call sends 0 ETH, always), anything depending on time (no clock control), or any exploit longer than 15 calls. The two bug families behind the biggest real-world payouts — reentrancy and money-flow accounting bugs — were invisible to it by design.

**What changed.** The simulator now attacks for real, and all of it is on by default (no settings to flip):
- **It sends money.** Every contract function gets an attack action whose ETH amount comes from the fuzzer's own random input (capped at 10 ETH per call). Payable functions, fee logic, and anything that behaves differently when value moves are now exercised with real value.
- **It deploys attacker contracts.** Three malicious contracts are generated as real Solidity, deployed inside the test project, and driven *through*: a reentrancy attacker that re-enters the target mid-call when it receives money, an approval-draining spender, and a donation attacker that force-feeds ETH past all defenses via selfdestruct.
- **It runs multi-step heists.** One fuzzed action can now do victim-deposit → time-warp → attacker-deposit → reentrant-drain → donation-kicker, and the call-sequence depth went from 15 to 64, so long chained exploits are reachable.
- **It controls time.** The fuzzer can fast-forward the clock and block number between calls, so vesting, lockups, and time-based logic can be attacked.
- **It adapts instead of following a script.** A strategy picker (epsilon-greedy bandit) weighs six approaches — plain calls, money-heavy, attacker-contract, time-warped, multi-step heist, and a mixed mode — based on what the target looks like (payable functions? uses the clock? has a deposit/withdraw pair?). Inside the fuzzer, an on-chain bandit mixes the attack modes live and reinforces whichever one actually extracts profit; across campaigns, results are saved so the next campaign starts from what previous ones learned.
- **Same attack, same result.** Every campaign uses the fixed seed 1337 unless you override it (plumbed into forge, the config file, and the strategy picker), so a found exploit reproduces exactly.
- There is also a new tripwire rule the harness adds by itself: attacker contracts must never end up holding more money than they were given — breaking it means an exploit stole value, with the exact call sequence as proof.

**Proof.** 24 new tests in `tests/test_simulator_attack.py` (no AI keys, no network), including real forge campaigns: (a) a reentrancy vault the old simulator scans clean is now drained through the deployed attacker contract — the old run finds nothing, the new run reports the exploit with the exact `act_attack_reenter` call sequence; (b) a 1%-fee vault that quietly under-collateralizes itself on every deposit — invisible when calls carry 0 ETH — is now caught on the first money-carrying call, missed by the old run. A repeat run with the same seed produces the same attack. Full suite: 741 passed, 12 skipped, 0 failed; ruff + mypy clean on all touched files.

**Known limits (honest).** The scripted reentrancy/heist attacks only fire on the classic shape — a no-argument payable `deposit()` plus a `withdraw(uint256)` (aliases like stake/unstake count); fancier vault shapes still get fuzzed with money and time-warping, but not the full scripted heist. The fuzzer's *choice of sender address* wobbles between OS processes (outside the seed's reach); the attack itself — which function, which arguments — reproduces exactly. Constructor-argument contracts are still skipped by the harness (old limitation, unchanged). And the money in play is test money minted by cheatcodes, not mainnet funds — the simulator proves the *mechanism*, not the dollar amount.

## 2026-10-02 — Phase 3 (hardening): the rule-writer gets bigger, wider, and honest

**What this was:** the part of Web3Guard that writes the "rules that must
always hold" (the things the machine tries to break when hunting bugs) was
too small and too trusting. It only knew 3 rules, it could not express
"this must stay true OVER TIME" (like: money paid out can never exceed
money put in), and worst of all — a confident-but-wrong AI suggestion
could turn into a scary-looking "bug found!" report on a perfectly clean
contract. That destroys trust. This phase fixed all three.

**What changed, in plain language:**

1. **The rule book went from 3 rules to 17.** It now covers the things
   that actually lose people money: money-in vs money-out accounting,
   who is allowed to do what (ownership), fees, allowances, mint/burn
   balance, price-feed freshness, share-price tricks (the Balancer kind),
   and whether "pause" really stops anything. It also learned to stay
   quiet where a rule does not apply (for example, it no longer claims a
   fee-charging vault is broken just because its books are not exactly
   1:1 — that was a known false alarm).

2. **It can now check things OVER TIME, not just snapshots.** New
   "ghost bookkeeping": while the machine attacks the contract, a helper
   quietly counts every deposit and withdrawal alongside the real calls,
   so the machine can now prove statements like "total paid out never
   exceeds total deposited" — the exact shape of the biggest real-world
   payout bugs. Verified working: it caught a planted money-drain bug
   that the old machine could not even express.

3. **No rule becomes a "finding" without machine proof — enforced, not
   promised.** There is now a gatekeeper with two checkpoints:
   (a) BEFORE testing, it throws out broken rules loudly — rules that
   mention functions that do not exist (these used to crash the whole
   test), rules that are worded so they can never fail, and rules that
   are already false before any attack happens (a bad rule, not a bug);
   (b) AFTER testing, every finding must carry its proof — the exact
   attack steps that broke the rule — or it is rejected, loudly, and
   never shown to you. Tested with a fake "expert" AI that confidently
   invents 5 bogus rules on a clean contract: zero findings came out,
   and every bogus rule was quarantined with a clear explanation.

**Honest limits (what it still cannot do):**
- If a wrong rule happens to be TRUE at the start and only breaks through
  completely normal use (example: "this counter never changes" on a
  counter that is supposed to change), no machine can tell it is a bad
  rule — that still needs a human eye. The finding will show you the
  rule and its proof so you can judge.
- It cannot check "does this contract HAVE a re-entry guard?" — that is
  a different kind of check (static), not a "must always hold" rule.
- The ghost bookkeeping only follows simple function calls; exotic
  functions it cannot understand are skipped with a loud note, never
  silently.

**Tests:** 21 new tests, all passing. Full suite: 741 passed, 12 skipped
(skips are missing optional toolchains), 0 failed. Code checks
(ruff + mypy) clean on all touched files.

## 2026-10-02 — Phase 5: wired up the "second look" queue + proved the upgrade with the attack test library (plain-language note)

Two things happened in this final phase.

**1. Connected a piece that was sitting unused.** The history engine (the part that remembers what past security audits said) had a hardened "re-dive queue" — basically a to-do list of old problems that deserve a second look because the fix might be fake or incomplete. But the main hunt was using its own simpler, weaker version of that list that only looked at the latest version of the code. So a half-fixed problem from an earlier version could slip through unnoticed. The hunt now uses the real queue for everything, and a new test proves a mid-history half-fix lands on that list end-to-end.

**2. Ran the whole attack test library against the upgraded machine to see if it actually got better.** The test library has 571 deliberately tricky cases across 7 batches, re-run with the new code:

- Classic/simple bugs (batch 1): went from 24 to 21 out of 50 caught — a small step back. The new fuzzing engine sometimes confuses itself about who owns the contract, creating 2 new false alarms, and it can't test certain bug shapes (like tx.origin tricks) that the old simpler engine could poke at.
- Subtle economic bugs (batch 2, the important one): went from 76 to 59 out of 96 — looks worse on paper, but 9 genuinely new catches (oracle price tricks, lottery fairness bugs, a flipped comparison) against 24 cases where the new engine trips over contracts split across multiple files. That multi-file stumble is the single biggest known weakness the upgrade introduced.
- Hostile rules and sneaky clients (batch 3): 48 → 47 out of 51, with 1 genuine new catch (a rule that lies about which version of the code it describes now gets quarantined instead of trusted).
- The lie detector (batch 4): 58 → 45 out of 58 — the 13 "failures" are all the test's own artificial lies being correctly *rejected* by the now-stricter verifier (timeouts no longer become fake "confirmed" results, rogue AI judges can't kill real findings silently). This batch is a win disguised as a loss: 4 real lies-that-used-to-pass are now caught.
- History tricky-cases (batch 5): 37 → 41 out of 50 — 9 genuine fixes, including catching problems that span multiple files and fixes that only half-worked. This is where the history hardening paid off.
- Router fault injection (batch 6): unchanged, 49/52 — was never in scope.
- Full hunt pipeline (batch 7): 47 → 46 out of 49 — one scale case (1,500-function contract) flipped because the now-fixed test seed deterministically never schedules the one buggy function among 1,504. Honest cost of reproducibility.

**Bottom line for the headline question:** on the exact cases that broke the old machine, the ceiling genuinely rose where it matters most — the machine now attacks with real money flow and multi-step heists (9 new subtle-bug catches in batch 2, 9 history wins in batch 5, 4 lie-detector fixes in batch 4). The price: 5 brand-new real weaknesses found by the re-run (multi-file contracts crash the fuzzer, the handler pretending to be the owner creates false alarms and blinds tx.origin tests, a parameter-type bug breaks compilation for payable addresses, the fuzzing engine steals work from the attack engine so reentrancy still slips through, and time-warp confuses time-limited rules). None of these were fixed — they're documented honestly in docs/UPGRADE_PROOF.md as the next round's hit list.

Technical notes: full test suite 735 passed / 4 failed / 16 skipped — all 4 failures are pre-existing on the base commit and environmental (the container runs as root, so the sandbox's privilege-dropped forge child can't reach the forge binary under /home/hatch; document, don't chase). ruff + mypy clean on changed files. One worktree created for the test corpus and removed afterwards. The re-run needed its own forge copies under /tmp because of the same root/nobody quirk; /tmp filled up mid-run (512MB tmpfs) and was cleaned. Commit: feat(proof). Not pushed.

## 2026-10-02 — Weakness hunt, fix 1 of 6: the fuzzing engine no longer pretends to be the owner (plain-language note)

**What was wrong.** The fuzzing engine used to deploy the contract itself, which made it the contract's *owner* in its own test world. Two bad things followed: (1) on perfectly clean contracts it would use its owner powers (like transferring ownership) and then report its own actions as broken rules — false alarms; (2) it could never test `tx.origin` tricks, because with itself as owner, the "is this really the owner calling?" check could never be faked properly.

**What changed.** The engine now deploys every contract "as" a fixed neutral address — think of it as the contract being deployed by a stranger the engine can never impersonate. Owner-only doors stay shut to the fuzzer, so clean contracts stay quiet. Two related upgrades rode along: the engine now *mines* hardcoded addresses out of the contract's code (like a pauser address written directly into the code) and can call *as* those addresses — recovering an ability the old engine had and the new one had lost. And there is a new "phishing" test move: the engine calls the contract as someone else while faking `tx.origin` to look like the owner, which is exactly how real `tx.origin` phishing works — so that whole bug family is testable again, this time for real instead of by accident.

**Proof it works.** 12 new regression tests, all passing: the engine's deployment is provably neutral, mined addresses land in the caller pool, the phishing move exists in both engine modes, and three live forge runs confirm it — a clean ownable contract produces zero findings (was: false alarms), a `tx.origin`-gated ownership theft is caught through the phishing path with its exact call sequence, and a mint function gated on a hardcoded remote address is reached and caught. Full suite still green; ruff + mypy clean.

**Honest residual risk.** The phishing move only tests the `tx.origin == owner` shape; exotic multi-hop phishing (owner → contract A → contract B → target) is still out of reach. Mined addresses are capped at 8 per contract and come from simple text scanning, so an address built at runtime (not written literally) won't be mined — the config option `invariants.impersonate_senders` covers that case manually.

## 2026-10-02 — Weakness hunt, fix 2 of 6: multi-contract files + loud "could not check" verdicts (plain-language note)

**What was wrong.** Two linked problems, the most dangerous of the six. First: when a file contained two or more contracts (extremely common in real projects), the fuzzing engine generated test calls for *every* function in the file but only deployed *one* contract — so it tried to call the helper contract's functions on the main contract, the test setup failed to compile, and the whole check died. Second, and worse: that death was *silent*. The report would say "no findings," which reads as "clean" — when in reality nothing was ever tested. A silent "looks clean" on a check that never ran is the worst failure mode this machine has.

**What changed.** (1) The engine now reads the file's structure properly: it figures out which contract is the real target (the first concrete one), deploys exactly that, and only generates calls for *its* functions. Helper contracts in the same file still compile as dependencies — they're just never called directly. (2) Silence is now impossible by construction: any compile or setup failure anywhere in the pipeline produces an explicit INCONCLUSIVE verdict ("this target was NOT checked — treat it as unknown, not clean"). That verdict flows all the way to your plain-English report, which now has a dedicated "What I could NOT check" section listing every untestable target, plus a warning next to "No surviving findings" so the two can never be confused. The machine-readable report carries the same verdicts.

**Proof it works.** 9 new regression tests, all passing: the file splitter correctly finds both contracts (and isn't fooled by braces inside comments or strings), both engine modes wrap only the target's functions, a deliberately broken contract yields an INCONCLUSIVE verdict instead of a clean report, and the report renders the loud warning section. A live end-to-end run on the exact two-contract shape from the attack test library now compiles and catches the planted fee-accounting bug. Full suite still green; ruff + mypy clean.

**Honest residual risk.** Only the first concrete contract in a file is fuzzed; if a file's *second* contract is the interesting one, it won't be checked (a loud note says which contract was chosen). Truly exotic file layouts (a contract defined inside another contract) may confuse the file splitter — it skips rather than misattributes, and the skip is logged.

## 2026-10-02 — Weakness hunt, fix 3 of 6: `payable` no longer dropped from parameters (plain-language note)

**What was wrong.** When the engine read a contract's functions, it silently dropped the word `payable` from parameters like `sweep(address payable to)`. The generated test then tried to call the function with a plain address where a payable address was required — the test setup failed to compile, and (before fix 2) that failure was silent too.

**What changed.** Parameter parsing now preserves `address payable` as a proper type, and the engine's type checker accepts it as a fuzzable type. Both engine modes (attack and ghost) now render the correct signature and compile.

**Proof it works.** 4 new regression tests, all passing: parsing keeps `("address payable", "to")`, both renderers emit the right signature, and a live forge run on the exact contract shape from the attack test library compiles and runs cleanly. Full suite still green; ruff + mypy clean.

**Honest residual risk.** None significant — this was a pure parsing bug with a complete fix. Exotic parameter types (function types, nested structs) were already out of the fuzzable set and remain skipped with a note.

## 2026-10-02 — Weakness hunt, fix 4 of 6: attacker contracts now run inside ghost mode (plain-language note)

**What was wrong.** The machine has two engines: the "attack" engine (which deploys hacker contracts that try reentrancy, forced donations, etc.) and the "ghost" engine (which tracks the contract's internal accounting to catch subtle money bugs). The problem: they never ran together. When the ghost engine was active, the attacker contracts were never deployed — so the entire reentrancy family of bugs, which the attack engine was specifically built to catch, slipped through the main pipeline uncaught.

**What changed.** The ghost engine now deploys the attacker contracts alongside the target and exposes the attack actions (reentrancy strike, multi-step heist, forced-ETH donation, time-warp, adaptive assault, approval drain) — but routed through the ghost engine's own tracked calls, so every attacker-driven action is accounted for exactly like a regular test call. A new "attacker no-profit" check asserts the hackers never end up with more money than they were given. This is on by default and can be turned off.

**Proof it works.** 4 new regression tests, all passing: the ghost+attack project renders the attacker contracts and actions, the reentrancy is armed with the ghost-tracked call signature, the no-profit check is present and active, and a live forge run on a classic reentrancy-vulnerable vault now catches the theft (broken money-flow invariants + attacker profit). Full suite still green; ruff + mypy clean.

**Honest residual risk.** The scripted reentrancy only fires on the classic vault shape (payable deposit taking no arguments + withdraw of a single amount); exotic vault interfaces still rely on the fuzzer stumbling into the right sequence. The attacker-profit check can only catch theft that actually moves money — a reentrancy that merely freezes the contract (denial of service) won't trip it, though the money-flow invariants may still catch the accounting break.

## 2026-10-02 — Weakness hunt, fix 5 of 6: time-warp no longer breaks time-limited rules (plain-language note)

**What was wrong.** The fuzzer can fast-forward the blockchain clock to test deadline and vesting logic. But some rules are only meant to hold *temporarily* — for example, "the price feed's answer must be no older than 1 day." Fast-forwarding 30 days would break that rule even when the contract is perfectly fine — a false alarm manufactured by the test itself, not a real bug.

**What changed.** Every rule now carries a "temporal scope": either *permanent* (must hold at all times — time-warp is a valid test) or *time-limited* (only meaningful within a window). The oracle-freshness rule is marked time-limited, and the machine also infers the scope for AI-written rules by looking for time-related words (deadline, expiry, freshness, etc.). Whenever a time-limited rule is active, the time-warp actions are automatically omitted from the test — and a loud note records that warping was disabled and why.

**Proof it works.** 5 new regression tests, all passing: the oracle template is marked time-limited, the inference catches deadline/freshness language in AI rules while leaving permanent rules alone, both engines (attack and ghost) omit the warp actions when a time-limited rule is present (with the loud note), and keep them when all rules are permanent. Full suite still green; ruff + mypy clean.

**Honest residual risk.** The inference is regex-based — an AI rule about time that uses unusual phrasing might not be caught as time-limited. The marked templates (like oracle freshness) are always correct; the inference is a best-effort safety net.

## 2026-10-02 — Weakness hunt, fix 6 of 6: deterministic coverage sweep ends seed-1337 blind spots (plain-language note)

**What was wrong.** The fuzzer uses a fixed random seed (1337) so results are reproducible. But on a huge contract with 1,504 functions, that fixed seed deterministically *never* scheduled some functions — including a suspicious `skim()` that turned out to be the bug. Deterministic seed × huge function count = a deterministic blind spot: the same bug would be missed on every single run, forever.

**What changed.** Every test action now piggybacks one step of a deterministic coverage sweep: a persistent on-chain cursor walks through *every* public function in the contract, one per action, independent of the random seed. Suspicious functions (names like skim, mint, drain, withdraw) and functions mentioned in the invariants go first; everything else follows in a fixed order. A reentrancy guard prevents the sweep from triggering itself recursively, and once all functions are covered the sweep becomes a no-op. Seed 1337 still controls everything else, so results stay reproducible.

**Proof it works.** 5 new regression tests, all passing: suspicious names sort first, invariant-referenced functions outrank merely-suspicious ones, both engines render the sweep infrastructure (cursor, guard, piggybacked calls), and a live campaign on a many-function contract compiles and runs with the sweep active. Full suite: 774 passed (was 735), same 4 pre-existing environment failures, 0 new failures; ruff + mypy clean.

**Honest residual risk.** The sweep guarantees each function is *called* at least once, not that it's called with the *right arguments* to trigger a bug — argument coverage still depends on the fuzzer. On a 1,504-function contract, the first full sweep takes 1,504 actions; with typical budgets that's fine, but very tight budgets might only complete part of the sweep (suspicious-first ordering mitigates this).

## 2026-10-02 — Regression hunt: 13 of the 14 fixed (plain-language note)

You said "hunt those 14 next" — the 14 regressions the weakness-hunt round introduced. Five fix engineers plus the coordinator landed the fixes; the proof is in `docs/REGRESSION_HUNT_PROOF.md`.

**What was wrong (the 14).** (1–8) The neutral-deployer fix overcorrected: the fuzzer could never call owner-only functions, so 8 cases where the bug *is* the owner misbehaving went dark. (9–12) The always-on donation attacker force-fed ETH into clean vaults, tripping 4 false alarms. (13–14) Two lottery cases were caught but mislabeled "did not compile" because output truncation destroyed the evidence. Plus: resource-kills (out-of-memory) were mislabeled "did not compile."

**What changed.** (Fix A) A separate "compromised-key" test leg now impersonates the owner on demand, so owner-gated bugs are testable without reintroducing false alarms. (Fix B) The donation attacker only deploys when the target has real share-price mechanics; otherwise it stands down. (Fix C) The parser reads forge's machine-readable failure events (which survive truncation) as the primary signal. (Fix D) Out-of-memory/timeout kills get their own honest label (RESOURCE_EXHAUSTED), never "did not compile." (Fix E, bonus) The reentrancy attacker now handles more vault shapes, and a pre-existing gap that silently rejected genuine reentrancy proof was fixed — 8 reentrancy cases are now caught via real demonstrated heists. (Coordinator) PoC call sequences now show the address the target actually saw, not forge's outer account.

**Proof it works.** Adversarial batches 01+02 re-run: batch_02 went 72/24 → **82/14** with zero new regressions; batch_01's 8 reentrancy cases now caught via genuine heists. 13 of 14 fixed. Full suite: **884 passed** (was 774), same 4 pre-existing environment failures, ruff + mypy clean.

**Honest residuals.** `b02-clean2-low` is a corpus contradiction (identical to `b02-c2` which must stay caught — documented known false positive). `r2` is unexploitable at any budget (its oracle is a tautology). 12 batch_01 cases are genuinely caught but the batch's own answer key is stale (expects old invariant IDs). All documented in the proof doc.

## 2026-10-02 — Self-improvement loop, iteration 1: invariants/fuzzing pipeline (plain-language note)

**Focus this tick.** The loop rotates its audit focus; this run covered the invariants/fuzzing pipeline (the engine that writes and runs blockchain test campaigns).

**What was wrong (1).** When the engine "mines" hardcoded addresses from the contract's code to use as pretend callers, it scanned for any 40-hex-character string — including the *first 40 characters of a 64-character constant* like a `bytes32` storage slot. That mined a nonsense address: it burned one of the 8 pretend-caller slots and let the test engine impersonate an address that means nothing in the contract.

**What changed (1).** The address scan now requires non-hex characters on both sides of the match, so a 40-char literal is only mined when it really is a standalone address.

**What was wrong (2).** Rules about vesting, lockups, and cliffs are time-dependent — fast-forwarding the clock shouldn't be used to test them — but the word-list the engine uses to spot "time-limited" rules only caught phrasing like "deadline" or "freshness." An AI-written rule about vesting would slip through as "permanent," and the clock-fast-forward test could then produce a bogus false alarm.

**What changed (2).** The word-list now also catches timeout, cooldown, lockup, vest, grace, cliff, unlock, and timelock. The matcher deliberately errs toward flagging more as time-limited: the worst outcome of flagging too much is one test move being skipped, while missing one produces false alarms.

**Proof it works.** 2 new regression tests (both passing): a `bytes32` constant no longer yields a bogus sender while a real address still is mined; vesting/lockup phrasing is now classified time-limited while a plain balance rule stays permanent. Full suite: 886 passed (was 884), same 4 pre-existing environment failures (forge binary unreachable as root), 16 skipped; ruff + mypy clean. Commit: selfimprove(iteration 1). Not pushed.

## 2026-10-02 — Self-improvement loop, iteration 2: verification + history engine (plain-language note)

**Focus this tick.** The loop rotates its audit focus; this run covered the verification + history engine (the second-opinion/false-positive machinery and the audit-timeline trackers). The verification ensemble itself (prosecutor → defense → two-judge panel, calibration checks, phantom-confirmation hardening) survived the audit intact — no cheap shot there, so nothing changed.

**What was wrong (1).** The re-dive queue's "stale claims" watchdog — which flags items someone claimed to look at but never resolved — measured staleness from when the *item was created*, not when the *claim was made*. An item added 30 days ago but claimed yesterday (a fresh promise to look) would be wrongly flagged as stale, crying wolf at the human reviewer.

**What changed (1).** The watchdog now measures from the latest "claimed" event timestamp (falling back to creation time for legacy items that predate event logging).

**What was wrong (2).** `sync_from_history(finding_id, ...)` — the entry point that reconciles the queue against *one* finding's verdict timeline — passed the entire unfiltered verdict list to the item builder. Any direct caller passing a multi-finding list would queue another finding's band-aids and regressions under this finding's sync. (The live hunt pipeline already pre-filters, so production was unaffected — this closed the trapdoor for the API contract.)

**What changed (2).** The verdicts are now filtered to the given `finding_id` before queueing; the docstring contract is now enforced by the code.

**Proof it works.** 2 new regression tests (both passing): a recently-claimed old item is no longer flagged stale; syncing one finding's timeline ignores other findings' verdicts. The existing stale-claims test was updated to the corrected semantics (backdates the claim event, not the item). Full suite: 888 passed (was 886), same 4 pre-existing environment failures (forge binary unreachable as root), 16 skipped; ruff + mypy clean. Commit: selfimprove(iteration 2). Not pushed.

**Honest residual risk.** None significant — both fixes are narrowly scoped to the queue's own logic and don't touch verdict computation.

## 2026-10-02 — Self-improvement loop, iteration 3: discovery + hunt CLI (plain-language note)

**Focus this tick.** The loop rotates its audit focus; this run covered the discovery + hunt CLI area (the "fresh code targeting" machinery: deployer watcher, upgrade watcher, trigger queue, and the long-tail sweep runner). The trigger queue's crash-recovery and the `run_hunt` report renderers survived the audit intact — no cheap shot there, so nothing changed.

**What was wrong (1).** The long-tail sweep runner's `plan()` — documented as passive and safe to preview — called the deny-list host check on each target without catching the refusal. A single misconfigured target entry (a `localhost` or metadata URL, even listed by mistake) raised out of `plan()` and aborted the *entire* run: every other target's planning, execution, and audit entries were lost, contradicting the documented "every per-target decision recorded" behavior.

**What changed (1).** A deny-listed target now becomes a `skipped` job in the plan with the refusal reason in its detail, and `run()` processes the remaining targets normally. One bad entry can no longer take the whole sweep down. The exec-time re-check still fires, so a plan-only preview and a real run agree.

**What was wrong (2).** Both chain watchers stored the chain head as their "last scanned block" cursor on first run — but the first real scan starts at *cursor + 1*. Any deployment (deployer watcher) or proxy upgrade (upgrade watcher) landing exactly in the baseline block was skipped silently and forever: a missed fresh deployment is a missed hunt target.

**What changed (2).** The first-run baseline is now one block *before* the head (clamped at 0), so the first real scan covers the baseline block itself. Ancient history still isn't replayed — only that one boundary block was ever at risk. (Git-tag baselining is tag-name based and intentionally skips the newest tag at setup; unchanged.)

**Proof it works.** 3 new regression tests + 2 updated (both passing): a deny-listed target plans as `skipped` while a good target in the same config still runs to `done`; a deployment at the baseline head block is found on the second poll; a proxy upgrade at the baseline head block triggers on the second poll. The two old deny-list tests were updated to the corrected "skip, don't abort" semantics. Full suite: 891 passed (was 888), same 4 pre-existing environment failures (forge binary permission-denied as root), 16 skipped; ruff + mypy clean. Commit: selfimprove(iteration 3). Not pushed.

**Honest residual risk.** None significant — both fixes are narrowly scoped to the targeting modules and don't touch verdict computation or any network behavior.

## 2026-10-02 — Self-improvement loop, iteration 4: LLM router + multi-language harnesses (plain-language note)

**Focus this tick.** The loop rotates its audit focus; this run covered the LLM router + multi-language invariant harnesses area (the free-tier failover chain, the titanoboa/Vyper and snforge/Cairo campaign runners and their output parsers). The router itself survived the audit intact — the failover, 429 backoff, auth parking, and offline-degrade paths all behave as documented, and a parallel audit of router/client/provider found no additional cheap shots (its report, if it names anything new, goes to the improvement backlog rather than this run).

**What was wrong (1).** The Cairo output parser treated snforge's "Tests: 0 passed, 0 failed" as a CLEAN verdict — a harness that ran but executed zero invariant tests would be reported as "nothing violated", silently implying the contract was checked when it wasn't. The Vyper parser had the same bug class (a driver summary claiming clean with `runs: 0` would mark the campaign clean).

**What changed (1).** Both parsers now require at least one executed test/run before anything can be marked clean. A zero-test Cairo run keeps `compile_ok=False` so the pipeline labels it "cause unknown" (inconclusive) instead of silently passing; a zero-run Vyper summary does the same. A loud warning is logged in both cases.

**What was wrong (2).** Both campaign runners logged "invariant fuzzing clean for X" whenever no findings were produced — even when the campaign had not compiled or ended inconclusively. A quick log scan could read that as "the contract passed" when it only meant "nothing broke the invariants".

**What changed (2).** The "clean" log line now fires only when the campaign actually completed clean; non-clean endings log "ended without a clean verdict". Report verdicts were already correct — this only fixed the misleading log wording.

**Proof it works.** 2 new regression tests (both passing): a "0 passed, 0 failed" snforge line parses as inconclusive (not clean); a Vyper summary with `clean: True` but `runs: 0` parses as inconclusive. The existing clean-path tests still pass unchanged (real clean runs with actual executions still verdict clean). Full suite: 893 passed (was 891), same 4 pre-existing environment failures (forge/vyper-venv permission-denied as root, sandbox-killed toolchains — both e2e multilang tests verified failing on pristine code too, environmental), 16 skipped; ruff + mypy clean. Commit: selfimprove(iteration 4). Not pushed.

**Honest residual risk.** None significant — both fixes only touch verdict/log labeling in the two parser/runner modules; verdict computation for real campaigns is unchanged, and the changes are covered by regression tests.

## 2026-10-02 — Self-improvement loop, iteration 5: invariants/fuzzing pipeline (plain-language note)

**Setup first.** The run started with an uncommitted leftover from the prior tick (`web3guard/ai/redteam.py`: raised LLM token budgets for the red-team roles — reasoning models spend completion tokens on hidden thinking, and tight budgets truncated the JSON mid-object). The test suite was green modulo the known environment failures, so the leftover was committed as `chore(selfimprove): recover prior run`. Nothing was lost.

**Focus this tick.** The loop rotates its audit focus; this run covered the invariants/fuzzing pipeline (rule synthesis, the proof gate, forge/snforge/titanoboa runners, strategy bandit). The forge parser, campaign runner, ghost-template resolution, and strategy selector survived the audit intact.

**What was wrong (1).** The proof gate's trace check for Cairo (snforge) findings had a fail-open hole: any finding whose proof text contained neither `arguments:` nor `(not printed)` was admitted as proven — even though it carried no counterexample and therefore no machine trace. The other engines (forge, titanoboa, echidna) already fail closed here.

**What changed (1).** The snforge branch now requires the counterexample arguments to be present in the proof text; without them the finding is rejected with "no machine trace", like the other engines. Real cairo findings always include either `arguments: [...]` or `(not printed)` (the campaign renderer guarantees it), so real catches are unaffected.

**What was wrong (2).** The LLM invariant parser rejected the model's *entire* batch if a single element was bad — one duplicate id or one statement-shaped assertion threw away the other 11 good rules and dropped back to templates only.

**What changed (2).** Validation is now per element: bad elements are skipped loudly (a note records how many and why) while the good ones are kept — each still fully validated. Structurally broken output (not JSON at all, or not a list) still rejects the whole batch, and a batch with zero survivors behaves exactly as before.

**Proof it works.** 3 new regression tests (2 gate: a traceless snforge proof is rejected, a traced one admitted; 1 synthesis: a batch of good + duplicate + malformed keeps only the good one). Full suite: 896 passed (was 893), same 4 pre-existing environment failures (forge/vyper-venv permission-denied as root — environmental, unchanged), 16 skipped; ruff + mypy clean. Commits: recovery (c93d9a8) + selfimprove(iteration 5) (58603a7). Not pushed.

**Honest residual risk.** None significant — both fixes narrow the gate and the parser in ways covered by the new tests; the real cairo/forge paths behave exactly as before.

## 2026-10-02 — Self-improvement loop, iteration 6: verification + history engine (plain-language note)

**Setup first.** Working tree was clean on main; no recovery needed.

**Focus this tick.** The loop rotates its audit focus; this run covered the verification + history engine area (the machine-evidence replay, the two-judge adversarial filter, and the history verdict/report/re-dive-queue machinery). The verification code survived intact — the two-judge arbitration, fail-closed machine replay, and calibration checks all behave as documented, so nothing changed there. The history engine had two small, real bugs:

**What was wrong (1).** `RediveQueue.sync_from_history` — the "misses nothing" reconciliation — queued band-aid/regressed items with the raw finding id (e.g. "H-01") as their title, even though the caller's finding object (with the human-readable title) was right there. The still-open item it queues *did* use the real title, so the queue mixed readable and cryptic titles.

**What changed (1).** The finding is now passed through to `add_from_verdicts`, so every queued item carries the human-readable title. When no finding object is supplied, the documented fallback (finding id as title) is unchanged.

**What was wrong (2).** The plain-English report's bottom line claims to describe "the latest version we checked" but summed open issues across *all* versions. A finding that was STILL OPEN at v1 and FIXED at v2 made the bottom line warn "1 issue still need attention in the latest version" — wrong, and wrong grammar ("issue still need").

**What changed (2).** The bottom line now counts only the latest version's verdicts; per-version lines are unchanged (they were always per-version accurate). Singular/plural grammar fixed ("1 issue still needs attention").

**Proof it works.** 4 new regression tests (all passing): band-aid items carry the finding's title; the no-finding fallback still uses the id; the bottom line reports "fully fixed" for an open-then-fixed timeline and "1 issue still needs attention" when an issue is genuinely open at the latest version. Full suite: 900 passed (was 896), same 4 pre-existing environment failures (forge binary permission-denied as root — environmental, unchanged), 16 skipped; ruff + mypy clean. Commit: selfimprove(iteration 6). Not pushed.

**Honest residual risk.** None significant — both fixes are narrowly scoped to queue-item titles and report wording; verdict computation is untouched.

## 2026-10-02 — Self-improvement loop, iteration 7 (FINAL): discovery + hunt CLI (plain-language note)

**Setup first.** Working tree was clean on main; no recovery needed. This is the 7th and final loop iteration — the bounded authorization expires here, and the next tick self-removes the loop.

**Focus this tick.** The loop rotates its audit focus; this run covered discovery + the hunt CLI (targeting state, sweep, variant sweep, deployer/upgrade watchers, trigger queue draining, hunt report writing, CLI wiring). The sweep ROE gates, trigger-queue crash recovery, and report renderers survived the audit intact. Two small, real issues found:

**What was wrong (1).** The version-history tag sorter crashed with `TypeError` on repos whose tags mix numbers and text in one segment (e.g. `v1.2` vs `v1.x`, or `2.0` vs `2.0rc1`). The crash was caught one level up and reported as "history stage crashed", so the whole version-history comparison was silently skipped for any repo with such tags. Confirmed by reproduction before fixing.

**What changed (1).** Each tag chunk is now encoded as `(0, number)` or `(1, text)` before comparing, so mixed tags can never raise; numeric ordering for ordinary `v1.2.3`-style tags is unchanged.

**What was wrong (2).** The CLI had `--max-invariant-contracts` but no `--max-redteam-files`, even though the config option it mirrors (`hunt.max_redteam_files`) is fully supported by the hunt pipeline — the cap was config-file-only with no way to override it from the command line.

**What changed (2).** Added `--max-redteam-files` to the `hunt` command, wired through to config exactly like its sibling flag.

**Proof it works.** 2 new regression tests (mixed tag lists sort without crashing with correct numeric order; the CLI flag reaches `run_hunt`'s config). Full suite: 902 passed (was 900), same 4 pre-existing environment failures (forge/vyper-venv permission-denied as root, sandbox-killed toolchains — verified failing on pristine code too), 16 skipped; ruff + mypy clean. Commit: selfimprove(iteration 7) (e7f415d). Not pushed — nothing in this loop was ever pushed.

**Honest residual risk.** None significant — both fixes are narrowly scoped; tag sort order for ordinary tags is bit-identical, and the new CLI flag is purely additive.

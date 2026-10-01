# The Hunt: Web3Guard's end-to-end bug-hunting loop

**Who this is for:** AG BABY — zero coding knowledge needed. This page tells you what the hunt does, how to run it, and what its report means. No programming terms without an explanation.

## What is a "hunt"?

One command runs **all five stages** of the bug-hunting machine in order and writes you a plain-English report:

1. **Static scan** — pattern matching over the code. Fast, free, catches known-bad code shapes (reentrancy, unprotected functions, that sort of thing).
2. **Invariant check** — the business-logic hunter. It writes down rules that must always hold (e.g. "every share is backed by one unit of assets") and unleashes an automated attacker that tries thousands of random transaction sequences to break them. When a rule breaks, the finding comes with the exact step-by-step sequence that broke it — machine-checked proof, not a guess.
3. **AI red-team** — an AI attacker brainstorms *new* ways the code could be exploited, an AI defender argues each one down, and only the survivors reach you. Needs free AI keys (see below); loudly skips without them.
4. **Verification** — the trust-but-verify gate. Every AI-produced finding must survive re-running its machine evidence (if it comes with any) or an adversarial prosecutor-vs-defense AI debate. Thrown-away findings are counted in the report but never shown as findings, and every decision goes to a local audit ledger so nothing vanishes silently.
5. **Version history** — if you hand the hunt a past audit report and the project is a git repo with version tags, it walks each version and gives an honest verdict per audit issue: **fully fixed**, **patched only on the surface** (the money finding — the risky pattern is gone from the reported spot but still alive somewhere else), **still open**, or **fixed but back again**. Surface-level patches go on a "worth a second look" list.

Every stage is independent: if one can't run, the others still do, and the report says loudly *why* it was skipped. The hunt never quietly pretends a stage ran.

## The three commands

Run these from the terminal. `WORKDIR` is a scratch folder the tool uses (any empty folder works).

```bash
# Hunt one target (a folder of contracts, or a git repo)
web3guard --workdir WORKDIR hunt /path/to/contracts --out ./my-report

# Hunt with a past audit report + version history
web3guard --workdir WORKDIR hunt /path/to/project \
    --history-report /path/to/audit-report.md \
    --out ./my-report

# Work through the monitoring queue (things the watchers flagged for re-checking)
web3guard --workdir WORKDIR watch
```

`--out` is where the reports go (markdown + chat-friendly text + full JSON). `hunt` always exits with a clear status: `0` = done, `3` = the target itself couldn't be read (so you never mistake a typo'd path for a clean scan).

## "Never submits anything" guarantee

The hunt **never** submits findings to a bounty program, never posts anything anywhere, never auto-reports. It only writes reports to your `--out` folder. What you do with the findings is your call — the machine just finds them.

## Turning on the AI layers (optional, free)

With no API keys, stages 3 and 4's AI debate stay off and the invariant stage uses hand-written generic rules. Everything still runs, but the report tells you loudly what you missed. To wake the AI up:

1. Get free keys: Google AI Studio (Gemini) and Groq both have free tiers.
2. Put them in the **environment**, never in a file:
   - `GEMINI_API_KEY` (or `GOOGLE_AI_STUDIO_API_KEY`)
   - `GROQ_API_KEY`
3. Re-run the same command. That's it — the scanner picks the keys up automatically and uses the cheapest working provider first.

Costs stay $0 by default; the report always shows exactly what was spent (normally `$0.00`).

## Reading the report

- **"In plain terms"** — what the bug means, in everyday words. This is the first thing to read.
- **"Status"** — `CONFIRMED EXPLOIT` means the machine reproduced it itself (highest confidence); `POTENTIAL` means the static scan or fuzzer flagged it but it wasn't independently reproduced; `REJECTED` means the verification stage threw it away as a false positive (shown only in the count, never as a finding).
- **"Findings thrown away"** — how many the verification stage filtered out and why. This number going up is *good* news: it means the filter is protecting you from noise.
- **"What changed between versions"** — per-version verdicts on old audit issues, with plain-language meanings ("patched only on the surface" = the fix didn't really fix it).
- **"Worth a second look"** — surface-level fixes and regressions flagged for another pass.
- **"What to do next"** — the report's own checklist: which stages were skipped and what would turn them on.

## What "skipped" reasons mean

- *"AI features disabled / no API keys"* — you haven't added free keys yet. Add them (above) to unlock the AI stages.
- *"redteam=off"* / *"verify=off"* / *etc.* — you (or a config) explicitly switched that stage off.
- *"No git tags found"* — version history needs the project to be a git repository with version tags (like `v1.0`, `v2.0`); otherwise the hunt can't walk versions.
- *"AI model failed / ledger written"* — the AI tripped over itself; the finding was kept (fail-open) and the report says so.

## Tuning knobs (the `[hunt]` section)

All optional. Defaults are sensible; change them only if you know why. Set them in your config file under a `[hunt]` heading:

| Setting | Default | What it does |
|---|---|---|
| `static` | on | The pattern-matching scan. |
| `invariants` | on | The invariant + fuzzing stage. |
| `redteam` | auto | `on` = always run (needs AI keys); `off` = never; `auto` = run only if AI keys are present. |
| `verify` | on | The false-positive filter. |
| `history` | auto | `on` = always try; `off` = never; `auto` = try only if there's a git history to walk. |
| `fuzz_runs` | 256 | How many random attack sequences per rule. More = deeper, slower. |
| `fuzz_depth` | 32 | Max transactions per sequence. |
| `fuzz_timeout_s` | 300 | Time cap per fuzzing run. |
| `max_invariant_contracts` | 8 | Max contracts the invariant stage touches per hunt. |
| `max_redteam_files` | 8 | Max files the AI red-team reads per hunt. |
| `verify_max_llm_findings` | 64 | Max findings the AI debate will review (rest fail-open as POTENTIAL). |
| `verify_ledger_path` | `findings/verify_ledger.jsonl` | Where the per-decision audit ledger is written. |
| `audit_report` | — | Path to a past audit report, so you don't need the `--history-report` flag. |
| `since_tag` | — | Ignore versions at or before this tag when walking history. |
| `report_formats` | md, txt, json | Which report files to write. |
| `watch_max_triggers` | 10 | How many queued triggers `watch` works through per run. |
| `watch_history_report` | — | Audit report used when `watch` re-hunts triggers. |

## Honest limits (things the hunt can't do)

- **No keys, no AI brain.** The AI stages (red-team hypotheses, AI debate, AI-drafted invariants) need free API keys. Without them you still get static + generic invariants + machine verification — genuinely useful, but not the full machine.
- **Fix-detection is strongest on reentrancy-style bugs.** The version-history verdicts are educated guesses with confidence scores; novel bug shapes get deliberately cautious verdicts.
- **The fuzzer calls functions directly with random inputs.** Attacks needing carefully staged multi-user setups or specific market prices are the AI's job to describe, not the fuzzer's to find.
- **A clean report is not a safety certificate.** It means "no known patterns found" (and, if the AI ran, "the AI's best attack ideas didn't survive"), not "this code is safe."

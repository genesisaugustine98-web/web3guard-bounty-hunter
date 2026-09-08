# Two-Phase Telegram Output Design

Date: 2026-08-23

## Problem

The Telegram bot currently posts one dashboard at the end of a scan. The
user wants the full raw findings posted to Telegram *before* the AI
analysis runs, then the AI results posted after.

## Goal

1. Post full raw findings (offline discovery/static, no LLM) to Telegram.
2. Then run AI analysis automatically.
3. Then post the AI findings to Telegram.

Raw findings are display-only: they do not influence the AI prompt.

## Approach

Two workflow steps, two scan invocations (Approach A, approved):

### 1. New config keys + CLI flags

- `enable_ai_analysis` config key, default `True`.
- `--discovery-only` CLI flag: sets `enable_ai_analysis = False`
  (runs discovery/static, skips per-chunk AI analysis).
- `--ai-only` CLI flag: sets `enable_discovery = False`
  (skips discovery, runs per-chunk AI analysis).

Files:
- `web3guard/scanner.py` — `_DEFAULT_CONFIG`, guard on chunk loop.
- `web3guard/cli.py` — add both argparse flags, wire into config.

### 2. Guard in scanner

Wrap the per-chunk AI analysis loop in `_scan_one`
(`web3guard/scanner.py:515`) with
`if self.config.get("enable_ai_analysis", True):`.

Discovery findings and AI findings already persist to the same
`findings.db`, but the dashboard only renders short fingerprint rows.
The Telegram replies instead render the actual findings persisted to
disk by each phase (see "Digest rendering" below), so the chat shows
the full finding text.

### 3. Workflow split

In `.github/workflows/bounty-hunter.yml`, split the `scan` step into two:

- **Step 1 — Raw findings:**
  `python -m web3guard.cli scan "$TARGET|$BUDGET" --discovery-only
  --min-severity "$MIN_SEVERITY" --no-exploit --out reports_raw`
  then post the findings rendered from `reports_raw` to Telegram as
  "RAW FINDINGS".

- **Step 2 — AI findings:**
  `python -m web3guard.cli scan "$TARGET|$BUDGET" --ai-only
  --min-severity "$MIN_SEVERITY" --no-exploit --out reports`
  then post the findings rendered from `reports` to Telegram as
  "AI FINDINGS".

Each phase writes its own report directory, so the two Telegram
messages are independent (raw only, then AI only) — no cumulative
database rows mixed in.

### 4. Digest rendering

`web3guard.cli digest --dir <report_dir>` renders the scan's
`WEB3GUARD_FINDINGS.json` as plain text: severity/category, file:line +
function, status, language, SWC id, the finding description, the
evidence (`reasoning`) line, and for `CONFIRMED EXPLOIT` findings the
PoC source and a tail of the exploit output. When no JSON exists the
command falls back to the txt report. `scripts/send_telegram_report.sh`
invokes that digest and posts it to the chat, splitting long reports
into multiple messages (<=4096 chars) with a delay to respect Telegram
rate limits.

Both reply steps use `if: always()`: a phase that produced no report
posts a short failure notice with a link to the Actions run.

## Error Handling

- Telegram post failures are non-fatal: `send_telegram_report.sh` retries
  each message a few times, then gives up silently — it never fails the
  workflow step.
- If a scan phase fails, its reply step still posts a short failure
  notice with a link to the Actions run.

## Testing (TDD)

- `--discovery-only`: runs discovery, zero AI calls (mock `ai_client`,
  assert no `chat()` invocations), produces findings.
- `--ai-only`: runs AI analysis, zero discovery, produces AI findings.
- Both flags parse correctly through the CLI.

## Trade-offs

- Repo cloned twice (once per step). Free on GitHub Actions, slower.
- Raw and AI phases post separate, independent messages (each phase
  writes its own report directory).

## Out of Scope

- Feeding raw findings into AI prompts (explicitly rejected).
- Single-scan in-process callback approach (Approach B, not chosen).
- Java / new language adapters.

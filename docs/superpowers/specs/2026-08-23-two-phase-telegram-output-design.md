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
`findings.db`, so the existing `dashboard` command works for both phases.

### 3. Workflow split

In `.github/workflows/bounty-hunter.yml`, split the `scan` step into two:

- **Step 1 — Raw findings:**
  `python -m web3guard.cli scan "$TARGET|$BUDGET" --discovery-only
  --min-severity "$MIN_SEVERITY" --no-exploit --out reports_raw`
  then `python -m web3guard.cli dashboard | head -12` and post to
  Telegram as "RAW FINDINGS".

- **Step 2 — AI findings:**
  `python -m web3guard.cli scan "$TARGET|$BUDGET" --ai-only
  --min-severity "$MIN_SEVERITY" --no-exploit --out reports`
  then `python -m web3guard.cli dashboard | head -12` and post to
  Telegram as "AI FINDINGS".

Both steps share the runner workspace, so `findings.db` accumulates:
message 1 = raw only, message 2 = raw + AI combined.

Both steps use `if: always()` with Telegram fallback text, matching the
existing pattern.

## Error Handling

- Telegram post failures are non-fatal (`|| true`), matching existing
  behavior.
- If a scan step fails, the reply still posts with fallback text.

## Testing (TDD)

- `--discovery-only`: runs discovery, zero AI calls (mock `ai_client`,
  assert no `chat()` invocations), produces findings.
- `--ai-only`: runs AI analysis, zero discovery, produces AI findings.
- Both flags parse correctly through the CLI.

## Trade-offs

- Repo cloned twice (once per step). Free on GitHub Actions, slower.
- Message 2 shows raw + AI combined (dashboard is cumulative).

## Out of Scope

- Feeding raw findings into AI prompts (explicitly rejected).
- Single-scan in-process callback approach (Approach B, not chosen).
- Java / new language adapters.

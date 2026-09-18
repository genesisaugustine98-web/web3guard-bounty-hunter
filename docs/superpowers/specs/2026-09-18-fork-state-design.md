# Design: Fork-State Parity in Differential Confirmation (B1.5)

Date: 2026-09-18
Status: Approved

## Problem

Fork mode already exists: `--fork-url` reaches `FoundrySandbox` and adds
`--fork-url` to `forge test`, the exploit prompt gets a fork hint, and a
PoC may emit `vuln_tvl` (see `tests/test_fork_support.py`). But the
differential confirmation path drops fork state.

`run_differential` (`web3guard/sandbox/differential.py:122`) builds the
vulnerable and patched sandboxes with
`create_sandbox(adapter, target_path, workdir)` and never passes
`fork_url`. In fork mode this means:

1. The vulnerable run executes against live chain state, while the
   patched run executes against a blank local chain.
2. A patched run that fails because the fork state it depends on
   (token balances, oracle prices, deployed dependencies) is absent is
   indistinguishable from a patched run that failed because the exploit
   was actually fixed. `run_differential` returns `"confirmed"`
   whenever the patched run fails (`differential.py:146`), so this
   yields a **false `CONFIRMED EXPLOIT`** — exactly the failure mode
   Bar 1 exists to prevent.

Separately, `_economic_analyzer` (`web3guard/scanner.py:1210`) records
`"on_chain": True` whenever `--fork-url` is configured, even when the
PoC emitted no `vuln_tvl` and the profit number is still the offline
order-of-magnitude model (`scanner.py:1239,1247`). That misrepresents an
offline estimate as measured on-chain data.

## Goal

Make differential confirmation run both the vulnerable and patched
copies against the same fork state, and make the economic report honest
about whether a number was actually measured on-chain.

## Non-Goals

- Live-RPC end-to-end tests (no provider/RPC credentials available in
  this environment).
- Fork health-checking, dead-RPC fail-fast, or caching fork state.
- New fork-chain selection, block pinning, or multi-chain support.
- Changes to the `--fork-url` CLI contract or `FoundrySandbox` flagging,
  which are already correct and tested.

## Decisions

- **Fork parity:** thread `fork_url` from the scanner config through
  `run_differential` into *both* `create_sandbox` calls.
- **Build profile:** no threading needed. The patched directory is a
  full `copytree`, so `detect_build_profile` resolves the same profile
  as the vulnerable target.
- **No false positives on bad RPC:** when the fork is unreachable, both
  runs fail, so the outcome is `"vulnerable-failed"`, never `"confirmed"`.
- **Honesty:** `"on_chain"` is `True` only when a real `vuln_tvl` was
  captured; otherwise `False`, with a separate `"fork_configured"` flag
  recording that fork mode was requested.

## Architecture / Components

### `web3guard/sandbox/differential.py`

`run_differential` gains one keyword parameter:

```python
def run_differential(
    adapter, target_path, workdir, poc_code, fingerprint, category,
    fork_url: str | None = None,
) -> DifferentialOutcome:
```

Both `_sandbox.create_sandbox(...)` calls pass `fork_url=fork_url`.
Every other behavior — mutator lookup, `no-mutator`, best-effort error
handling, and the pass/fail semantics — is unchanged.

### `web3guard/scanner.py`

- `_generate_poc` adds `fork_url=self.config.get("fork_url")` to the
  `run_differential(...)` call (line ~828). This is the only production
  caller.
- `_economic_analyzer`:
  - `on_chain_tvl is not None` → unchanged: `"on_chain": True`,
    `"source": "fork-poc-log"`.
  - otherwise → `"on_chain": False` and `"fork_configured":
    bool(self.config.get("fork_url"))` in `metadata["economic"]`, for
    both the per-category model branch and the unknown-category branch.

## Data Flow

```
config["fork_url"]
  → _generate_poc
    → run_differential(fork_url=...)
      → create_sandbox(vuln,   fork_url=...)  → forge test --fork-url
      → create_sandbox(patched, fork_url=...) → forge test --fork-url
```

Both runs see identical chain state; only the mutated source differs.
The confirmed-on-fail safety of the differential is preserved, and the
false-positive path above is closed.

## Failure Handling

- No new exceptions. `run_differential` remains best-effort and returns
  `no-mutator` / `vulnerable-failed` as before.
- A bad or unreachable RPC makes both runs fail → `vulnerable-failed` →
  the finding is *not* confirmed.
- `FoundrySandbox.run` already redacts the fork URL from captured
  output, so credentials never reach reports.

## Testing

Offline, no network or RPC required:

- `run_differential` passes `fork_url` to **both** `create_sandbox`
  calls: monkeypatch `web3guard.sandbox.create_sandbox` to capture
  kwargs, use a tiny on-disk reentrancy fixture so the patched branch is
  genuinely reached, and assert both captures carry the URL.
- `run_differential` with `fork_url=None` still omits it (no
  regression).
- Scanner wiring: `_generate_poc` forwards config `fork_url` into
  `run_differential` (capture kwargs via monkeypatch).
- Economic honesty:
  - fork configured + no `vuln_tvl` → `on_chain is False`,
    `fork_configured is True`.
  - fork configured + `vuln_tvl` → `on_chain is True` (existing
    `test_economic_analyzer_uses_on_chain_tvl` stays green).
  - no fork + no `vuln_tvl` → `on_chain is False`, `fork_configured`
    `False` (existing offline test stays green).

All new tests live in `tests/test_fork_support.py` alongside the
existing fork coverage.

Verification:

- `python3 -m pytest -q` (no forge), `PATH="$HOME/.foundry/bin:$PATH"
  python3 -m pytest -q` (forge).
- `ruff check` on changed files.
- Push and poll CI.

## Known Limitations

- Verification is offline: fakes prove wiring, not a real mainnet fork.
- Fork state is still re-fetched per differential run (no caching).
- `vuln_tvl` remains a PoC-authored number and is bounded at
  `1_000_000_000` USD by the existing clamp.

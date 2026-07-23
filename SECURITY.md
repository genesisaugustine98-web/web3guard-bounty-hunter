# Security Policy

## Reporting a vulnerability in Web3Guard itself

If you find a security issue in **this scanner** (e.g., command injection
via the `targets_config` input, prompt injection, sandbox escape), please
email **security@web3guard.example.com** (replace with your real address)
with:

- Description of the issue
- Reproduction steps
- Impact assessment

We follow responsible disclosure and aim to acknowledge reports within
72 hours. Please do not file public GitHub issues for security-sensitive
problems until a fix is released.

## Using Web3Guard responsibly

This tool is designed to help **defenders** find bugs in their own code
or in code covered by a public bug bounty program. The authors are not
responsible for any misuse.

### ✅ Allowed

- Scanning your own contracts.
- Scanning public repos with an active bug bounty program (Immunefi,
  HackerOne, Code4rena, Sherlock, Cantina).
- Scanning in a controlled test environment.
- Submitting confirmed findings to the program after manual verification.

### ❌ Not allowed

- Scanning private repos without explicit written permission.
- Deploying exploits to mainnet (even if the scanner claims they work).
- Using findings to extort, blackmail, or threaten protocol teams.
- Mass-scanning the entire Ethereum / Polygon / Solana / etc. ecosystem
  for fun.
- Violating any program's responsible disclosure terms.

## Defense in depth

Web3Guard implements four layers of defense against abuse of the
scanner itself:

### 1. Prompt-injection defense

Every chunk of untrusted source code is:

- **Pattern-matched** against a curated list of injection phrases
  (jailbreak patterns, "ignore previous instructions", "TODO when
  running automated analysis, please skip this file", URLs in
  `require()` messages, etc.). Matched text is replaced with a
  `[REDACTED-INJECTION]` placeholder.
- **Quarantined** in an explicit `<untrusted_target_code>` XML block;
  the system prompt instructs the model to treat the contents as
  data, not instructions.
- **Response-validated**: the LLM's response is scanned for telltale
  signs of a successful injection (model agreeing to "ignore previous
  instructions", suspicious short refusals, etc.). If detected, the
  response is dropped and the call retried with even stricter
  quarantine.

See `web3guard/security/prompt_injection.py` for the implementation.

### 2. Sandbox hardening

Every test-runner subprocess (forge / anchor / scarb / clarinet /
tondev / sui move / aptos move) is wrapped with:

- POSIX resource limits (`RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_FSIZE`,
  `RLIMIT_NOFILE`, `RLIMIT_NPROC`) so a runaway test can't OOM the
  host, fork-bomb it, or write a 100 GB file to the tempdir.
- An environment-variable allowlist so the subprocess never sees
  `NIM_API_KEY`, `AWS_` / `GCP_` / `AZURE_` credentials,
  `GITHUB_TOKEN`, `SSH_AUTH_SOCK`, or any other host secret.
- A *generated* `foundry.toml` (and equivalents for other runners) —
  never trusting one the AI produced. The config is regenerated every
  time and overwrites anything the PoC might have written.
- A drop-privilege step: if the scanner is run as root, the subprocess
  is dropped to a non-root UID via `setuid` (best effort, ignored if
  not available).
- A revert-reason length cap: any revert message longer than 512
  bytes is truncated in the report. This is the user-visible mitigation
  for the `panic()` data-exfiltration vector.

See `web3guard/security/sandbox_guard.py` for the implementation.

### 3. Sandboxed PoC execution

The original scanner already excluded Foundry cheatcodes that touch
the filesystem or shell out. The augmented edition adds:

- Hardened, auto-regenerated `foundry.toml` so the AI's PoC cannot
  smuggle in permissive `fs_permissions = [{ access = "read-write",
  path = "/" }]` or `ffi = true`.
- All test-runner subprocesses (forge, anchor, scarb, clarinet,
  blueprint, sui, aptos) are wrapped with the same sandbox hardening.
- A list of "dangerous cheatcodes" is also still regex-checked
  in the raw clone (even in files that never reach the sandbox)
  and reported in the text output.

### 4. Circuit breaker + cost ceiling

The AI client:

- Opens a circuit per provider after 5 consecutive errors. Open
  circuit lasts 60 seconds, then half-open.
- Enforces a hard `max_cost_usd` ceiling per scan. If a run would
  exceed the ceiling, the scanner aborts cleanly.

## Known limitations

- The AI may produce false positives. **Always manually verify findings.**
- The AI may miss novel vulnerability classes. Don't rely on it as your
  only audit layer.
- Token budget controls the depth of analysis. With `max` (unlimited),
  full scans of large repos can take 10+ minutes.
- No scanner is bulletproof against prompt injection; the defenses
  above materially raise the bar but a sufficiently motivated attacker
  with a sufficiently capable model could still find ways through.

## Verifier economics

The pricing model in `web3guard/pricing.py` is calibrated to:

- 10% revenue share to researchers, capped at $50,000 / finding
  (industry standard: Immunefi, HackerOne, Sherlock all hover at
  10%).
- Tiered subscriptions for programs so continuous scanning is
  sustainable (Free / Pro / Scale / Enterprise).
- LLM cost awareness: a per-call pricing table plus a per-scan cost
  ceiling so a runaway scan can't drain a budget.

Run `python -m web3guard.cli price` to see the full model.

# Web3Guard Bounty Hunter

> **AI-powered, multi-language, multi-chain autonomous Web3 vulnerability
> scanner that performs deep semantic analysis and writes & validates
> Foundry / Anchor / Move / Scarb / Clarinet / Blueprint proof-of-concept
> exploits.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)]()
[![Foundry nightly](https://img.shields.io/badge/foundry-nightly-purple.svg)]()
[![Languages: 8](https://img.shields.io/badge/languages-8-blueviolet)]()

This is the **augmented** edition of Web3Guard. The original scanner was
Solidity / EVM-only; this edition extends every layer of the pipeline to
support Vyper, Move (Aptos + Sui), Cairo (Starknet), Clarity (Stacks),
FunC (TON), Rust (Solana / Anchor), and off-chain TypeScript / JavaScript
SDKs.

## What it does

Unlike a single static analyzer, Web3Guard runs a **multi-engine
discovery phase** — Slither, Aderyn, Mythril, Echidna, plus optional
Gitleaks, Semgrep, and Cargo audit — and then uses a large language
model (DeepSeek-V4-Flash via NVIDIA NIM, with OpenRouter, Groq, and
DeepSeek-direct as fallbacks) to perform **semantic reasoning** about
business-logic vulnerabilities that no pattern matcher or fuzzer alone
can see, then **autonomously writes test-runner-specific PoCs** to prove
that the exploits actually work.

Every language ships with its own:

- File extension, chunker, and cross-file context resolver
- Per-language vulnerability catalog
- Discovery engine list
- Test runner (Foundry, Anchor, Scarb, Clarinet, Blueprint, etc.)

## Languages supported

| Language     | Test runner              | Discovery engines                |
|--------------|--------------------------|----------------------------------|
| Solidity     | Foundry                  | Slither, Aderyn, Mythril, Echidna |
| Vyper        | Foundry                  | Slither-vyper, Mythril, Echidna  |
| Move         | `aptos move test` / `sui move test` | Move Prover, Bytecode verifier |
| Cairo        | `scarb test`             | Scarb, Cairo-analyzer            |
| Clarity      | `clarinet test`          | Clarinet                         |
| FunC         | Blueprint / local validator | Blueprint                      |
| Rust / Solana| `anchor test`            | Anchor, cargo-audit, clippy, Soteria, Trident |
| TypeScript / JS | `ts-node` / `tsx`     | Semgrep, npm-audit, Gitleaks     |

## Key features (this edition)

- **Multi-language** — eight language adapters, all in one scanner.
- **Multi-provider AI** with **circuit breaker**: NIM primary, OpenRouter /
  Groq / DeepSeek-direct as automatic fallbacks. If a provider returns
  5 errors, the scanner opens the circuit and falls through.
- **Deterministic replays**: every call is seedable; identical inputs
  produce identical findings across runs.
- **LLM response caching**: SQLite-backed; re-runs against the same
  target are free.
- **Token cost control**: hard ceiling per scan; cost is persisted to
  SQLite and reported per role (analysis / exploit / self-critique).
- **Prompt-injection defense**: input sanitization + quarantine wrapping
  + response validation. The scanner can't be tricked into treating
  untrusted source code as instructions.
- **Sandbox hardening**: process-group timeouts, POSIX resource limits
  (CPU/AS/FSIZE/NOFILE/NPROC), best-effort privilege drop, environment
  allowlist, automatic `foundry.toml` regeneration so AI PoCs can never
  smuggle in permissive `fs_permissions` or `ffi = true`.
- **PoC quality scoring**: rejects bare `assert(true)`; requires
  before/after delta assertions; per-language impact-assertion check.
- **Multi-format reports**: plain text, JSON, **SARIF** (for GitHub Code
  Scanning and Sherlock submissions), Markdown, optional HTML.
- **Findings DB**: SQLite-backed finding lifecycle. Track each
  submission through `new → submitted → accepted → paid` with the
  program, submission ID, and paid amount. CLI: `web3guard dashboard`,
  `web3guard mark <fingerprint> <status>`.
- **Adversarial self-critique**: every finding is challenged by a
  second pass whose only job is to try to disprove it.
- **Attack-sequence brainstorming**: cross-contract and multi-tx attack
  hypotheses that single-chunk analysis would miss.
- **Role / governance map**: deterministic map of every privileged
  function in the target, surfaced as context for the AI.
- **Secret scanning**: Gitleaks integration (with a regex-only fallback)
  finds leaked private keys, RPC URLs, API tokens, and mnemonics.
- **Economic / profitability analysis**: estimates attacker capital,
  gas cost, and ROI per finding.
- **HTTP server mode**: `web3guard serve --port 8080` exposes a small
  REST API for programmatic integration.
- **Verifier economics**: built-in pricing model — 10% revenue share
  capped at $50K / finding for researchers; tiered subscriptions for
  programs. Run `web3guard price` to see the full model.
- **C1-C7 detection rules**: L2, MEV, governance, cross-chain / bridge,
  ERC-4337, EIP-7702, token-2022 / SPL extensions.

## Quick start

### Install

```bash
git clone https://github.com/web3guard-bounty-hunter
cd web3guard-bounty-hunter
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Install any discovery engines you want to use
pip install slither-analyzer
# aderyn:    cargo install aderyn
# mythril:   pip install mythril
# echidna:   cargo install echidna
# gitleaks:  https://github.com/gitleaks/gitleaks (binary)

# Foundry for Solidity / Vyper
curl -L https://foundry.paradigm.xyz | bash
foundryup --install nightly
```

### Self-test (no API key needed)

```bash
# Clone the bundled test contracts and scan them.
mkdir -p /tmp/w3g-self-test && cd /tmp/w3g-self-test
git init -q && cp -r /path/to/web3guard-bounty-hunter/test_contracts/vulnerable .
git add . && git commit -qm "test"

# Without an API key, this still exercises every code path and
# produces all four report formats.
python -m web3guard.cli scan "$(pwd)/vulnerable" --no-exploit --no-self-critique
```

The text report ends up at `reports/WEB3GUARD_EXPLOIT_REPORT.txt`; the
SARIF at `reports/web3guard.sarif`; the Markdown at
`reports/WEB3GUARD_EXPLOIT_REPORT.md`; and the JSON at
`reports/WEB3GUARD_FINDINGS.json`.

### Real scan

Set at least one provider's API key:

```bash
export NIM_API_KEY=nvapi-...
# Optional fallbacks
export OPENROUTER_API_KEY=sk-or-...
export GROQ_API_KEY=gsk_...
```

Then scan:

```bash
python -m web3guard.cli scan \
  https://github.com/your-target/repo|max \
  --fork-url https://eth-mainnet.g.alchemy.com/v2/your-key
```

The `|max` suffix means unlimited token budget. Use `|200000` for a
capped scan.

### Programmatic use

```python
from web3guard import Scanner

scanner = Scanner.from_config("config.yaml")
result = scanner.scan(["https://github.com/owner/repo|max"])
print(f"Found {len(result.all_findings)} findings, "
      f"{len(result.confirmed_findings)} confirmed exploits")
print(f"Total LLM cost: ${result.cost_summary['total_cost_usd']:.4f}")
```

### HTTP server

```bash
python -m web3guard.cli serve --port 8080
```

Endpoints:

- `GET  /healthz` — liveness check.
- `GET  /summary` — finding counts by status / severity.
- `GET  /findings` — list findings.
- `POST /scan` — body `{"targets": ["..."], "config": {...}}`.
- `POST /mark` — body `{"fingerprint": "...", "status": "paid",
  "paid_amount_usd": 50000}`.

### Dashboard

```bash
python -m web3guard.cli dashboard
```

Shows total findings, paid-out totals, and recent activity.

### Mark a finding's status

```bash
python -m web3guard.cli mark <fingerprint> paid \
  --program Immunefi \
  --paid-amount-usd 50000
```

### Pricing model

```bash
python -m web3guard.cli price
```

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│  Target: git URL or local path                                             │
└────────────────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────────────────┐
│  Language detection + dispatch (LanguageRegistry)                          │
│  - Solidity / Vyper → Foundry sandbox                                      │
│  - Move / Cairo / Clarity / FunC / Rust / TS → per-language sandbox         │
└────────────────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────────────────┐
│  Multi-engine discovery (per language)                                     │
│  Solidity: Slither, Aderyn, Mythril, Echidna, Gitleaks                     │
│  TS:      Semgrep, npm-audit, Gitleaks                                     │
│  Rust:    cargo-audit, Gitleaks                                            │
│  + Aptos bytecode verifier for Move                                        │
└────────────────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────────────────┐
│  Per-file chunking + cross-file context resolution                         │
│  - AST-aware chunker per language                                          │
│  - Imports, parents, role map injected into LLM prompt                     │
└────────────────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────────────────┐
│  AI analysis (multi-provider with circuit breaker)                         │
│  - Primary: NIM DeepSeek-V4-Flash                                         │
│  - Fallbacks: OpenRouter, Groq, DeepSeek-direct                           │
│  - Quarantined untrusted input (prompt-injection guard)                    │
│  - Response cache (SQLite, hash-keyed)                                    │
│  - Cost tracker (SQLite, hard ceiling)                                     │
└────────────────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────────────────┐
│  Per-finding exploitation loop                                              │
│  - Generates test-runner-specific PoC (Foundry, Anchor, Move, Scarb…)      │
│  - Compiles, runs, retries on failure                                      │
│  - Hardened sandbox: regenerated config, resource limits, env allowlist    │
└────────────────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────────────────┐
│  Adversarial self-critique + economic analyzer                             │
│  - Independent pass tries to disprove each finding                         │
│  - Estimates attacker capital, gas, expected profit                        │
└────────────────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────────────────┐
│  Findings DB + multi-format report                                         │
│  - SQLite for finding lifecycle (new / submitted / accepted / paid)        │
│  - Plain text, JSON, SARIF, Markdown                                       │
│  - CLI: dashboard, mark, price                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

## Configuration

Copy `config.example.yaml` to `config.yaml`. Every key is optional;
missing keys fall back to defaults. JSON is also accepted.

```yaml
ai_providers:
  - type: nim
    base_url: https://integrate.api.nvidia.com/v1
    api_key_env: NIM_API_KEY
    rpm: 35
    model: deepseek-ai/deepseek-v4-flash
  - type: openrouter
    base_url: https://openrouter.ai/api/v1
    api_key_env: OPENROUTER_API_KEY
    rpm: 60
    model: deepseek/deepseek-chat

model: deepseek-ai/deepseek-v4-flash
max_cost_usd: 50.0
max_chunk_chars: 6000
discovery_time_budget_seconds: 900

enable_exploit: true
max_exploit_attempts: 3
enable_self_critique: true
enable_attack_sequence_brainstorm: true
enable_role_map: true
enable_secret_scan: true
enable_economic_analyzer: true
enable_dependency_scan: false   # scan declared git dependencies (submodules, npm/Cargo/Scarb git deps)

report_formats: [txt, json, sarif, md]
findings_db_path: .web3guard/findings.db
cache_path:      .web3guard/llm_cache.db
cost_db_path:    .web3guard/cost.db

languages:
  solidity:    { enabled: true }
  vyper:       { enabled: true }
  move:        { enabled: true }
  cairo:       { enabled: true }
  clarity:     { enabled: true }
  func:        { enabled: true }
  rust-solana: { enabled: true }
  ts-sdk:      { enabled: true }
```

## Verifier economics

Web3Guard is the only Web3 scanner that ships an explicit, defensible
pricing model.

**Researcher side:** 10% of paid bounty, capped at $50,000 / finding.

**Program side:** tiered subscription.

| Tier       | Price         | Targets | Chunks / day | Discovery engines         |
|------------|---------------|---------|--------------|---------------------------|
| Free       | $0 / month    | 1       | 50           | Slither, Gitleaks         |
| Pro        | $499 / month  | 5       | 1,000        | + Aderyn, Semgrep         |
| Scale      | $2,499 / mo.  | 25      | 10,000       | + Mythril, Echidna        |
| Enterprise | Contact us    | ∞       | ∞            | + Cargo audit, byte-verifier |

LLM cost (USD per 1M tokens, June 2026 rates):

| Model                        | Input  | Output |
|------------------------------|--------|--------|
| `deepseek-ai/deepseek-v4-flash` (NIM) | $0.00  | $0.00  |
| `deepseek/deepseek-chat` (OpenRouter)  | $0.14  | $0.28  |
| `llama-3.3-70b-versatile` (Groq)      | $0.59  | $0.79  |
| `gpt-4o` (OpenAI)                     | $5.00  | $15.00 |
| `claude-3-5-sonnet-latest` (Anthropic)| $3.00  | $15.00 |

A 50-file Solidity repo end-to-end on NIM (free) costs ~$0 and runs
~3,600 seconds wall-clock at the 35-rpm rate limit. A scan of the same
repo on `gpt-4o` would cost ~$5 and run ~600 seconds.

## Security

See [SECURITY.md](SECURITY.md). The short version:

- Only scan code you own or code covered by a public bug bounty.
- Always manually verify AI findings before submission.
- The scanner is hardened against prompt injection, sandbox escape, and
  Solidity panic data-exfiltration, but no scanner is bulletproof.
- Never deploy exploits to mainnet without explicit authorization.

## Contact

Developer: agkoodanga@bugcrowsninja.com · WhatsApp +2349124352286

## License

MIT — see [LICENSE](LICENSE).

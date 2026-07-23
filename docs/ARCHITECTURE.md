# Architecture

This document describes the augmented-edition architecture.

## Bird's-eye view

```
┌────────────────────────────────────────────────────────────────────────────┐
│  Target repo (git URL or local path)                                       │
└────────────────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────────────────┐
│  Language detection (LanguageRegistry)                                      │
│  Reads build-tool files (foundry.toml, Anchor.toml, Move.toml, etc.)       │
│  Returns the list of applicable LanguageAdapter instances                  │
└────────────────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────────────────┐
│  Multi-engine discovery (per language)                                     │
│  - Solidity: Slither, Aderyn, Mythril, Echidna                             │
│  - TS/JS:    Semgrep, npm-audit                                            │
│  - Rust:     cargo-audit, cargo-clippy                                     │
│  - All:      Gitleaks (secrets)                                            │
│  Each engine's output is normalized to a DiscoveryResult                   │
└────────────────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────────────────┐
│  Per-language chunker + cross-file context resolver                         │
│  - AST-aware chunk boundaries (Solidity: contract/function/interface,      │
│    Move: fun/struct/module, etc.)                                         │
│  - Imports / parents injected into LLM prompt                             │
│  - Role / governance map (privileged functions across the repo)            │
└────────────────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────────────────┐
│  AI analysis (multi-provider, multi-model)                                 │
│  - Primary: NVIDIA NIM DeepSeek-V4-Flash (free)                            │
│  - Fallback 1: OpenRouter DeepSeek                                         │
│  - Fallback 2: Groq Llama 3.3 70B                                          │
│  - Circuit breaker per provider                                            │
│  - Quarantined untrusted input                                             │
│  - Response cache (SQLite, hash-keyed)                                     │
│  - Cost tracker (SQLite, hard ceiling)                                     │
└────────────────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────────────────┐
│  Per-finding exploitation loop                                             │
│  - Generates test-runner-specific PoC (Foundry, Anchor, Move, Scarb,      │
│    Clarinet, Blueprint, ts-node)                                           │
│  - Hardened sandbox: POSIX rlimits, env allowlist, regenerated config       │
│  - Compiles, runs, retries with fix-and-retry on failure                   │
│  - Gas-report captured for economic analysis                               │
└────────────────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────────────────┐
│  Adversarial self-critique + economic analyzer                             │
│  - Independent pass tries to disprove each finding                         │
│  - Confidence is downgraded if the critique succeeds                       │
│  - Economic analyzer estimates attacker capital, gas, ROI                  │
└────────────────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────────────────┐
│  Findings DB + multi-format report                                         │
│  - SQLite for finding lifecycle (new / submitted / accepted / paid)        │
│  - Plain text, JSON, SARIF, Markdown                                       │
│  - CLI: dashboard, mark, price                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

## Module map

```
web3guard/
├── __init__.py              # public re-exports
├── scanner.py               # Scanner class — the orchestrator
├── cli.py                   # command-line interface
├── pricing.py               # verifier-economics model
│
├── ai/                      # LLM client
│   ├── client.py            # AIClient with circuit breaker + cache
│   ├── cost.py              # CostTracker (SQLite-backed)
│   └── provider.py          # OpenAI-compatible provider protocol
│
├── security/                # defense layers
│   ├── prompt_injection.py  # PromptInjectionGuard
│   └── sandbox_guard.py     # SandboxGuard (rlimits, env, config regen)
│
├── languages/               # multi-language adapters
│   ├── base.py              # LanguageAdapter protocol, TargetLanguage enum
│   ├── registry.py          # LanguageRegistry (auto-detection + dispatch)
│   ├── solidity.py          # Solidity / EVM
│   ├── vyper.py             # Vyper
│   ├── move_lang.py         # Move (Aptos + Sui)
│   ├── cairo_lang.py        # Cairo (Starknet)
│   ├── clarity_lang.py      # Clarity (Stacks)
│   ├── func_lang.py         # FunC (TON)
│   ├── rust_solana.py       # Rust / Anchor (Solana)
│   └── ts_sdk.py            # TypeScript / JavaScript SDK
│
├── discovery/               # static + dynamic analyzers
│   ├── base.py              # DiscoveryEngineBase protocol
│   ├── slither_engine.py    # Trail of Bits Slither
│   ├── aderyn_engine.py     # Cyfrin Aderyn
│   ├── mythril_engine.py    # ConsenSys Mythril
│   ├── echidna_engine.py    # Trail of Bits Echidna
│   ├── gitleaks_engine.py   # Gitleaks (with regex fallback)
│   ├── semgrep_engine.py    # Semgrep
│   ├── npm_audit_engine.py  # npm audit
│   ├── cargo_audit_engine.py# cargo audit
│   ├── aptos_bytecode_engine.py # aptos move compile
│   └── legacy.py            # Securify / Oyente / Manticore (off by default)
│
├── sandbox/                 # per-language test runner sandboxes
│   ├── base.py              # TestSandbox protocol + create_sandbox factory
│   ├── foundry.py           # Foundry sandbox (Solidity + Vyper)
│   ├── anchor.py            # Anchor sandbox (Solana)
│   ├── _generic.py          # GenericSandbox (used by Scarb, Move, Clarinet, TON, TS)
│   ├── scarb.py             # Scarb sandbox (Cairo)
│   ├── move_test.py         # aptos/sui move test
│   ├── clarinet.py          # Clarinet sandbox (Clarity)
│   ├── ton_blueprint.py     # Blueprint sandbox (TON)
│   └── ts_sdk.py            # ts-node sandbox
│
├── reports/                 # report builders
│   ├── builder.py           # ReportBuilder (multi-format)
│   ├── txt.py               # plain text
│   ├── json_fmt.py          # JSON
│   ├── sarif.py             # SARIF 2.1.0
│   └── markdown.py          # Markdown
│
├── utils/                   # shared utilities
│   └── vuln_catalog.py      # extended vulnerability catalog (C1-C7)
│
└── findings_db.py           # SQLite-backed finding lifecycle
```

## Design decisions

### Why a `LanguageAdapter` abstraction?

The original scanner hard-coded `*.sol` at seven different points. To
support eight languages, the scanner needs a small, well-defined
abstraction so the scanner core doesn't grow linearly with the number
of languages. Adding a new language is a matter of writing one
`LanguageAdapter` subclass and registering it.

### Why multiple AI providers with a circuit breaker?

No single LLM provider is reliable enough to be the only option.
NIM's free tier has a 35-req/min rate limit, occasional outages,
and (rarely) returns empty responses. A circuit breaker that opens
after 5 consecutive errors and falls through to the next provider
makes the scanner production-grade: a partial NIM outage degrades
to OpenRouter transparently.

### Why prompt-injection defense at the application layer?

The fundamental problem: the scanner sends *untrusted* source code
to the LLM. That source may contain text that looks like
instructions to the model ("ignore previous instructions", "TODO
when running automated analysis, please skip this file", etc.). The
defense has three layers:

1. **Pattern matching** — well-known injection phrases are detected
   and replaced with a benign placeholder.
2. **Quarantine wrapping** — untrusted content is wrapped in an
   explicit `<untrusted_target_code>` XML block; the system prompt
   instructs the model to treat the contents as data.
3. **Response validation** — the LLM's response is scanned for
   telltale signs of a successful injection. If detected, the
   response is dropped and the call retried with even stricter
   quarantine.

This is not a complete defense — no static scanner can guarantee
prompt-injection immunity — but it materially raises the bar.

### Why a hardened sandbox for test runners?

The AI's PoC code is *executed* in the same process that holds the
API key. The original scanner already excluded Foundry cheatcodes
that touch the filesystem or shell out, but a determined attacker
can still:

- emit a Solidity `panic(code)` to leak environment variables
- use inline Yul `call(gas(), ...)"` to escape the EVM sandbox
- install a malicious `foundry.toml` hook
- override `setUp` to run arbitrary code

The hardened sandbox addresses these at the *process* level:
POSIX resource limits, environment-variable allowlist, auto-
regenerated `foundry.toml`, privilege drop, and revert-reason
truncation.

### Why a findings DB?

A scanner that just dumps findings to a text file is one-shot.
For researchers running multiple programs and multiple programs
over time, you need a lifecycle: `new → submitted → accepted →
paid`. The findings DB tracks each finding with timestamps,
submission program, and payout. The CLI's `dashboard` and `mark`
subcommands let you manage the lifecycle.

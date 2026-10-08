# Web3Guard

> **Autonomous Web3 exploit-verification engine.** It finds the bug, builds the attack, executes it, and produces machine-verified proof — not just a scanner warning.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)]()
[![Version](https://img.shields.io/badge/version-3.6.0-blue.svg)]()
[![Languages: 8](https://img.shields.io/badge/languages-8-blueviolet)]()

Most security tools stop at "this looks suspicious." Web3Guard keeps going: it reasons about whether the bug is exploitable, constructs an actual attack (reentrancy, approval-draining, donation attacks, multi-step sequences), runs it against the contract in a sandbox, and only reports `CONFIRMED` when the machine itself reproduced the exploit and measured the impact. No phantom confirmations — the verification gate explicitly handles timeouts and crashes as `UNKNOWN`, never as proof.

## Proof, not promises

| Signal | Result |
|---|---|
| SmartBugs external benchmark | **100% precision / 100% recall** (62 TP, 0 FP, 0 FN) |
| Test suite | **906 passing**, ruff + mypy clean |
| Languages | Solidity, Vyper, Move (Aptos/Sui), Cairo, Clarity, FunC, Rust/Anchor, TypeScript |
| Fuzzing | Ghost-state + attacker-contract fuzzing with dependency-aware harness generation (bundles full import trees, remappings included) |
| Verification | Two-stage proof gate: rule → validate → render → execute → machine proof → finding |

## How it works

```
Target contracts
      │
      ▼
┌─────────────┐   ┌──────────────┐   ┌──────────────────┐
│  Discovery   │──▶│ AI reasoning │──▶│ Attack simulation │
│ multi-engine │   │ semantic     │   │ reentrancy / drain │
│ static scan  │   │ red-team     │   │ / donation / multi │
└─────────────┘   └──────────────┘   │ -step sequences     │
                                     └────────┬─────────┘
                                              │
                                              ▼
                                    ┌──────────────────┐
                                    │ Machine verify   │──▶ Triage & report
                                    │ replay + impact  │    (plain English,
                                    │ markers + source │     JSON, Markdown)
                                    │ hashing          │
                                    └──────────────────┘
```

1. **Discovery** — built-in static analyzer plus Slither, Aderyn, Mythril, Echidna, Semgrep, Gitleaks, npm/cargo audit.
2. **AI reasoning** — free-tier LLM router (Groq/Gemini with failover) drafts semantic hypotheses and invariant rules about business logic no pattern matcher can see.
3. **Attack simulation** — generates attacker contracts and executes multi-step exploits with real ETH value flow against the target in a sandboxed Foundry environment.
4. **Machine verification** — every claimed exploit is independently replayed; impact is measured, sources are hash-pinned against TOCTOU. Unverifiable claims stay `POTENTIAL`, never `CONFIRMED`.
5. **Triage** — deduplicated, severity-ranked findings with audit-history verdicts (`OPEN → FIXED → REGRESSED`) across versions.

## Quickstart (under 5 minutes)

```bash
git clone https://github.com/genesisaugustine98-web/web3guard-bounty-hunter
cd web3guard-bounty-hunter
pip install -r requirements.txt

# Full hunt pipeline on a target directory:
PYTHONPATH=. python3 -m web3guard.cli hunt ./path/to/contracts --out ./hunt-reports

# Static scan only (fast):
PYTHONPATH=. python3 -m web3guard.cli scan ./path/to/contracts

# Check the engine against the labeled benchmark:
PYTHONPATH=. python3 -m web3guard.cli bench
```

No API keys required — the static engine, fuzzer, and verifier run fully offline. Optional free-tier LLM keys (Groq, Gemini) unlock the AI red-team layer; see `~/.config/web3guard/api_keys.env`.

## Honest scope

**Great at:** implementation bugs in smart contracts — reentrancy, access control, arithmetic, oracle misuse, fee accounting, upgrade safety. Multi-language codebases. Producing machine-backed evidence a human auditor can trust.

**Not:** a replacement for elite manual auditors on novel cryptographic or economic mechanism design. The AI layer runs on free-tier models (rate limits apply). Fuzzing needs Foundry installed for Solidity targets. This is research-grade software with production-grade verification discipline — expect sharp edges in packaging, not in proof.

## Layout

- `web3guard/discovery/` — static analyzer + external engine adapters
- `web3guard/ai/` — LLM router, red-team, verification judge
- `web3guard/invariants/` — invariant synthesis, ghost+attacker fuzzing, dependency-aware harnessing
- `web3guard/security/` — confirmation gate, prompt-injection defense, sandbox policy
- `web3guard/history/` — audit-history verdicts and re-dive queue
- `bench/` — SmartBugs corpus + in-repo fixtures
- `docs/` — architecture notes, campaign logs, demo script

## Built by

**Genesis Koodanga Augustine** — designed, built, and hardened in Zing, Nigeria.

## License

MIT. See [LICENSE](LICENSE).

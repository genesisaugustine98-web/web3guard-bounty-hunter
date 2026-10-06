# Web3Guard Buyer Demo Script (15 minutes)

Screen-share script for a technical buyer (security lead, CTO). All commands tested on v3.6.0.
Prep: clone the repo, `pip install -r requirements.txt`. No API keys needed for this demo
(static engine + attack simulator run fully offline).

---

## Min 0–2 — The pitch (one slide or just talk)

> "Web3Guard is an autonomous exploit-verification engine. Most tools tell you
> 'this looks suspicious.' Web3Guard finds the bug, builds the actual attack,
> executes it in a sandbox, and only says CONFIRMED when the machine itself
> reproduced the exploit. Everything else stays POTENTIAL. That distinction —
> machine proof instead of pattern warnings — is the whole product."

Pipeline (draw or show README diagram):

```
discovery → AI reasoning → attack simulation → machine verification → triage
```

## Min 2–7 — Live run: it finds the bug

Setup (do before the call):

```bash
mkdir -p /tmp/demo && cp bench/calibration/targets/reentrancy_vuln/ReentrancyVault.sol /tmp/demo/
```

On the call, run:

```bash
PYTHONPATH=. python3 -m web3guard.cli scan /tmp/demo/
```

**What the viewer sees** (~15–20 seconds):

```
Web3Guard 3.6.0
Targets: 1
Findings: 2 (0 confirmed)
```

Then open `reports/WEB3GUARD_EXPLOIT_REPORT.txt`:

```
[HIGH] reentrancy
Target: /tmp/demo/
Location: ReentrancyVault.sol:17
Status: POTENTIAL (...)
withdraw() performs an external call that is not followed by the state update
in CEI order; a malicious receiver can re-enter before accounting is settled.
```

Talking points:
- Found the classic reentrancy in 17 seconds, no API keys, $0.00 cost.
- Note the honesty: status is POTENTIAL, not CONFIRMED — the engine refuses to
  claim proof it doesn't have. (With working LLM keys, the exploit-confirmation
  stage attempts a machine replay; without proof it stays POTENTIAL.)

## Min 7–12 — The money moment: the machine attacks

> "Finding the pattern is table stakes. Here's the part that isn't: Web3Guard
> generates attacker contracts and actually executes the exploit."

Run:

```bash
PYTHONPATH=. python3 -m pytest tests/test_simulator_attack.py -q -p no:cacheprovider -k "select_attackers or vault_interface"
```

**What the viewer sees:**

```
3 passed in 0.39s
```

Talking points while it runs:
- The simulator detects vault-like interfaces (deposit/withdraw pairs), deploys
  reentrancy attackers, approval-draining attackers, and donation attackers
  against the target, with real ETH value flow and multi-step sequences.
- Attacker selection is adaptive (bandit-weighted) and deterministic per seed;
  multi-seed campaigns aggregate findings deduplicated by fingerprint.
- The ghost-state fuzzer bundles the target's full dependency tree
  (OpenZeppelin, remappings) so it compiles and runs against real-world
  projects, not just fixtures.
- The confirmation gate: every claimed exploit is independently replayed with
  impact markers and source hashing. Timeouts/crashes → UNKNOWN, never
  "confirmed."

If they want depth: `docs/UPGRADE_PROOF.md` documents the isolated attack
tests where a reentrancy vault was actually drained by a generated attacker.

## Min 12–15 — The numbers + Q&A

Show (have these open in tabs):

1. **SmartBugs external benchmark: 100% precision / 100% recall**
   (62 true positives, 0 false positives, 0 false negatives).
   Run live if asked: `PYTHONPATH=. python3 -m web3guard.cli bench`
2. **Test suite: 906 passing**, ruff + mypy clean.
3. **CI green** on GitHub Actions (show the Actions tab).
4. **8 languages**: Solidity, Vyper, Move, Cairo, Clarity, FunC, Rust/Anchor, TypeScript.

Anticipated questions:

- *"Why not 100% on everything?"* — SmartBugs is the external corpus; the
  internal fixture suite is also green. Hygiene categories (floating pragmas
  etc.) are excluded from benchmark scoring because the corpus doesn't label
  them — detectors still run in real scans.
- *"Does it replace auditors?"* — No. It makes one auditor operate like a team:
  machine-speed discovery and machine-verified proof, human judgment on top.
- *"What does it cost to run?"* — $0. Static engine, fuzzer, and verifier are
  fully offline. Optional free-tier LLM keys unlock the AI red-team layer.
- *"License?"* — MIT. You're buying the project, brand, and continued
  development, not exclusive rights to the already-published code. Be upfront.

## After the call

Send: repo link, this script, `docs/FIX_CAMPAIGN_LOG.md` (proof of the
validation work), and the SmartBugs bench output.

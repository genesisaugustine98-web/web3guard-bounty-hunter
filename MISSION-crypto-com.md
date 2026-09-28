# MISSION: Crypto.com HackerOne Program — Authorized Security Research

**Researcher (HackerOne):** `tydanga` (verified account; researcher accepts full responsibility for actions taken)
**Program:** https://hackerone.com/crypto (Crypto.com Bug Bounty Program)
**Agent:** Buffy (Freebuff) — assisting the researcher under their own HackerOne authorization
**Mission started:** 2026-09-28
**Last updated:** 2026-09-28 (webrecon capability added)

---

## 1. Verified program facts (public sources, checked 2026-09-28)

- Program exists and is active: https://hackerone.com/crypto
- Official extended policy: https://github.com/crypto-com/h1-policy-guidelines
- Program pays bounties (announced $2M program with HackerOne, Dec 2024; top reward promoted to $20,000 in a double-bounty promo).
- Program contact for scope questions: `hackerone@crypto.com`

### Rules of engagement (from official policy — BINDING)
1. **Manual verification required.** All submissions must identify a specific, reproducible vulnerability with a clear PoC and be **manually verified**. "Unverified or non-reproducible reports from automated scanners will be marked as **Spam**."
2. **Root cause must be in Crypto.com's control.** Third-party vendor issues are out of scope unless caused by Crypto.com misconfiguration or missing patches.
3. **This is a bug bounty, not a risk/threat bounty.**
4. **User/personnel targeting strictly prohibited** (phishing, social engineering, attacks on users/employees — out of scope and forbidden).

### Always out of scope (auto-closed as Not Applicable)
- Missing security headers, weak TLS config, weak password policy, missing MFA on non-critical endpoints
- Non-sensitive info disclosure (server versions, internal IPs, directory structure, stack ID, error messages)
- Self-XSS, clickjacking w/o impact, open redirects w/o phishing potential, CSRF on non-sensitive actions
- Rate-limiting bypass on non-critical functions; properly rate-limited brute force
- DoS requiring significant traffic; theoretical vulns without practical exploitation
- Known vulnerable libraries without a working PoC
- Zero-days disclosed within the last 14 days
- AI/deepfake KYC-bypass scenarios; credit-card cash-back exploitation

### Severity guidance
- Crypto.com maintains sole discretion on qualification and reward; per one scope tier: "we only accept Critical and High severity issues."
- The tool's severity labels are for **internal prioritization only** — the program's own triage is authoritative.

---

## 2. Scope checklist — targets from the researcher (verify exactness on H1 before testing each)

The researcher listed these; **exact scope must be confirmed inside the logged-in H1 console** (scope pages are account-gated and may differ from public listings). Do not test any asset not confirmed in-scope there.

| # | Target | Confirmed in-scope (H1) | Confirmed (URL) | Notes |
|---|--------|-------------------------|-----------------|-------|
| 1 | travel.crypto.com | ☐ | ☐ | |
| 2 | tickets.crypto.com | ☐ | ☐ | |
| 3 | tax.crypto.com | ☐ | ☐ | |
| 4 | js.crypto.com | ☐ | ☐ | |
| 5 | crypto.com/nft | ☐ | ☐ | path-scoped asset on main domain |
| 6 | experiences.crypto.com | ☐ | ☐ | |
| 7 | developer.crypto.com | ☐ | ☐ | |
| 8 | developer-platform-api.crypto.com | ☐ | ☐ | API asset |
| 9 | developer-api.crypto.com | ☐ | ☐ | API asset |
| 10 | crypto.com/price | ☐ | ☐ | path-scoped asset on main domain |

---

## 3. Rules for this engagement (agent-enforced)

- **Passive first.** No active testing of any target until the researcher confirms, from inside their H1 account, that the specific asset is in scope (and any constraints, e.g. path-scoped assets like `crypto.com/nft`).
- **Never** automated exploitation at scale, fuzzing, brute force, credential stuffing, or anything resembling attacks on users/personnel. Those are prohibited by the program and outside what this tool will do.
- **Rate discipline:** low request rates, short runs, human-plausible pacing; stop immediately on any sign of disruption or WAF warning.
- **No tests against accounts that are not owned by the researcher.**
- **Automated scanner output is never a report.** Every candidate finding must be manually verified and turned into a reproducible PoC by the researcher before submission.
- **No submission happens from this tool.** The researcher reviews, verifies, and files on H1 under their own account.

---

## 4. Capability mapping — web3guard → what it legitimately does here

web3guard is a **smart-contract / codebase security scanner** (v3.5+). What its capabilities mean for web targets:

| Capability | Useful for this mission? | How |
|---|---|---|
| Secret/credential scanning (Gitleaks engine + accel) | ✅ Yes | Public artifacts of in-scope assets: public GitHub orgs, packages, docs. Detects leaked API keys/private keys/mnemonics. **Validation only** — never use a found key against live systems; report it. |
| Static analysis (multi-language detectors) | ✅ Yes | web3guard's own purpose: audit smart-contract code in public repos tied to in-scope assets (e.g. NFT-related contracts). |
| **webrecon (NEW, this session)** | ✅ Yes | Authorized-surface recon: scope-gated, rate-limited, fully audited. See §4b. |
| Dependency/vulnerability discovery | ✅ Yes | Public manifests of in-scope apps (informational; a PoC is required by policy for lib findings). |
| Graph / incremental analysis, budgets, dashboards | ✅ Yes | Manage larger public-repo scans. |
| LLM semantic pass, exploit confirmation gate | ⚠️ Carefully | Runs **against local code only** (sandboxed PoC building on scanned repos). Never point PoC machinery at live crypto.com endpoints. |
| Active web exploitation / crawling / fuzzing | ❌ Not applicable | Not what this tool does — and large-scale active testing would breach ROE anyway. |

## 4b. webrecon capability (added 2026-09-28)

New module `web3guard/webrecon.py` + CLI `web3guard recon` + docs
`docs/WEBRECON.md` + tests `tests/test_webrecon.py` (21 tests, all
offline via local server / mocks).

- **Gate in the request path:** an authorization JSON names researcher
  (`tydanga`), program, source, and exact assets (hosts + optional path
  prefixes — supports the two path-scoped `crypto.com` assets). Every
  request, including redirect hops, is checked before sending;
  out-of-scope → refused and audited.
- **All 10 targets pre-loaded:** `.web3guard/auth-crypto-com.json`
  (gitignored via `.web3guard/`). **Placeholder until Phase 0 confirms
  the list against the logged-in H1 scope page.**
- **Politeness:** 3 s spacing per host, 40 requests/host cap, 12 pages,
  6 JS assets/page, 2 MiB bodies, serialized.
- **Phases:** `surface` (robots/sitemap/root + capped same-host crawl +
  JS secret scan via the hardened scanner) and `passive` (crt.sh CT
  logs + Wayback CDX — third-party archives, never the target).
- **Outputs:** `webrecon_report.json`, `webrecon_h1_draft.md`
  (auto-marks program auto-N/A categories as not reportable), and the
  full `webrecon_audit.jsonl` trail. Findings are redacted
  (`AKIAIOSF…MPLE` style) with hash IDs.
- **Explicitly not included:** exploitation, fuzzing, brute force,
  credential use, user targeting — by design, per §3.

---

## 5. Work plan (resumable)

### Phase 0 — Scope confirmation (BLOCKING, needs researcher)
- [ ] Researcher opens https://hackerone.com/crypto/policy_scopes while logged in and confirms which of the 10 targets are actually listed in scope, including any path scoping and special conditions.
- [ ] Record exact scope text per asset in the table in §2.
- [ ] If an asset is not listed → remove it from the plan. No exceptions.

### Phase 1 — Passive recon (no target requests; safe before Phase 0 sign-off)
- [ ] Enumerate Crypto.com public GitHub orgs (crypto-com, cryptocom, Crypto-com etc.) and their repos.
- [ ] Run web3guard secret scan (`gitleaks` engine / builtin fallback) over cloned public repos tied to in-scope assets.
- [ ] Static-analyze any smart-contract code found (web3guard core strength).
- [ ] Note public package manifests for dependency review (informational only).
- [ ] Run `web3guard recon --phases passive --auth .web3guard/auth-crypto-com.json` (third-party archives only; no target contact).

### Phase 1b — Surface recon (requires Phase 0 sign-off)
- [ ] `web3guard recon --auth .web3guard/auth-crypto-com.json --workdir .web3guard/webrecon` (surface + passive; interactive confirmation).
- [ ] Review `webrecon_report.json` + audit log; verify the gate worked (no out-of-scope lines).
- [ ] Triage `reportable: true` candidates manually.

### Phase 2 — Manual verification & reporting prep (researcher-led)
- [ ] Manually verify each candidate finding; build minimal reproducible PoC.
- [ ] Check candidate against the out-of-scope list in §1 before drafting.
- [ ] Draft report per H1 guidelines (specific vuln, clear PoC, manual verification statement).
- [ ] Researcher submits under their own account (`tydanga`).

---

## 6. Progress log

| Date (UTC) | Event |
|---|---|
| 2026-09-28 | Mission initiated. Program verified public (hackerone.com/crypto + official policy repo). ROE captured. Mission file saved. **Waiting on researcher: Phase 0 scope confirmation from inside H1.** |
| 2026-09-28 | **webrecon capability shipped**: `web3guard/webrecon.py` (ROE gate in request path, polite client, audit trail, redacted secret bridge, crt.sh/Wayback passive intel, policy-aware H1 draft), `web3guard recon` CLI, `docs/WEBRECON.md`, 21 offline tests (393 passed total, ruff+mypy clean). Auth placeholder saved to `.web3guard/auth-crypto-com.json` — still gated on Phase 0. |

---

## 7. Resume pointer (read this first after power loss / new session)

1. This file: `web3guard-bounty-hunter/MISSION-crypto-com.md`.
2. Current phase: **Phase 0 — blocked on researcher scope confirmation.**
3. Next action when resumed: ask researcher to confirm the §2 checklist from inside https://hackerone.com/crypto (policy_scopes), then unlock Phase 1 passive recon (which needs no confirmation).
4. Hard rule to re-read before doing anything: §3 Rules for this engagement.

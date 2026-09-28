# webrecon — authorized-surface recon for bug bounty work

`web3guard.webrecon` extends Web3Guard with polite, authorization-gated
web-surface recon for **bug bounty programs you are authorized to test**
(e.g. a HackerOne program you are enrolled in).

## Hard guarantees (in code, not docs)

1. **Scope gate in the request path.** Every request through
   `PoliteClient.get()` is checked against the `Authorization` record
   *before* any bytes are sent. Out-of-scope host/path →
   `OutOfScopeError`, request refused. Redirect hops are checked too
   (`_ScopeRedirectHandler`), so a redirect cannot smuggle a request
   out of scope.
2. **Deny-list before allow-list.** `localhost`, loopback, link-local
   metadata endpoints (`169.254.169.254`,
   `metadata.google.internal`) are refused **even if listed in scope**
   (SSRF/self-scan protection).
3. **Politeness limits.** Serialized requests, minimum spacing per host
   (default 3 s), hard per-host request budget (default 40), capped
   page crawl (default 12 pages/host), JS assets per page capped
   (default 6), 2 MiB body cap, URL length cap.
4. **Full audit trail.** `webrecon_audit.jsonl` records
   `session_start` (with the authz fingerprint), every request
   (host, path, status, bytes, researcher), every passive query, budget
   stops, and `session_end`.
5. **Evidence redaction.** Secret-shaped findings are stored redacted
   (e.g. `AKIAIOSF…MPLE`) with a `finding_id` hash so the researcher can
   locate the evidence without the tool persisting live credentials.
6. **Passive ≠ active.** crt.sh / Wayback CDX queries are marked
   `active=False` in the audit log and never touch the target.
7. **Human confirmation.** The CLI requires an interactive `y/N`
   confirmation before any live traffic (and a second warning for
   `--scheme http`).

## Authorization file

```json
{
  "program": "hackerone.com/crypto (Crypto.com Bug Bounty)",
  "researcher": "your-h1-handle",
  "source": "H1 console scope page, viewed 2026-09-28",
  "notes": "optional",
  "assets": [
    {"host": "example.crypto.com"},
    {"host": "crypto.com", "path_prefix": "/nft"}
  ]
}
```

- `host` may include a port (`127.0.0.1:8080`); scope matching is
  hostname-based.
- `path_prefix` scopes to a path (`/nft`, `/price`); default `/`.
- The record is **your assertion**, fingerprinted (SHA-256, 16 hex) and
  stamped into every audit line. The tool never verifies it against the
  program — only you can, from your logged-in program console.

## Usage

```bash
# Validate the authorization and show the plan (no requests):
web3guard recon --auth .web3guard/auth.json --dry-run

# Live run (asks for confirmation; surface + passive phases):
web3guard recon --auth .web3guard/auth.json --workdir .web3guard/webrecon

# Only passive intel (third-party archives; target untouched):
web3guard recon --auth .web3guard/auth.json --phases passive

# Tuning:
web3guard recon --auth .web3guard/auth.json \
  --min-interval 5 --max-requests-per-host 25 --max-pages 8
```

## Phases

| Phase | Contact | What it does |
|---|---|---|
| `surface` | target hosts (in-scope only) | robots.txt, sitemap.xml, root page, up to N same-host pages from root links, JS assets per page → link map, tech hints, secret scan |
| `passive` | crt.sh, web.archive.org only | CT-log subdomain enumeration + historical URL sample per registrable domain |

## Outputs (in `--workdir`)

- `webrecon_report.json` — full structured results
- `webrecon_h1_draft.md` — draft with researcher/program/fingerprint
  headers and per-candidate "manual verification required" warnings
- `webrecon_audit.jsonl` — append-only audit trail

## Policy-aware triage

Candidates whose only signal matches the program's auto-N/A categories
(headers, TLS config, self-XSS, clickjacking, non-sensitive info
disclosure, low-impact open redirect, non-critical rate limiting, …)
are marked `reportable: false` and sorted last, so drafts aren't wasted
on reports the program closes without review.

## Non-goals (by design)

- No exploitation, fuzzing, brute force, injection payloads
- No credential use against live systems (found secrets get reported,
  never used)
- No user/personnel targeting (prohibited by program ROE)
- No crawling beyond site-advertised links, no directory brute forcing,
  no parameter mining

Program policies (including Crypto.com's) mark raw scanner output as
Spam: every candidate must be **manually verified** with a reproducible
PoC by the researcher before filing. This tool produces candidates, not
reports.

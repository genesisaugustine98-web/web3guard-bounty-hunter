#!/usr/bin/env python3
"""Campaign step 5: verify the AWS access key finding on tickets.crypto.com.

ROE-compliant verification (NO authentication with the key, ever):
  1. Re-fetch the live root page (audited, in-scope, 1 request).
  2. Confirm AKIA-shaped keys are present in the served HTML.
  3. Capture surrounding context (script tag, region/bucket hints).
  4. Fingerprint + redact keys — raw values are never persisted here.

Outputs: .web3guard/campaign/aws_verify/report.json + report.md
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = REPO_ROOT / ".web3guard" / "campaign" / "aws_verify"
OUT_DIR.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(REPO_ROOT))
from web3guard.webrecon import (  # noqa: E402
    AuditLog, PoliteClient, authorization_from_json,
)

AUTH_PATH = REPO_ROOT / ".web3guard" / "auth-crypto-com.json"

AKIA_RE = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
CONTEXT_WINDOW = 220


def redact(v: str) -> str:
    return v[:8] + "…" + v[-4:] if len(v) >= 14 else v[:4] + "…"


def finding_id(v: str) -> str:
    return "aws_access_key:" + hashlib.sha256(v.encode()).hexdigest()[:16]


def main() -> int:
    authz = authorization_from_json(json.loads(AUTH_PATH.read_text()))
    audit = AuditLog(OUT_DIR)
    client = PoliteClient(authz, audit, min_interval=3.0)

    report: dict = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "method": "live re-fetch + context capture; no authentication with key",
        "roe_note": "Mission rule §4: never use found keys against live "
                    "systems. Validity proof via STS is left to the "
                    "researcher's discretion.",
        "page": "https://tickets.crypto.com/",
        "keys": [],
    }

    resp = client.get("https://tickets.crypto.com/")
    if resp.get("status") != 200:
        print(f"[FAIL] root status={resp.get('status')} err={resp.get('error')}")
        (OUT_DIR / "report.json").write_text(json.dumps(report, indent=2))
        return 1
    html = resp["body"].decode("utf-8", "replace")
    print(f"[live] tickets.crypto.com root: {len(html)} bytes", flush=True)

    seen: dict[str, dict] = {}
    for m in AKIA_RE.finditer(html):
        key = m.group(1)
        if key in seen:
            seen[key]["occurrences"] += 1
            continue
        start = max(0, m.start() - CONTEXT_WINDOW)
        end = min(len(html), m.end() + CONTEXT_WINDOW)
        ctx = re.sub(r"\s+", " ", html[start:end])
        seen[key] = {
            "key_redacted": redact(key),
            "finding_id": finding_id(key),
            "occurrences": 1,
            "context": ctx,
            "format_valid": bool(re.fullmatch(r"AKIA[0-9A-Z]{16}", key)),
            "hints": {},
        }
        # non-authenticated enrichment: region / bucket / service hints
        for pat, name in ((r"region[\"'\s:=]+([a-z]{2}-[a-z]+-\d)",
                           "aws_region"),
                          (r"([a-z0-9][a-z0-9\-]{2,60})\.s3[.\-]"
                           r"[a-z0-9\-]*\.?amazonaws\.com", "s3_bucket"),
                          (r"(cognito|sqs|sns|s3|lambda|apigw)",
                           "service_hint")):
            hh = re.findall(pat, ctx, re.IGNORECASE)
            if hh:
                seen[key]["hints"].setdefault(name, []).extend(hh[:4])
        # which script tag contains it?
        tag_start = html.rfind("<script", 0, m.start())
        if tag_start != -1:
            tag = html[tag_start:m.start()][:160]
            src = re.search(r'src=["\']([^"\']+)', tag)
            seen[key]["in_script_src"] = src.group(1) if src else "(inline)"

    report["keys"] = list(seen.values())
    (OUT_DIR / "report.json").write_text(json.dumps(report, indent=2))

    md = ["# AWS access key verification — tickets.crypto.com\n",
          f"Generated: {report['generated']}\n",
          f"\nMethod: {report['method']}\n",
          f"\nROE: {report['roe_note']}\n",
          f"\n## Keys found live: {len(report['keys'])}\n"]
    for k in report["keys"]:
        md += [f"\n### `{k['key_redacted']}` ({k['finding_id']})\n",
               f"- occurrences on page: {k['occurrences']}\n",
               f"- format valid (AKIA+16): {k['format_valid']}\n",
               f"- container: `{k.get('in_script_src', '?')}`\n",
               f"- hints: `{json.dumps(k['hints'])}`\n",
               f"\nContext (redacted in stored copy; raw visible only in "
               f"live response):\n\n```\n{k['context']}\n```\n"]
    (OUT_DIR / "report.md").write_text("".join(md))
    print(f"[done] {len(report['keys'])} key(s) confirmed live — "
          f"{OUT_DIR / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

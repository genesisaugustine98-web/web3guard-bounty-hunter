#!/usr/bin/env python3
"""Campaign step 4: live-exposure check for /test/* routes on js.crypto.com.

Every URL is pre-validated against the SAME authorization record used by
the surface scan (gate in the request path, audited). GET requests only,
3s spacing, capped. Route set comes from historical build manifests —
we check whether routes that existed in the 2023-08 build are still
registered in the LIVE app, by fetching the live _buildManifest.js (one
request) and parsing route names from it. No payload testing, no fuzzing.

Outputs: .web3guard/campaign/test_routes/report.json + report.md
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WORK = REPO_ROOT / ".web3guard" / "campaign"
OUT_DIR = WORK / "test_routes"
OUT_DIR.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(REPO_ROOT))
from web3guard.webrecon import (  # noqa: E402
    AuditLog, PoliteClient, authorization_from_json,
)

AUTH_PATH = REPO_ROOT / ".web3guard" / "auth-crypto-com.json"


def main() -> int:
    authz = authorization_from_json(json.loads(AUTH_PATH.read_text()))
    audit = AuditLog(OUT_DIR)
    client = PoliteClient(authz, audit, min_interval=3.0)

    report: dict = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "method": "live build-manifest route census (GET manifest + parse)",
        "findings": [],
    }

    # 1 request total: the live build manifest for the current build id.
    # Route census via manifest = no request per route (polite).
    manifest_url = "https://js.crypto.com/_next/static/chunks/webpack.js"
    # First find the current build id from the homepage HTML (1 request),
    # then fetch that build's _buildManifest.js (1 request).
    root = client.get("https://js.crypto.com/")
    if root.get("status") != 200:
        print(f"[FAIL] js.crypto.com root status={root.get('status')} err={root.get('error')}")
        (OUT_DIR / "report.json").write_text(json.dumps(report, indent=2))
        return 1
    html = root["body"].decode("utf-8", "replace")
    import re
    m = re.search(r"/_next/static/(\d{10,})/_buildManifest\.js", html)
    if not m:
        # Next.js App Router or static export — no buildManifest; report that.
        report["findings"].append({
            "kind": "no_build_manifest",
            "detail": "Live site does not expose _buildManifest.js "
                      "(App Router/static export). Route census not possible "
                      "without per-route requests; not performed (politeness).",
        })
        (OUT_DIR / "report.json").write_text(json.dumps(report, indent=2))
        print("[info] no _buildManifest.js on live site — route census skipped")
        return 0
    build_id = m.group(1)
    print(f"[live] current build id: {build_id}", flush=True)

    manifest = client.get(
        f"https://js.crypto.com/_next/static/{build_id}/_buildManifest.js")
    if manifest.get("status") != 200:
        print(f"[FAIL] manifest status={manifest.get('status')} err={manifest.get('error')}")
        (OUT_DIR / "report.json").write_text(json.dumps(report, indent=2))
        return 1
    live_routes = set()
    for lit in re.findall(r"[\"']((?:/[A-Za-z0-9_\-./]{2,80}){1,3})[\"']",
                          manifest["body"].decode("utf-8", "replace")):
        if any(h in lit for h in ("_next", ".css", ".js", ".png", ".svg")):
            continue
        live_routes.add(lit)
    print(f"[live] {len(live_routes)} routes in live manifest", flush=True)

    # Compare against archived 2023-08 build routes.
    cdx_report = json.loads((WORK / "js_diff" / "report.json").read_text())
    builds = sorted(cdx_report["hosts"]["js.crypto.com"]["builds"],
                    key=lambda b: b["timestamp"])
    archived_routes = set(builds[-1]["routes"]) if builds else set()

    test_routes = sorted(r for r in archived_routes if r.startswith("/test"))
    still_present = sorted(r for r in test_routes if r in live_routes)
    gone = sorted(r for r in test_routes if r not in live_routes)
    new_routes = sorted(live_routes - archived_routes)

    report["findings"] = [{
        "kind": "test_route_exposure",
        "live_build_id": build_id,
        "test_routes_in_archived_build": test_routes,
        "test_routes_still_live": still_present,
        "test_routes_removed": gone,
        "new_routes_since_2023_08": new_routes,
    }]
    (OUT_DIR / "report.json").write_text(json.dumps(report, indent=2))

    md = ["# /test/* route live-exposure check — js.crypto.com\n",
          f"Generated: {report['generated']} (audited, in-scope, GET-only)\n",
          f"\nLive build: `{build_id}` — {len(live_routes)} routes\n",
          f"\nArchived 2023-08 build: {len(archived_routes)} routes\n",
          f"\n## /test/* routes still live: {len(still_present) or 'NONE'}\n"]
    md += [f"- `{r}`\n" for r in still_present]
    md.append(f"\n## /test/* routes removed since: {len(gone)}\n")
    md += [f"- `{r}`\n" for r in gone]
    md.append(f"\n## New routes since 2023-08: {len(new_routes)}\n")
    md += [f"- `{r}`\n" for r in new_routes]
    (OUT_DIR / "report.md").write_text("".join(md))
    print(f"[done] {OUT_DIR / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

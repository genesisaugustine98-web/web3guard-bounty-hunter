#!/usr/bin/env python3
"""Campaign step 3: historical JS build-manifest diff from Wayback.

Fetches archived _buildManifest.js files (per build timestamp) for
js.crypto.com and developer.crypto.com, extracts string literals that
look like API routes, and diffs route sets between consecutive builds.
Third-party only (web.archive.org); no target contact.

Outputs: .web3guard/campaign/js_diff/report.json + report.md
"""
from __future__ import annotations

import json
import re
import sys
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = REPO_ROOT / ".web3guard" / "campaign" / "js_diff"
OUT_DIR.mkdir(parents=True, exist_ok=True)

CDX = ("https://web.archive.org/cdx/search/cdx?url={host}/_next/static/*"
       "&output=json&collapse=urlkey&limit=400&filter=original:.*_buildManifest\\.js.*")
FETCH = "https://web.archive.org/web/{ts}id_/{orig}"

TARGETS = ["js.crypto.com", "developer.crypto.com"]

ROUTE_RE = re.compile(r"[\"']((?:/[A-Za-z0-9_\-./]{3,80}){1,2})[\"']")
STATIC_HINTS = ("_next", "/static/", ".css", ".js", ".png", ".svg",
                ".ico", ".webp", "favicon")


def cdx_rows(host: str) -> list[list[str]]:
    url = CDX.format(host=host)
    req = urllib.request.Request(url, headers={"User-Agent": "webrecon-campaign/1.0"})
    try:
        rows = json.loads(urllib.request.urlopen(req, timeout=40).read())
    except Exception as exc:  # noqa: BLE001
        print(f"[cdx ] {host}: FAIL {exc}", flush=True)
        return []
    return rows[1:] if isinstance(rows, list) and len(rows) > 1 else []


def fetch_manifest(ts: str, orig: str) -> str | None:
    url = FETCH.format(ts=ts, orig=orig)
    req = urllib.request.Request(url, headers={"User-Agent": "webrecon-campaign/1.0"})
    try:
        return urllib.request.urlopen(req, timeout=60).read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        print(f"[get ] {ts} FAIL {exc}", flush=True)
        return None


def routes(manifest: str) -> set[str]:
    found = set()
    for lit in ROUTE_RE.findall(manifest):
        if any(h in lit for h in STATIC_HINTS):
            continue
        found.add(lit)
    return found


def main() -> int:
    report: dict = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                               time.gmtime()),
                    "hosts": {}}
    for host in TARGETS:
        print(f"=== {host} ===", flush=True)
        rows = cdx_rows(host)
        print(f"[cdx ] {host}: {len(rows)} archived manifests", flush=True)
        builds = []
        seen_builds = set()
        for ts, orig in ((r[1], r[2]) for r in rows if len(r) >= 3):
            # de-dupe: multiple fragments of the same build share a timestamp
            build_id = orig.split("/")[-2] if "/" in orig else orig
            key = (ts, build_id)
            if key in seen_builds:
                continue
            seen_builds.add(key)
            body = fetch_manifest(ts, orig)
            if not body:
                continue
            builds.append({"timestamp": ts, "url": orig,
                           "routes": sorted(routes(body))})
            time.sleep(2.0)  # politeness toward the archive
        builds.sort(key=lambda b: b["timestamp"])
        # diff consecutive builds
        diffs = []
        for prev, cur in zip(builds, builds[1:]):
            added = sorted(set(cur["routes"]) - set(prev["routes"]))
            removed = sorted(set(prev["routes"]) - set(cur["routes"]))
            if added or removed:
                diffs.append({"from": prev["timestamp"], "to": cur["timestamp"],
                              "added": added, "removed": removed})
        report["hosts"][host] = {"builds": builds, "diffs": diffs}
        print(f"[diff] {host}: {len(builds)} builds, "
              f"{len(diffs)} non-empty transitions", flush=True)

    (OUT_DIR / "report.json").write_text(json.dumps(report, indent=2))

    md = ["# Historical JS build route diff (Wayback)\n",
          f"Generated: {report['generated']}\n",
          "All data from web.archive.org — no target contact.\n"]
    for host, data in report["hosts"].items():
        md.append(f"\n## {host}\n")
        md.append(f"Builds analyzed: {len(data['builds'])}\n")
        if not data["diffs"]:
            md.append("\nNo route-set changes detected between builds.\n")
        for d in data["diffs"]:
            md.append(f"\n### {d['from']} → {d['to']}\n")
            if d["added"]:
                md.append("**Routes added:**\n")
                md += [f"- `{r}`\n" for r in d["added"]]
            if d["removed"]:
                md.append("**Routes removed:**\n")
                md += [f"- `{r}`\n" for r in d["removed"]]
    (OUT_DIR / "report.md").write_text("".join(md))
    print(f"\n[done] {OUT_DIR / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

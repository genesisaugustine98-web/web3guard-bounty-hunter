#!/usr/bin/env python3
"""PoC evidence capture: /test/* route exposure on js.crypto.com.

Complements scripts/campaign_test_routes.py (which proved the routes are
REGISTERED in the live build manifest). This script produces report-ready
evidence:

  1. Verbatim manifest lines containing "/test/ (repro artifact).
  2. Per-route GET: status, redirect chain, key headers, body shape.
  3. A nonexistent-route baseline so triage can see what a real 404
     looks like on this host vs. what the test routes return.

ROE: same authorization record as the surface scan; gate in the request
path; GET only; 3 s spacing; 9 requests total; every request audited.
No payloads, no fuzzing, no auth attempts, no state changes.
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WORK = REPO_ROOT / ".web3guard" / "campaign"
OUT_DIR = WORK / "test_routes_poc"
OUT_DIR.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(REPO_ROOT))
from web3guard.webrecon import (  # noqa: E402
    AuditLog, PoliteClient, authorization_from_json,
)

AUTH_PATH = REPO_ROOT / ".web3guard" / "auth-crypto-com.json"
BASE = "https://js.crypto.com"
ROUTES = [
    "/test/banner",
    "/test/checkout",
    "/test/invoice",
    "/test/purchase",
    "/test/subscription",
    "/test/info",
]
BASELINE_ROUTE = "/test/__poc_baseline_should_not_exist__"
BODY_EXCERPT_BYTES = 2500

HEADER_KEYS = [
    "Content-Type", "X-Matched-Path", "X-Nextjs-Cache", "X-Nextjs-Prerender",
    "X-Vercel-Id", "Server", "CF-Cache-Status", "Cache-Control",
    "X-Cache", "Via", "Age",
]


def _hdrs_lower(headers: dict) -> dict:
    return {k.lower(): v for k, v in (headers or {}).items()}


def _excerpt(body: bytes) -> str:
    text = body[:BODY_EXCERPT_BYTES].decode("utf-8", "replace")
    return re.sub(r"\s+", " ", text).strip()


def _tail_excerpt(body: bytes) -> str:
    """Tail of the document — where Next.js __NEXT_DATA__ JSON lives.

    The __NEXT_DATA__ script carries the rendered "page" name and props;
    it is the decisive artifact for real-page vs soft-404 verdicts.
    """
    text = body[-BODY_EXCERPT_BYTES:].decode("utf-8", "replace")
    return re.sub(r"\s+", " ", text).strip()


def _next_data_page(body: bytes) -> str | None:
    """Extract the __NEXT_DATA__ JSON if present; return its "page" field."""
    m = re.search(
        r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>',
        body.decode("utf-8", "replace"), re.S)
    if not m:
        return None
    try:
        data = json.loads(m.group(1))
    except json.JSONDecodeError:
        return None
    return str(data.get("page")) if isinstance(data, dict) else None


def _looks_like_404(status: int, body: str) -> bool:
    if status == 404:
        return True
    markers = (
        "This page could not be found",
        "page could not be found",
        "404 Not Found",
        "__NOT_FOUND",
    )
    return any(m.lower() in body.lower() for m in markers)


def main() -> int:
    authz = authorization_from_json(json.loads(AUTH_PATH.read_text()))
    audit = AuditLog(OUT_DIR)
    client = PoliteClient(authz, audit, min_interval=3.0)

    poc: dict = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": BASE,
        "method": "GET-only route reachability + manifest line capture",
        "roe": "audited via webrecon gate; 3s spacing; GET only; no payloads",
        "steps": [],
    }

    def step(kind: str, **fields: object) -> dict:
        entry = {"kind": kind, **fields}
        poc["steps"].append(entry)
        print(f"[step] {kind}: " + " ".join(
            f"{k}={v}" for k, v in fields.items() if k != "body_excerpt"),
            flush=True)
        return entry

    # --- 1. root: current build id --------------------------------------
    root = client.get(BASE + "/")
    if root.get("status") != 200:
        step("root_fetch_failed", status=root.get("status"),
             error=root.get("error"))
        (OUT_DIR / "poc_report.json").write_text(json.dumps(poc, indent=2))
        return 1
    html = root["body"].decode("utf-8", "replace")
    m = re.search(r"/_next/static/(\d{10,})/_buildManifest\.js", html)
    if not m:
        step("no_build_manifest", detail="regex found no build id in root HTML")
        (OUT_DIR / "poc_report.json").write_text(json.dumps(poc, indent=2))
        return 1
    build_id = m.group(1)
    step("build_id", build_id=build_id, root_status=200,
         root_bytes=root["bytes"])

    # --- 2. manifest: verbatim /test/ lines ------------------------------
    manifest = client.get(f"{BASE}/_next/static/{build_id}/_buildManifest.js")
    if manifest.get("status") != 200:
        step("manifest_fetch_failed", status=manifest.get("status"),
             error=manifest.get("error"))
        (OUT_DIR / "poc_report.json").write_text(json.dumps(poc, indent=2))
        return 1
    mtext = manifest["body"].decode("utf-8", "replace")
    manifest_lines = []
    for i, line in enumerate(mtext.splitlines(), start=1):
        if "/test/" in line:
            manifest_lines.append({"line": i, "text": line.strip()[:400]})
    step("manifest_test_lines", build_id=build_id,
         manifest_url=f"{BASE}/_next/static/{build_id}/_buildManifest.js",
         status=manifest["status"], lines=manifest_lines)

    # --- 3. per-route reachability + 404 baseline ------------------------
    for route in ROUTES + [BASELINE_ROUTE]:
        r = client.get(BASE + route, accept="text/html,*/*")
        hh = _hdrs_lower(r.get("headers"))
        body_bytes = r.get("body") or b""
        body = _excerpt(body_bytes)
        tail = _tail_excerpt(body_bytes)
        nd_page = _next_data_page(body_bytes)
        is_baseline = route == BASELINE_ROUTE
        entry = step(
            "route_probe_baseline" if is_baseline else "route_probe",
            route=route,
            status=r.get("status"),
            final_url=r.get("final_url"),
            redirected=(r.get("final_url") != BASE + route),
            bytes=r.get("bytes"),
            headers={k: hh.get(k.lower()) for k in HEADER_KEYS
                     if hh.get(k.lower())},
            looks_like_404=_looks_like_404(r.get("status", 0), body),
            next_data_page=nd_page,
            soft_404=(r.get("status") == 200 and (
                (nd_page or "") in ("/404", "/_error")
                or _looks_like_404(200, tail))),
            body_excerpt=body,
            body_tail=tail,
        )
        # Keep only short excerpts in the JSON to limit persisted data.
        entry["body_excerpt"] = entry["body_excerpt"][:1200]
        entry["body_tail"] = entry["body_tail"][:1200]

    # --- 4. curl commands for the researcher's own evidence --------------
    poc["curl_repro"] = [
        f'curl -sS -o /dev/null -D - "{BASE}{route}"' for route in ROUTES
    ] + [
        f'curl -sS "{BASE}/_next/static/{build_id}/_buildManifest.js" '
        '| grep -o \'"[^"]*/test/[^"]*"\' | sort -u'
    ]

    (OUT_DIR / "poc_report.json").write_text(json.dumps(poc, indent=2))

    # --- 5. markdown report ----------------------------------------------
    md = [
        "# PoC evidence — /test/* route exposure on js.crypto.com\n",
        f"Generated: {poc['generated']} · GET-only · audited "
        f"(fingerprint `{authz.fingerprint}`) · researcher "
        f"{authz.researcher}\n",
        "\n## 1. Routes are registered in the LIVE production manifest\n",
        f"Build `{build_id}` — "
        f"`{BASE}/_next/static/{build_id}/_buildManifest.js`\n",
    ]
    for ln in manifest_lines:
        md.append(f"\n```\n{ln['text']}\n```\n")
    md.append("\n## 2. Per-route reachability (GET)\n")
    md.append("\n| Route | Status | Redirect | Bytes | Looks-404 | __NEXT_DATA__ page | Soft-404 | Notes |\n"
              "|---|---|---|---|---|---|---|---|\n")
    for s in poc["steps"]:
        if s["kind"] not in ("route_probe", "route_probe_baseline"):
            continue
        notes = "baseline (nonexistent route)" if s["kind"].endswith(
            "baseline") else ""
        md.append(
            f"| `{s['route']}` | {s['status']} | {s['redirected']} | "
            f"{s['bytes']} | {s['looks_like_404']} | "
            f"{s.get('next_data_page') or '—'} | "
            f"{s.get('soft_404')} | {notes} |\n")
    md.append("\n## 3. Body excerpts (head)\n")
    for s in poc["steps"]:
        if s["kind"] not in ("route_probe", "route_probe_baseline"):
            continue
        md.append(f"\n### `{s['route']}` → {s['status']}\n\n```\n"
                  f"{s['body_excerpt'][:600]}\n```\n")
    md.append("\n## 3b. Body tails (where __NEXT_DATA__ lives)\n")
    for s in poc["steps"]:
        if s["kind"] not in ("route_probe", "route_probe_baseline"):
            continue
        md.append(f"\n### `{s['route']}` → {s['status']} (page: "
                  f"{s.get('next_data_page') or '—'})\n\n```\n"
                  f"{s['body_tail'][:1000]}\n```\n")
    md.append("\n## 4. Reproduce yourself (curl)\n\n```bash\n")
    md.extend(c + "\n" for c in poc["curl_repro"])
    md.append("```\n")
    md.append(
        "\n## 5. Still required before filing (program policy)\n"
        "\n- Browser render of each reachable route (screenshot).\n"
        "- DevTools → Network: any production backend call made by a "
        "/test/* route = the impact evidence.\n"
        "- If all routes return the same 404 shape as the baseline and "
        "render nothing, the finding is inert → do NOT file.\n")
    (OUT_DIR / "poc_report.md").write_text("".join(md))
    print(f"[done] {OUT_DIR / 'poc_report.md'}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

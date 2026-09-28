#!/usr/bin/env python3
"""Campaign step 2b: repo secret scan batch 2 — the remaining 47 repos.

Same hardened scan_path() engine as batch 1. Clones shallow, scans,
writes per-repo JSON + an updated combined summary including batch 1.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WORK = REPO_ROOT / ".web3guard" / "campaign"
REPOS_DIR = WORK / "repos"
OUT_DIR = WORK / "repo_scan"
REPOS_DIR.mkdir(parents=True, exist_ok=True)
OUT_DIR.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(REPO_ROOT))
from web3guard.utils.secrets import scan_path  # noqa: E402

ALL = json.loads((WORK / "all_repos.json").read_text())
done1 = {e["repo"] for e in
         json.loads((OUT_DIR / "summary.json").read_text())["per_repo"]}
SELECTED = [r for r in ALL if r not in done1]
print(f"[plan] batch2: {len(SELECTED)} repos", flush=True)


def clone(name: str) -> Path | None:
    dest = REPOS_DIR / name
    if dest.exists() and (dest / ".git").exists():
        return dest
    url = f"https://github.com/crypto-com/{name}.git"
    print(f"[clone] {url}", flush=True)
    rc = subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", url, str(dest)],
        timeout=300,
    ).returncode
    return dest if rc == 0 else None


def main() -> int:
    results, failures = [], []
    for name in SELECTED:
        path = clone(name)
        if path is None:
            print(f"[FAIL] clone {name}", flush=True)
            failures.append(name)
            continue
        t0 = time.time()
        print(f"[scan ] {name} ...", flush=True)
        try:
            secrets = scan_path(path)
        except Exception as exc:  # noqa: BLE001
            print(f"[FAIL] scan {name}: {exc}", flush=True)
            failures.append(name)
            continue
        elapsed = round(time.time() - t0, 1)
        print(f"[done ] {name}: {len(secrets)} hits in {elapsed}s", flush=True)
        entry = {
            "repo": name,
            "url": f"https://github.com/crypto-com/{name}",
            "seconds": elapsed,
            "secret_hits": len(secrets),
            "findings": secrets[:200],
            "truncated": len(secrets) > 200,
        }
        results.append(entry)
        (OUT_DIR / f"{name}.json").write_text(json.dumps(entry, indent=2))

    # merged summary (batch 1 + 2)
    old = json.loads((OUT_DIR / "summary.json").read_text())
    merged = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "repos_scanned": old["repos_scanned"] + len(results),
        "repos_failed": old["repos_failed"] + failures,
        "total_secret_hits": old["total_secret_hits"]
                             + sum(r["secret_hits"] for r in results),
        "per_repo": old["per_repo"]
                    + [{"repo": r["repo"], "hits": r["secret_hits"],
                        "seconds": r["seconds"]} for r in results],
    }
    (OUT_DIR / "summary.json").write_text(json.dumps(merged, indent=2))
    print(f"\n[summary] batch2 scanned={len(results)} failed={len(failures)} "
          f"hits={sum(r['secret_hits'] for r in results)}")
    print(f"[summary] total across both batches: "
          f"{merged['repos_scanned']} repos, {merged['total_secret_hits']} hits")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())

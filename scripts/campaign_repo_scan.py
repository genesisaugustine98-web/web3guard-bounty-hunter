#!/usr/bin/env python3
"""Campaign step 2: clone crypto-com public repos + secret/contract scan.

Passive recon: GitHub is third-party, no crypto.com endpoint contact.
Uses web3guard's own hardened scan_path() for secret detection.
Outputs: .web3guard/campaign/repo_scan/{repo}.json + summary.json
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

# Priority: repos tied to in-scope assets / actively maintained first.
PRIORITY = [
    "developer-platform-sdk-examples",
    "developer-platform-client-ts",
    "developer-platform-client-py",
    "facilitator-client-ts",
    "cdcx-cli",
    "crypto-agent-trading",
    "cdc-ai-agent-client-ts",
    "cdc-ai-agent-client-py",
    "defi-wallet-core-rs",
    "chain-desktop-wallet",
    "chain-indexing",
    "swap-contracts-core",
    "swap-contracts-periphery",
    "swap-interface",
    "deficonnect-monorepo",
    "crypto-pay-magento2",
    "crypto-pay-prestashop",
    "cro-staking",
    "pystarport",
    "ibc-solo-machine",
]
FALLBACK = [
    "thaler", "chain-tx-enclave", "chain-indexing", "swap-subgraphs",
    "defi-swap-swap-subgraph", "swap-info", "swap-token-list",
    "thaler-indexing", "WalletConnectRust", "tmkms-light",
    "crypto-exchange", "cosmos-sdk-codeql", "python-iavl",
    "bulletproofs", "jellyfish-merkle-tree", "siwe-rs",
]
SELECTED = PRIORITY + [r for r in FALLBACK if r not in PRIORITY]
# Keep the campaign bounded: top N repos, re-runnable in batches.
BATCH = 24


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


def scan_repo(name: str, path: Path) -> dict:
    t0 = time.time()
    print(f"[scan ] {name} ...", flush=True)
    secrets = scan_path(path)
    elapsed = round(time.time() - t0, 1)
    print(f"[done ] {name}: {len(secrets)} secret hits in {elapsed}s", flush=True)
    return {
        "repo": name,
        "url": f"https://github.com/crypto-com/{name}",
        "seconds": elapsed,
        "secret_hits": len(secrets),
        "findings": secrets[:200],
        "truncated": len(secrets) > 200,
    }


def main() -> int:
    results = []
    failures = []
    for name in SELECTED[:BATCH]:
        path = clone(name)
        if path is None:
            print(f"[FAIL] clone {name}", flush=True)
            failures.append(name)
            continue
        try:
            results.append(scan_repo(name, path))
        except Exception as exc:  # noqa: BLE001
            print(f"[FAIL] scan {name}: {exc}", flush=True)
            failures.append(name)
    summary = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "repos_scanned": len(results),
        "repos_failed": failures,
        "total_secret_hits": sum(r["secret_hits"] for r in results),
        "per_repo": [
            {"repo": r["repo"], "hits": r["secret_hits"], "seconds": r["seconds"]}
            for r in results
        ],
    }
    (OUT_DIR / "summary.json").write_text(json.dumps(summary, indent=2))
    for r in results:
        (OUT_DIR / f"{r['repo']}.json").write_text(json.dumps(r, indent=2))
    print(f"\n[summary] scanned={len(results)} failed={len(failures)} "
          f"secret_hits={summary['total_secret_hits']}")
    print(f"[summary] {OUT_DIR / 'summary.json'}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())

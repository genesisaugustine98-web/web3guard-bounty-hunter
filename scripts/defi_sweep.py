"""Top-50 DeFi sweep driver.

Scans a list of ``owner/repo`` targets through the real Web3Guard
pipeline (deterministic layer) into a single FindingsDB workdir, in
resumable chunks: each chunk is one ``web3guard scan`` subprocess with
its own SQLite findings DB, and the DB is closed cleanly after every
chunk (same convention as the fleet-mode batch tests). A chunk that
crashes can simply be re-run; already-scanned repos are skipped.

Usage:
    python scripts/defi_sweep.py --repos /tmp/defi_verified.txt \
        --workdir /tmp/wg-sweep --chunk 10 [--offset N]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = HERE.parent / ".venv" / "bin" / "python"


def read_repos(path: Path) -> list[str]:
    return [ln.strip() for ln in path.read_text().splitlines() if ln.strip()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repos", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--chunk", type=int, default=10)
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--parallel", type=int, default=4)
    args = ap.parse_args()

    repos = read_repos(Path(args.repos))
    root = Path(args.workdir)
    root.mkdir(parents=True, exist_ok=True)
    state_path = root / "sweep_state.json"
    state: dict[str, dict] = {}
    if state_path.exists():
        state = json.loads(state_path.read_text())

    todo = [
        r for r in repos[args.offset:]
        if state.get(r, {}).get("status") != "done"
    ]
    print(f"{len(repos)} repos total, {len(todo)} to scan", flush=True)

    for start in range(0, len(todo), args.chunk):
        chunk = todo[start:start + args.chunk]
        chunk_id = f"chunk{args.offset + start:03d}"
        work = root / chunk_id
        work.mkdir(parents=True, exist_ok=True)
        targets = [f"https://github.com/{r}" for r in chunk]
        t0 = time.monotonic()
        cmd = [
            str(PY), "-m", "web3guard.cli", "--workdir", str(work),
            "scan", *targets,
            "--no-exploit", "--no-self-critique", "--seed", "7",
            "--parallel", str(args.parallel),
            "--formats", "json",
        ]
        env = dict(os.environ)
        proc = subprocess.run(
            cmd, cwd=str(HERE.parent), env=env, timeout=5400,
            capture_output=True, text=True,
        )
        dt = time.monotonic() - t0
        # Persist state after every chunk (DB closed by CLI process exit).
        for r in chunk:
            state[r] = {
                "status": "done" if proc.returncode == 0 else "error",
                "chunk": chunk_id,
                "seconds": round(dt, 1),
            }
        state_path.write_text(json.dumps(state, indent=1, sort_keys=True))
        print(
            f"{chunk_id}: rc={proc.returncode} {dt:.0f}s "
            f"targets={len(chunk)} ({chunk[0]}..{chunk[-1]})",
            flush=True,
        )
        if proc.returncode != 0:
            (work / "stderr.log").write_text(proc.stderr[-20000:])
            print(f"  stderr saved to {work / 'stderr.log'}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

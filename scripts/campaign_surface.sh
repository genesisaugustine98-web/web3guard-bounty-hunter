#!/usr/bin/env bash
# Campaign step 1: webrecon SURFACE phase on the 10 confirmed in-scope hosts.
# Polite: 3s spacing, 40 req/host cap, 12 pages, JS secret scan built in.
# Confirmation is piped in — operator (tydanga) approved via interactive session.
set -uo pipefail
cd "$(dirname "$0")/.."

echo "=== SURFACE SCAN START $(date -u +%FT%TZ) ==="
echo y | .venv/bin/python -m web3guard.cli recon \
  --auth .web3guard/auth-crypto-com.json \
  --phases surface \
  --workdir .web3guard/webrecon
RC=$?
echo "=== SURFACE SCAN END rc=$RC $(date -u +%FT%TZ) ==="
exit $RC

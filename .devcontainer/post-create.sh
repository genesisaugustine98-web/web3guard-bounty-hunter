#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if command -v python >/dev/null 2>&1; then
  PY=python
elif command -v python3 >/dev/null 2>&1; then
  PY=python3
else
  echo "No Python interpreter found" >&2
  exit 1
fi
echo "Using interpreter: $PY"

echo "==> Installing any missing deps (idempotent)"
"$PY" -m pip install -e ".[dev]"

echo "==> Smoke: import + version"
"$PY" -m web3guard.cli version

echo "==> Tests"
"$PY" -m pytest -q

echo "==> Corpus validation"
"$PY" -m web3guard.cli bench --validate
"$PY" -m web3guard.cli bench --corpus bench/smartbugs/corpus.json --validate

echo "==> Benchmark (in-repo, offline)"
"$PY" -m web3guard.cli bench --fail-below 0.99,0.95

echo "==> Devcontainer is ready. Everything above ran green."

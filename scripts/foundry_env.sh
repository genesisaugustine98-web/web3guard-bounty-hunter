#!/usr/bin/env bash
# Web3Guard Foundry environment.
#
# Foundry is installed persistently at ~/workspace/tools/foundry (NOT
# ~/.foundry, which is ephemeral on this VM). Source this file to put
# forge/cast/anvil/chisel on PATH:
#
#   source scripts/foundry_env.sh   # from the repo root
#
# The invariant-fuzzing engine auto-discovers
# ~/workspace/tools/foundry/bin/forge on its own; WEB3GUARD_FORGE_BIN
# overrides it when set.

# Resolve the repo root (this script lives in <repo>/scripts/).
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_REPO_ROOT="$(cd "${_SCRIPT_DIR}/.." && pwd)"

export FOUNDRY_DIR="${FOUNDRY_DIR:-$HOME/workspace/tools/foundry}"
export PATH="$FOUNDRY_DIR/bin:$PATH"

if ! command -v forge >/dev/null 2>&1; then
    echo "web3guard: forge not found at \$FOUNDRY_DIR/bin ($FOUNDRY_DIR/bin)" >&2
    echo "web3guard: fuzz campaigns will skip until Foundry is installed there." >&2
else
    echo "web3guard: using $(command -v forge) ($(forge --version 2>/dev/null | head -1))"
fi

# Quiet repo-root hint for ad-hoc runs.
export WEB3GUARD_REPO_ROOT="$_REPO_ROOT"

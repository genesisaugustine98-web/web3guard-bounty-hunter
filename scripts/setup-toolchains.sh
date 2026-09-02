#!/usr/bin/env bash
# Install the web3guard language toolchains (Clarity, Cairo, FunC/Blueprint,
# Move, Solana/Anchor) on a CI runner. Idempotent: each tool is skipped if
# already present. A single toolchain failure must not abort the others, so
# each install is isolated and failures are collected (missing toolchains
# degrade gracefully to POTENTIAL (sandbox init failed)).
set -u

FAILED=()

has() { command -v "$1" >/dev/null 2>&1; }

note_fail() {
  FAILED+=("$1")
  echo "::warning::toolchain install failed: $1"
}

install_clarinet() {
  has clarinet && return 0
  local ver="v1.8.1"
  local url="https://github.com/hirosystems/clarinet/releases/download/${ver}/clarinet-linux-x64.zip"
  local dir="$HOME/.clarinet/bin"
  mkdir -p "$dir"
  curl -sSL "$url" -o /tmp/clarinet.zip && unzip -oq /tmp/clarinet.zip -d "$dir"
  chmod +x "$dir/clarinet"
  echo "$dir" >> "$GITHUB_PATH" 2>/dev/null || true
}

install_scarb() {
  has scarb && return 0
  curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh
}

install_blueprint() {
  has blueprint && return 0
  # --ignore-scripts: @tact-lang/compiler (a transitive dep) runs a husky
  # install hook that fails because husky is a devDependency, not installed
  # for transitive deps. The blueprint CLI does not need its install scripts.
  npm install -g --no-fund --no-audit --ignore-scripts @ton-community/blueprint
}

install_aptos() {
  has aptos && return 0
  local ver="3.1.0"
  local url="https://github.com/aptos-labs/aptos-core/releases/download/aptos-cli-v${ver}/aptos-cli-${ver}-Ubuntu-x86_64.zip"
  local dir="$HOME/.aptos/bin"
  mkdir -p "$dir"
  curl -sSL "$url" -o /tmp/aptos.zip && unzip -oq /tmp/aptos.zip -d "$dir"
  chmod +x "$dir/aptos"
  echo "$dir" >> "$GITHUB_PATH" 2>/dev/null || true
}

install_solana() {
  has solana && return 0
  sh -c "$(curl -sSfL https://release.solana.com/v1.18.18/install)"
  if has anchor; then return 0; fi
  cargo install --locked --git https://github.com/coral-xyz/anchor avm --force
  avm install latest && avm use latest
}

install_clarinet   || note_fail clarinet
install_scarb      || note_fail scarb
install_blueprint  || note_fail blueprint
install_aptos      || note_fail aptos
install_solana     || note_fail solana

if [ "${#FAILED[@]}" -gt 0 ]; then
  echo "::warning::one or more toolchains failed to install: ${FAILED[*]}"
fi
exit 0

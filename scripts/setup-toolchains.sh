#!/usr/bin/env bash
# Install the web3guard language toolchains (Clarity, Cairo, FunC/Blueprint,
# Move, Solana/Anchor) on a CI runner. Idempotent: each tool is skipped if
# already present. A single toolchain failure must not abort the others, so
# each install is isolated and failures are collected (missing toolchains
# degrade gracefully to POTENTIAL (sandbox init failed)).
#
# Each install_* function ends by returning the actual install result (the
# tool's binary exists / is on PATH), so a failed download that leaves no
# binary is reported via note_fail instead of being masked by a trailing
# no-op command.
#
# Usage: setup-toolchains.sh [tool ...]
# With no arguments every toolchain is installed; otherwise only the named
# ones (e.g. `setup-toolchains.sh clarinet scarb` for lightweight CI jobs).
set -u

FAILED=()

has() { command -v "$1" >/dev/null 2>&1; }

note_fail() {
  FAILED+=("$1")
  echo "::warning::toolchain install failed: $1"
}

install_clarinet() {
  has clarinet && return 0
  local ver="v3.23.2"
  # Asset naming changed from *.zip to *-glibc.tar.gz on the v3 releases.
  local url="https://github.com/hirosystems/clarinet/releases/download/${ver}/clarinet-linux-x64-glibc.tar.gz"
  local dir="$HOME/.clarinet/bin"
  mkdir -p "$dir"
  curl -sSL "$url" -o /tmp/clarinet.tar.gz && tar -xzf /tmp/clarinet.tar.gz -C "$dir"
  chmod +x "$dir/clarinet"
  echo "$dir" >> "$GITHUB_PATH" 2>/dev/null || true
  [ -x "$dir/clarinet" ]
}

install_scarb() {
  has scarb && return 0
  curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh
  # scarb-install.sh symlinks into ~/.local/bin (already on PATH on runners).
  has scarb || [ -x "$HOME/.local/bin/scarb" ]
}

install_blueprint() {
  has blueprint && return 0
  # --ignore-scripts: @tact-lang/compiler (a transitive dep) runs a husky
  # install hook that fails because husky is a devDependency, not installed
  # for transitive deps. The blueprint CLI does not need its install scripts.
  npm install -g --no-fund --no-audit --ignore-scripts @ton-community/blueprint
  has blueprint
}

install_aptos() {
  has aptos && return 0
  # v3.x Ubuntu binaries link libssl.so.1.1 (EOL) which Ubuntu 24.04 runners
  # do not ship; use the v9.5.1 Ubuntu 24.04 build (OpenSSL 3 / glibc 2.38+).
  local ver="9.5.1"
  local url="https://github.com/aptos-labs/aptos-core/releases/download/aptos-cli-v${ver}/aptos-cli-${ver}-Ubuntu-24.04-x86_64.zip"
  local dir="$HOME/.aptos/bin"
  mkdir -p "$dir"
  curl -sSL "$url" -o /tmp/aptos.zip && unzip -oq /tmp/aptos.zip -d "$dir"
  chmod +x "$dir/aptos"
  echo "$dir" >> "$GITHUB_PATH" 2>/dev/null || true
  [ -x "$dir/aptos" ]
}

install_solana() {
  has solana && return 0
  # release.solana.com is unreachable from CI runners (SSL egress block), so
  # pull the CLI from the anza-xyz/agave GitHub release mirror instead.
  local ver="v1.18.18"
  local url="https://github.com/anza-xyz/agave/releases/download/${ver}/solana-release-x86_64-unknown-linux-gnu.tar.bz2"
  local dir="$HOME/.solana"
  mkdir -p "$dir"
  curl -sSL "$url" -o /tmp/solana.tar.bz2
  tar -xjf /tmp/solana.tar.bz2 -C "$dir" --strip-components=1
  echo "$dir/bin" >> "$GITHUB_PATH" 2>/dev/null || true
  if ! has anchor; then
    cargo install --locked --git https://github.com/coral-xyz/anchor avm --force
    avm install latest && avm use latest
  fi
  [ -x "$dir/bin/solana" ]
}

TOOLS=("$@")
if [ "${#TOOLS[@]}" -eq 0 ]; then
  TOOLS=(clarinet scarb blueprint aptos solana)
fi

for tool in "${TOOLS[@]}"; do
  case "$tool" in
    clarinet)  install_clarinet   || note_fail clarinet ;;
    scarb)     install_scarb      || note_fail scarb ;;
    blueprint) install_blueprint  || note_fail blueprint ;;
    aptos)     install_aptos      || note_fail aptos ;;
    solana)    install_solana     || note_fail solana ;;
    *)         echo "::warning::unknown toolchain requested: $tool" ;;
  esac
done

if [ "${#FAILED[@]}" -gt 0 ]; then
  echo "::warning::one or more toolchains failed to install: ${FAILED[*]}"
fi
exit 0

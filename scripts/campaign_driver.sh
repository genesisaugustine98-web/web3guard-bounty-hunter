#!/usr/bin/env bash
# Campaign driver: runs all campaign steps sequentially with logging.
# Designed to run inside tmux session 'bounty-campaign'.
set -uo pipefail
cd "$(dirname "$0")/.."
LOG_DIR=".web3guard/campaign"
mkdir -p "$LOG_DIR"

echo "[$(date -u +%FT%TZ)] campaign driver started" | tee -a "$LOG_DIR/driver.log"

echo "[$(date -u +%FT%TZ)] STEP 1/3 surface scan" | tee -a "$LOG_DIR/driver.log"
bash scripts/campaign_surface.sh > "$LOG_DIR/surface.log" 2>&1
echo "[$(date -u +%FT%TZ)] STEP 1 rc=$?" | tee -a "$LOG_DIR/driver.log"

echo "[$(date -u +%FT%TZ)] STEP 2/3 repo clone + secret scan" | tee -a "$LOG_DIR/driver.log"
.venv/bin/python scripts/campaign_repo_scan.py > "$LOG_DIR/repo_scan.log" 2>&1
echo "[$(date -u +%FT%TZ)] STEP 2 rc=$?" | tee -a "$LOG_DIR/driver.log"

echo "[$(date -u +%FT%TZ)] STEP 3/3 js build diff" | tee -a "$LOG_DIR/driver.log"
.venv/bin/python scripts/campaign_js_diff.py > "$LOG_DIR/js_diff.log" 2>&1
echo "[$(date -u +%FT%TZ)] STEP 3 rc=$?" | tee -a "$LOG_DIR/driver.log"

echo "[$(date -u +%FT%TZ)] campaign driver finished" | tee -a "$LOG_DIR/driver.log"

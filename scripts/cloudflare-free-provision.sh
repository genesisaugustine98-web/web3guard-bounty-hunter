#!/usr/bin/env bash
set -euo pipefail
D1_NAME="web3guard-audit"
QUEUE_NAME="web3guard-scans"
DLQ_NAME="web3guard-scans-dlq"
R2_NAME="web3guard-reports"
npx wrangler whoami
npx wrangler d1 create "$D1_NAME" --location wnam --jurisdiction us --binding AUDIT_DB --update-config || true
npx wrangler queues create "$QUEUE_NAME" --message-retention-period-secs 86400 || true
npx wrangler queues create "$DLQ_NAME" --message-retention-period-secs 86400 || true
npx wrangler r2 bucket create "$R2_NAME" --update-config --binding REPORTS || true
python3 - <<'PY'
from pathlib import Path
p=Path("wrangler.toml")
s=p.read_text()
if 'queue = "web3guard-scans"' not in s:
    s += '''
[[queues.producers]]
queue = "web3guard-scans"
binding = "SCAN_QUEUE"

[[queues.consumers]]
queue = "web3guard-scans"
max_batch_size = 5
max_batch_timeout = 5
max_retries = 2
dead_letter_queue = "web3guard-scans-dlq"
max_concurrency = 1
'''
p.write_text(s)
PY
npx wrangler d1 migrations apply "$D1_NAME" --remote --config wrangler.toml
chmod +x scripts/cloudflare-free-provision.sh
cat <<'MSG'
Provisioned. Set:
  npx wrangler secret put GITHUB_TOKEN
  npx wrangler secret put TELEGRAM_BOT_TOKEN
  npx wrangler secret put TURNSTILE_SECRET
  npx wrangler secret put WEB_API_KEY
Then add TURNSTILE_SITE_KEY under [vars] and deploy with:
  npx wrangler deploy
MSG

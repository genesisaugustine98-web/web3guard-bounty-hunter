# Web3Guard Cloudflare Free Mode

Cloudflare is the edge/control plane; GitHub Actions remains the heavy scanner runtime.

Flow: Telegram/Web UI -> Worker -> Durable Object admission -> Queue -> GitHub repository_dispatch -> Web3Guard.

Application safety caps:
- Worker requests: 70,000/day
- Durable Object requests: 70,000/day
- Queue operations reserved: 7,000/day
- Scan admissions: 1,000/day
- R2 archival: disabled

Fail-closed defaults:
- REQUIRE_FREE_GUARD=1
- REQUIRE_QUEUE=1
- REQUIRE_TURNSTILE=1
- ENABLE_R2_ARCHIVE=0
- MAX_SCANS_PER_DAY=1000

The manual Actions workflow exposes target_url and budget while preserving the existing targets_config multi-target mode.

The web console provides GET /, POST /api/scan, and protected GET /api/usage. Telegram /scan and /quick continue to use the same scanner dispatch grammar.

R2 is intentionally not part of the scan critical path. Enable archival only with a dedicated bucket and monitoring policy.

Provision after Wrangler authentication:
~~~bash
bash scripts/cloudflare-free-provision.sh
npx wrangler secret put GITHUB_TOKEN
npx wrangler secret put TELEGRAM_BOT_TOKEN
npx wrangler secret put TURNSTILE_SECRET
npx wrangler secret put WEB_API_KEY
npx wrangler deploy
~~~

Test:
~~~bash
node --check bot/worker.js
node --check bot/cloudflare_free_guard.js
node --test scripts/free-cap-tests.mjs
bash -n scripts/cloudflare-free-provision.sh
~~~

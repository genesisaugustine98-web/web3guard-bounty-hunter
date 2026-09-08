#!/usr/bin/env bash
# Post a Web3Guard scan report to Telegram as readable finding text.
#
# The message is the *actual findings* (severity, location, description,
# evidence, and PoC for confirmed exploits), rendered from the scan output
# directory written by `web3guard scan --out <dir>`. Long messages are split
# into multiple Telegram messages (<=4096 chars each) with a small delay to
# stay under Telegram's flood limits.
#
# Usage:
#   send_telegram_report.sh <bot_token> <chat_id> <title> <report_dir> [phase_status]
#
#   phase_status: "ok" when the scan phase completed and produced a report;
#                 anything else posts a short failure notice instead.
# Exits 0 silently when token or chat_id are empty (nothing configured).
set -u

TOKEN="${1:-}"
CHAT="${2:-}"
TITLE="${3:-}"
REPORT_DIR="${4:-}"
STATUS="${5:-ok}"

if [ -z "$TOKEN" ] || [ -z "$CHAT" ]; then
  echo "send_telegram_report: token or chat_id not set; skipping"
  exit 0
fi

TEXT=""
if [ "$STATUS" != "ok" ] || [ ! -d "$REPORT_DIR" ]; then
  SERVER_URL="${GITHUB_SERVER_URL:-https://github.com}"
  REPO="${GITHUB_REPOSITORY:-}"
  RUN_ID="${GITHUB_RUN_ID:-}"
  TEXT="The scan phase did not complete, so no report was produced."
  if [ -n "$REPO" ] && [ -n "$RUN_ID" ]; then
    TEXT="${TEXT}
See the Actions run: ${SERVER_URL}/${REPO}/actions/runs/${RUN_ID}"
  fi
else
  TEXT="$(python3 -m web3guard.cli digest --dir "$REPORT_DIR" 2>/dev/null)" || TEXT=""
  if [ -z "$TEXT" ]; then
    TEXT="$(cat "$REPORT_DIR/WEB3GUARD_EXPLOIT_REPORT.txt" 2>/dev/null)" || TEXT=""
  fi
  if [ -z "$TEXT" ]; then
    TEXT="The scan finished but produced no readable findings in ${REPORT_DIR}."
  fi
fi

export WG_TOKEN="$TOKEN"
export WG_CHAT="$CHAT"
export WG_TITLE="$TITLE"
export WG_TEXT="$TEXT"
export WG_DRY_RUN="${WG_DRY_RUN:-}"

python3 - <<'PY'
import os
import time
import urllib.parse
import urllib.request

TOKEN = os.environ["WG_TOKEN"]
CHAT = os.environ["WG_CHAT"]
TITLE = os.environ["WG_TITLE"]
BODY = os.environ["WG_TEXT"]
DRY_RUN = os.environ.get("WG_DRY_RUN") == "1"

MAX = 4000  # Telegram hard limit is 4096 chars/message.


def chunks(text: str) -> list[str]:
    out: list[str] = []
    rest = text.strip("\n")
    while len(rest) > MAX:
        cut = rest.rfind("\n", 0, MAX)
        if cut <= 0:
            cut = MAX
        out.append(rest[:cut])
        rest = rest[cut:].lstrip("\n")
    if rest:
        out.append(rest)
    return out


def send(message: str) -> bool:
    if DRY_RUN:
        print(message)
        return True
    payload = urllib.parse.urlencode({
        "chat_id": CHAT,
        "text": message,
        "disable_web_page_preview": "true",
    }).encode("utf-8")
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, data=payload, method="POST")
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.status == 200
        except Exception:  # noqa: BLE001
            time.sleep(2 + attempt * 2)
    return False


message_parts = chunks(TITLE + "\n\n" + BODY)
for index, part in enumerate(message_parts, start=1):
    if len(message_parts) > 1:
        part = f"[{index}/{len(message_parts)}]\n{part}"
    send(part)
    if not DRY_RUN:
        time.sleep(1.2)  # respect Telegram per-bot rate limits
PY

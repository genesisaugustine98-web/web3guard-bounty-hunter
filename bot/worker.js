/**
 * Web3Guard zero-dollar trigger bot.
 *
 * Cloudflare Worker that sits between Telegram and GitHub Actions:
 *
 *   Telegram (mobile app)  ->  setWebhook pushes updates to this Worker
 *   Worker                 ->  verify chat_id, parse /scan <target>|<budget>,
 *                              clamp budget, POST GitHub repository_dispatch
 *   GitHub Actions         ->  runs scan-on-command, replies to Telegram
 *
 * Zero cost: Cloudflare Workers free tier (100k req/day, no card), the
 * GitHub Actions minutes on a public repo, and NVIDIA NIM (free LLM).
 *
 * Secrets (set as Worker encrypted env vars in the CF dashboard):
 *   GITHUB_TOKEN      fine-grained PAT, only this repo, Actions:write + Contents:read
 *   ALLOWED_CHAT_IDS  comma-separated Telegram chat ids that may trigger scans
 *   GITHUB_REPO       "owner/repo" e.g. genesisaugustine98-web/web3guard-bounty-hunter
 *
 * Bindings (no secret, public):
 *   MAX_BUDGET        optional, default 200000 (token budget per command)
 *   DEFAULT_MIN_SEV   optional, default LOW
 */

const MAX_BUDGET = parseInt(env("MAX_BUDGET", "200000"), 10);
const DEFAULT_MIN_SEV = env("DEFAULT_MIN_SEV", "LOW");

const ALLOWED = (env("ALLOWED_CHAT_IDS", ""))
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

async function handleRequest(request) {
  const url = new URL(request.url);

  // Liveness for the CF dashboard / uptime checks.
  if (url.pathname === "/healthz" || request.method === "GET") {
    return json({ ok: true, service: "web3guard-trigger" });
  }

  if (request.method !== "POST" || url.pathname !== "/webhook") {
    return json({ ok: false, error: "not found" }, 404);
  }

  let update;
  try {
    update = await request.json();
  } catch {
    return json({ ok: false, error: "invalid JSON" }, 400);
  }

  const msg = update?.message;
  const chatId = msg?.chat?.id;
  const text = msg?.text ?? "";

  // Security gate #1: only allowlisted chats can trigger anything.
  if (chatId === undefined || !ALLOWED.includes(String(chatId))) {
    return json({ ok: false, error: "unauthorized" }, 403);
  }

  const replyText = await handleCommand(String(chatId), text);
  await sendTelegram(chatId, replyText);

  return json({ ok: true });
}

async function handleCommand(chatId, text) {
  const line = text.trim();
  const match = line.match(/^\/(scan|status|help)\b(?:\s+(.+))?$/i);
  if (!match) {
    return "Commands: /scan <git-url-or-local-path>|<budget>  |  /status  |  /help";
  }

  const cmd = match[1].toLowerCase();
  if (cmd === "help") {
    return (
      "Web3Guard trigger\n" +
      "/scan <repo>|<budget>   start a scan (budget = token cap, or max)\n" +
      "/status                 show this repo's latest workflow run\n" +
      "Example: /scan https://github.com/owner/repo|200000"
    );
  }

  const GITHUB_TOKEN = env("GITHUB_TOKEN", "");
  const GITHUB_REPO = env("GITHUB_REPO", "");
  if (!GITHUB_TOKEN || !GITHUB_REPO) {
    return "Bot misconfigured (missing GITHUB_TOKEN or GITHUB_REPO).";
  }

  if (cmd === "status") {
    const s = await githubStatus(GITHUB_TOKEN, GITHUB_REPO);
    return s;
  }

  // cmd === "scan"
  const rest = (match[2] ?? "").trim();
  if (!rest) return "Usage: /scan <git-url>|<budget>   e.g. /scan https://github.com/owner/repo|200000";

  let [target, budgetRaw] = rest.split(/\s+/, 1)[0].split("|");
  let budget = budgetRaw ?? "200000";

  // Security gate #2: clamp the budget so a single command can't burn
  // unlimited Actions minutes or LLM tokens.
  if (budget === "max") {
    budget = String(MAX_BUDGET);
  } else {
    const n = parseInt(budget, 10);
    if (!Number.isFinite(n) || n <= 0) {
      return `Invalid budget '${budgetRaw}'. Use a positive number or 'max'.`;
    }
    budget = String(Math.min(n, MAX_BUDGET));
  }

  const ok = await dispatchScan(GITHUB_TOKEN, GITHUB_REPO, {
    target,
    budget,
    chat_id: chatId,
    min_severity: DEFAULT_MIN_SEV,
  });
  return ok
    ? `Scan dispatched: ${target}|${budget}\nResults will arrive here shortly.`
    : "Failed to dispatch scan. Check bot logs / GITHUB_REPO.";
}

async function dispatchScan(token, repo, payload) {
  const res = await fetch(`https://api.github.com/repos/${repo}/dispatches`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
      "User-Agent": "web3guard-trigger",
    },
    body: JSON.stringify({ event_type: "scan-request", client_payload: payload }),
  });
  return res.ok;
}

async function githubStatus(token, repo) {
  const res = await fetch(
    `https://api.github.com/repos/${repo}/actions/runs?per_page=1`,
    { headers: { Authorization: `Bearer ${token}`, "User-Agent": "web3guard-trigger" } }
  );
  if (!res.ok) return "Could not query GitHub status.";
  const data = await res.json();
  const run = data.workflow_runs?.[0];
  if (!run) return "No workflow runs yet.";
  return `Latest run #${run.run_number}: ${run.status}${run.conclusion ? " / " + run.conclusion : ""} (${run.event})`;
}

async function sendTelegram(chatId, text) {
  const token = env("TELEGRAM_BOT_TOKEN", "");
  if (!token) return;
  try {
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text }),
    });
  } catch {
    // Best effort; the scan result is the real payload and comes from CI.
  }
}

function env(name, fallback) {
  const v = globalThis[name];
  return v === undefined || v === null ? fallback : String(v);
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export default {
  fetch: handleRequest,
};

/**
 * Web3Guard zero-dollar trigger bot (v2).
 *
 * Cloudflare Worker that sits between Telegram and GitHub Actions:
 *
 *   Telegram (mobile app)  ->  setWebhook pushes updates to this Worker
 *   Worker                 ->  verify chat_id, parse the command, clamp
 *                              budget, rate-limit, POST repository_dispatch
 *   GitHub Actions         ->  runs scan-on-command, replies to Telegram
 *
 * Zero cost: Cloudflare Workers free tier (100k req/day, no card), the
 * GitHub Actions minutes on a public repo, and NVIDIA NIM (free LLM).
 *
 * v2 upgrades over v1:
 *   - /scan accepts ANY target the pipeline can fetch: git URLs on any
 *     host, archive/raw-file URLs, IPFS paths, and bare 0x addresses
 *     (verified on-chain source via free Blockscout — no API keys)
 *   - inline keyboards: severity picker after dispatch, confirm button
 *     on oversized budgets, /languages and /chains as tappable cards
 *   - callback_query handling (the v1 bot silently ignored button taps)
 *   - per-chat rate limiting (5 scans / minute) with a friendly notice
 *   - all replies use HTML parse mode with escaping; /status renders the
 *     last run with a live log link
 *
 * Secrets (set as Worker encrypted env vars in the CF dashboard):
 *   GITHUB_TOKEN      fine-grained PAT, only this repo, Actions:write + Contents:read
 *   ALLOWED_CHAT_IDS  comma-separated Telegram chat ids that may trigger scans
 *   TELEGRAM_BOT_TOKEN bot token from @BotFather (for instant replies)
 *   GITHUB_REPO       "owner/repo" e.g. genesisaugustine98-web/web3guard-bounty-hunter
 *
 * Bindings (no secret, public):
 *   MAX_BUDGET        optional, default 200000 (token budget per command)
 *   DEFAULT_MIN_SEV   optional, default LOW
 */

import {
  SAFE_LIMITS,
  Web3GuardFreeGuard,
  reserveFreeCapacity,
  scanReservations,
} from "./cloudflare_free_guard.js";

export { Web3GuardFreeGuard };

export const RATE_LIMIT = { max: 5, windowMs: 60_000 };
const rateBuckets = new Map(); // chatId -> [timestamps]

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Liveness for the CF dashboard / uptime checks.
    if (url.pathname === "/healthz") {
      return json({ ok: true, service: "web3guard-trigger", version: 3, free_mode: true });
    }
    if (url.pathname === "/" && request.method === "GET") {
      return new Response(scanUiHtml(env), {
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
      });
    }

    if (url.pathname === "/api/scan" && request.method === "POST") {
      const turnstile = await requireTurnstile(request, env);
      if (!turnstile.ok) return json(turnstile, 403);
      const keyCheck = requireWebApiKey(request, env);
      if (!keyCheck.ok) return json(keyCheck, 401);
      let body;
      try { body = await request.json(); }
      catch { return json({ ok: false, error: "invalid JSON" }, 400); }
      const target = String(body?.target || "").trim();
      if (!validTarget(target)) return json({ ok: false, error: "unsupported target" }, 400);
      const parsed = parseBudget(body?.budget, env);
      if (parsed.error) return json({ ok: false, error: parsed.error }, 400);
      const payload = {
        request_id: crypto.randomUUID(),
        target,
        budget: String(body?.discovery_only ? Math.min(parsed.budget, 50000) : parsed.budget),
        chat_id: "",
        min_severity: normalizeSeverity(body?.min_severity || env.DEFAULT_MIN_SEV || "LOW"),
        discovery_only: Boolean(body?.discovery_only),
        source: "web",
      };
      const ok = await dispatchScan(env, payload);
      return json({ ok, queued: Boolean(env.SCAN_QUEUE), request_id: payload.request_id, target },
        ok ? 200 : 503);
    }

    if (url.pathname === "/api/usage" && request.method === "GET") {
      const keyCheck = requireWebApiKey(request, env);
      if (!keyCheck.ok) return json(keyCheck, 401);
      return usageSnapshot(env);
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
    const callback = update?.callback_query;
    const chatId = callback?.message?.chat?.id ?? msg?.chat?.id;
    const text = msg?.text ?? "";

    const allowed = (env.ALLOWED_CHAT_IDS || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    // Security gate #1: only allowlisted chats can trigger anything.
    if (chatId === undefined || !allowed.includes(String(chatId))) {
      return json({ ok: false, error: "unauthorized" }, 403);
    }

    let replyText = "";
    let replyKeyboard;
    if (callback) {
      // Answer the callback immediately so the mobile spinner stops.
      await answerCallback(env, callback.id, null);
      const handled = await handleCallback(env, String(chatId), callback);
      replyText = handled.text;
      replyKeyboard = handled.keyboard;
    } else if (msg?.document) {
      replyText =
        "📎 File uploads are scanned by the long-polling bot " +
        "(python -m web3guard.telegram_bot). This Worker only dispatches " +
        "URL / address scans.";
    } else if (text) {
      const handled = await handleCommand(env, String(chatId), text);
      replyText = handled.text;
      replyKeyboard = handled.keyboard;
    }

    if (replyText) {
      await sendTelegram(env, chatId, replyText, replyKeyboard);
    }
    return json({ ok: true });
  },

  async queue(batch, env, ctx) {
    for (const message of batch.messages) {
      const payload = message.body || {};
      try {
        const ok = await dispatchGithubRepositoryEvent(env, payload);
        if (!ok) throw new Error("GitHub repository_dispatch failed");
        await recordAuditStatus(env, payload.request_id, "dispatched", null, ctx);
        if (typeof message.ack === "function") message.ack();
      } catch (error) {
        await recordAuditStatus(env, payload.request_id, "queue_error", String(error), ctx);
        if (typeof message.retry === "function") message.retry();
        else throw error;
      }
    }
  },
};

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async function handleCommand(env, chatId, text) {
  const line = text.trim();
  const match = line.match(/^\/([a-z_]+)(?:@\w+)?\b(?:\s+([\s\S]+))?$/i);
  if (!match) {
    return { text: "Send /help for the command sheet." };
  }

  const cmd = match[1].toLowerCase();
  const arg = (match[2] ?? "").trim();

  if (cmd === "start" || cmd === "help") {
    return { text: helpText() };
  }
  if (cmd === "languages") {
    return { text: languagesText() };
  }
  if (cmd === "chains") {
    return {
      text: chainsText(),
      keyboard: chainsKeyboard(),
    };
  }

  const GITHUB_TOKEN = env.GITHUB_TOKEN || "";
  const GITHUB_REPO = env.GITHUB_REPO || "";
  if (!GITHUB_TOKEN || !GITHUB_REPO) {
    return { text: "Bot misconfigured (missing GITHUB_TOKEN or GITHUB_REPO)." };
  }

  if (cmd === "status") {
    return { text: await githubStatus(GITHUB_TOKEN, GITHUB_REPO) };
  }

  if (cmd === "scan" || cmd === "quick") {
    if (!arg) {
      return {
        text:
          "Usage: /scan <target> [budget]\n" +
          "Targets: any git URL, archive/raw-file URL, IPFS path, or a bare " +
          "0x address (verified on-chain source, 11 chains).\n" +
          "Example: /scan 0xdAC17F958D2ee523a2206206994597C13D831ec7",
      };
    }
    if (!rateLimitOk(chatId)) {
      return { text: "⏳ Rate limit: 5 scans / minute per chat. Try again shortly." };
    }
    const bits = arg.split(/\s+/);
    const target = bits[0];
    if (!validTarget(target)) {
      return {
        text:
          "❌ That does not look like a supported target.\n" +
          "Supported: git URLs, .zip/.tar.gz archives, raw source files, " +
          "ipfs:// paths, 0x addresses, owner/repo shorthands (gh:/gl:/bb:/cb:/sr:).",
      };
    }
    const quick = cmd === "quick";
    const parsed = parseBudget(bits[1], env);
    if (parsed.error) return { text: parsed.error };
    const budget = quick ? Math.min(parsed.budget, 50_000) : parsed.budget;
    if (parsed.needsConfirm) {
      return {
        text:
          `⚠️ Budget ${budget} is large. Confirm?\n` +
          `target: ${target}`,
        keyboard: inlineKeyboard([
          [
            { text: "✅ Confirm scan", callback_data: `scan:${target}|${budget}` },
            { text: "❌ Cancel", callback_data: "noop" },
          ],
        ]),
      };
    }
    const ok = await dispatchScan(env, {
      target,
      budget: String(budget),
      chat_id: chatId,
      min_severity: env.DEFAULT_MIN_SEV || "LOW",
      discovery_only: quick,
    });
    return {
      text: ok
        ? `${quick ? "⚡ Quick scan" : "🚀 Scan"} dispatched: ${target} (budget ${budget})\n` +
          "Results will arrive here shortly."
        : "Failed to dispatch scan. Check bot logs / GITHUB_REPO.",
      keyboard: inlineKeyboard([
        [
          { text: "🟥 CRITICAL+", callback_data: `sev:${target}|${budget}|CRITICAL` },
          { text: "🟧 HIGH+", callback_data: `sev:${target}|${budget}|HIGH` },
        ],
      ]),
    };
  }

  return { text: "Unknown command. /help shows the full sheet." };
}

async function handleCallback(env, chatId, callback) {
  const data = String(callback.data || "");
  if (!data || data === "noop") {
    return { text: "" };
  }
  const GITHUB_TOKEN = env.GITHUB_TOKEN || "";
  const GITHUB_REPO = env.GITHUB_REPO || "";

  if (data.startsWith("scan:")) {
    const [target, budget] = data.slice(5).split("|");
    if (!rateLimitOk(chatId)) {
      return { text: "⏳ Rate limit hit — try again in a minute." };
    }
    const ok = await dispatchScan(env, {
      target,
      budget: budget || String(env.MAX_BUDGET || 200000),
      chat_id: chatId,
      min_severity: env.DEFAULT_MIN_SEV || "LOW",
    });
    return {
      text: ok
        ? `🚀 Scan dispatched: ${target} (budget ${budget})`
        : "Failed to dispatch scan.",
    };
  }

  if (data.startsWith("sev:")) {
    const [, target, budget, minSev] = data.split(":")[1].split("|").reduce(
      (acc, part, idx) => {
        if (idx === 0) acc.push(part);
        else acc[acc.length - 1] += ":" + part;
        return acc;
      },
      []
    );
    // data shape: sev:<target>|<budget>|<SEV> — target may itself contain ':'
    const rest = data.slice(4);
    const sevIdx = rest.lastIndexOf("|");
    const targetBudget = rest.slice(0, sevIdx);
    const severity = rest.slice(sevIdx + 1);
    const [t, b] = targetBudget.split("|");
    const ok = await dispatchScan(GITHUB_TOKEN, GITHUB_REPO, {
      target: t,
      budget: b || "200000",
      chat_id: chatId,
      min_severity: severity || "LOW",
    });
    return {
      text: ok
        ? `🚀 Re-scan dispatched for ≥${severity}: ${t}`
        : "Failed to dispatch scan.",
    };
  }

  return { text: "" };
}

// ---------------------------------------------------------------------------
// Target validation (mirror of the Python pipeline's supported shapes)
// ---------------------------------------------------------------------------

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function normalizeSeverity(value) {
  const v = String(value || "LOW").toUpperCase();
  return ["INFO","LOW","MEDIUM","HIGH","CRITICAL"].includes(v) ? v : "LOW";
}

async function requireTurnstile(request, env) {
  const secret = env.TURNSTILE_SECRET || "";
  const required = String(env.REQUIRE_TURNSTILE || "0") === "1";
  if (!secret) return required ? { ok:false, error:"turnstile_not_configured" } : { ok:true, skipped:true };
  const token = request.headers.get("cf-turnstile-response") || "";
  if (!token) return { ok:false, error:"turnstile_required" };
  try {
    const form = new URLSearchParams({ secret, response: token });
    const ip = request.headers.get("CF-Connecting-IP");
    if (ip) form.set("remoteip", ip);
    const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method:"POST",
      headers:{"content-type":"application/x-www-form-urlencoded"},
      body:form.toString(),
    });
    const data = await response.json();
    return data?.success ? { ok:true } : { ok:false, error:"turnstile_failed" };
  } catch {
    return { ok:false, error:"turnstile_unavailable" };
  }
}

function requireWebApiKey(request, env) {
  const configured = env.WEB_API_KEY || "";
  if (!configured) {
    return String(env.REQUIRE_WEB_API_KEY || "0") === "1"
      ? { ok:false, error:"web_api_key_not_configured" }
      : { ok:true, skipped:true };
  }
  return request.headers.get("x-web3guard-api-key") === configured
    ? { ok:true }
    : { ok:false, error:"invalid_api_key" };
}

function freeCapFailure(result) {
  if (result?.failures?.some((x) => x.metric === "rate_limit"))
    return { text:"⏳ Rate limit: 5 scans / minute per chat. Try again shortly." };
  return { text:"🛑 Free-mode capacity guard stopped this request before creating billable usage." };
}

function freeCapResponse(result) {
  return json({ ok:false, error:"free_cap_reached", failures:result?.failures || [] },429);
}

function scanUiHtml(env) {
  const siteKey = escapeHtml(env.TURNSTILE_SITE_KEY || "");
  const widget = siteKey
    ? '<div class="cf-turnstile" data-sitekey="' + siteKey + '"></div>'
    : '<p class="note">Turnstile is not configured.</p>';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Web3Guard</title>
<style>body{font:16px system-ui;max-width:760px;margin:40px auto;padding:0 18px}input,select,button{font:inherit;padding:10px;margin:6px 0;width:100%;box-sizing:border-box}button{cursor:pointer}.note{color:#666}.out{white-space:pre-wrap;margin-top:20px}</style>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script></head>
<body><h1>Web3Guard</h1><p>Free-mode scan control plane.</p>
<form id="scan"><input name="target" required placeholder="Target URL, IPFS path, owner/repo, or 0x address">
<input name="budget" value="max" placeholder="Budget"><select name="min_severity"><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option><option>INFO</option></select>
<label><input type="checkbox" name="discovery_only"> discovery-only</label>${widget}<button>Queue scan</button></form>
<div class="out" id="out"></div><script>
document.querySelector("#scan").addEventListener("submit",async e=>{
e.preventDefault();const f=new FormData(e.currentTarget);
const token=document.querySelector('[name="cf-turnstile-response"]')?.value||"";
const r=await fetch("/api/scan",{method:"POST",headers:{"content-type":"application/json",...(token?{"cf-turnstile-response":token}:{})},
body:JSON.stringify({target:f.get("target"),budget:f.get("budget"),min_severity:f.get("min_severity"),discovery_only:f.get("discovery_only")==="on"})});
document.querySelector("#out").textContent=await r.text();});
</script></body></html>`;
}

function validTarget(target) {
  if (/^0x[a-fA-F0-9]{40}$/.test(target)) return true; // on-chain address
  if (/^(gh|gl|bb|cb|sr):/.test(target)) return true; // shorthand
  if (/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(target)) return true; // owner/repo
  if (/^ipfs:\/\//.test(target)) return true;
  if (/^https?:\/\//.test(target)) return true; // archives, raw files, git
  if (/^git@/.test(target)) return true;
  return false;
}

function parseBudget(raw, env) {
  const maxBudget = parseInt(env.MAX_BUDGET || "200000", 10);
  let budget;
  if (!raw || raw === "max") {
    budget = maxBudget;
  } else {
    const n = parseInt(raw, 10);
    if (!Number.isFinite(n) || n <= 0) {
      return { error: `Invalid budget '${raw}'. Use a positive number or 'max'.` };
    }
    budget = Math.min(n, maxBudget);
  }
  return { budget, needsConfirm: budget >= maxBudget * 0.9 };
}

// ---------------------------------------------------------------------------
// GitHub + Telegram transports
// ---------------------------------------------------------------------------

async function dispatchScan(env, payload) {
  const admission = await admitScan(env, payload.chat_id || "web");
  if (!admission.ok) {
    await recordAudit(env, payload, "blocked", admission.error);
    return false;
  }
  if (env.SCAN_QUEUE) {
    try {
      await recordAudit(env, payload, "queued", null);
      await env.SCAN_QUEUE.send(payload);
      return true;
    } catch (error) {
      await recordAuditStatus(env, payload.request_id, "queue_error", String(error));
      return false;
    }
  }
  if (String(env.REQUIRE_QUEUE || "0") === "1") {
    await recordAudit(env, payload, "queue_missing", "SCAN_QUEUE binding is required");
    return false;
  }
  const ok = await dispatchGithubRepositoryEvent(env, payload);
  await recordAuditStatus(env, payload.request_id, ok ? "dispatched" : "dispatch_error", ok ? null : "GitHub dispatch failed");
  return ok;
}

async function dispatchGithubRepositoryEvent(env, payload) {
  const token = env.GITHUB_TOKEN || "";
  const repo = env.GITHUB_REPO || "";
  if (!token || !repo) return false;
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

async function admitScan(env, chatId) {
  return reserveFreeCapacity(env, {
    reservations: scanReservations(env, Boolean(env.SCAN_QUEUE)),
    rate: { key: String(chatId || "anonymous").slice(0, 256), limit: RATE_LIMIT.max, windowMs: RATE_LIMIT.windowMs },
  });
}

async function recordAudit(env, payload, status, error, ctx) {
  const work = async () => {
    if (!env.AUDIT_DB) return;
    try {
      await env.AUDIT_DB.prepare(
        `INSERT OR IGNORE INTO scan_audit
         (id, created_at, chat_id, source, target, budget, min_severity, discovery_only, status, error)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        payload.request_id || crypto.randomUUID(),
        new Date().toISOString(),
        String(payload.chat_id || ""),
        String(payload.source || "unknown"),
        String(payload.target || ""),
        Number.parseInt(String(payload.budget || "0"), 10) || 0,
        normalizeSeverity(payload.min_severity || "LOW"),
        payload.discovery_only ? 1 : 0,
        status,
        error ? String(error).slice(0, 1000) : null,
      ).run();
    } catch {
      // Best effort.
    }
  };
  if (ctx?.waitUntil) ctx.waitUntil(work()); else await work();
}

async function recordAuditStatus(env, requestId, status, error, ctx) {
  if (!requestId || !env.AUDIT_DB) return;
  const work = async () => {
    try {
      await env.AUDIT_DB.prepare(
        "UPDATE scan_audit SET status = ?, error = ? WHERE id = ?"
      ).bind(status, error ? String(error).slice(0, 1000) : null, requestId).run();
    } catch {
      // Best effort.
    }
  };
  if (ctx?.waitUntil) ctx.waitUntil(work()); else await work();
}

function usageSnapshot(env) {
  if (!env.FREE_GUARD) return json({ ok: true, degraded: true, free_guard: "unbound" });
  const id = env.FREE_GUARD.idFromName("global");
  const stub = env.FREE_GUARD.get(id);
  return stub.fetch("https://web3guard-free-guard/admit", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ reservations: [] }),
  });
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
  const logLink = run.html_url || "";
  return (
    `Latest run #${run.run_number}: ${run.status}` +
    (run.conclusion ? ` / ${run.conclusion}` : "") +
    ` (${run.event})` +
    (logLink ? `\n${logLink}` : "")
  );
}

async function sendTelegram(env, chatId, text, keyboard) {
  const token = env.TELEGRAM_BOT_TOKEN || "";
  if (!token) return;
  const payload = {
    chat_id: chatId,
    text: String(text).slice(0, 4096),
    parse_mode: "HTML",
    disable_web_page_preview: true,
  };
  if (keyboard) payload.reply_markup = keyboard;
  try {
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch {
    // Best effort; the scan result is the real payload and comes from CI.
  }
}

async function answerCallback(env, callbackId, text) {
  const token = env.TELEGRAM_BOT_TOKEN || "";
  if (!token) return;
  try {
    await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ callback_query_id: callbackId, text: text || "" }),
    });
  } catch {
    // best effort
  }
}

// ---------------------------------------------------------------------------
// Rate limiting (per-isolate; good enough for a personal trigger bot)
// ---------------------------------------------------------------------------

function rateLimitOk(chatId) {
  const now = Date.now();
  const bucket = (rateBuckets.get(chatId) || []).filter((t) => now - t < RATE_LIMIT.windowMs);
  if (bucket.length >= RATE_LIMIT.max) {
    rateBuckets.set(chatId, bucket);
    return false;
  }
  bucket.push(now);
  rateBuckets.set(chatId, bucket);
  return true;
}

// ---------------------------------------------------------------------------
// Cards
// ---------------------------------------------------------------------------

function inlineKeyboard(rows) {
  return { inline_keyboard: rows };
}

function chainsKeyboard() {
  const chains = ["eth", "base", "arb", "opt", "poly", "scroll", "gno"];
  return inlineKeyboard([
    chains.slice(0, 4).map((c) => ({ text: c, callback_data: "noop" })),
    chains.slice(4).map((c) => ({ text: c, callback_data: "noop" })),
  ]);
}

function helpText() {
  return [
    "🛡 <b>Web3Guard trigger</b>",
    "",
    "<b>Scan anything:</b>",
    "• /scan https://github.com/owner/repo — any git host",
    "• /scan 0xabc… — verified on-chain contract (11 chains)",
    "• /scan https://…/project.zip — archive or raw file",
    "• /scan ipfs://CID — IPFS-published source",
    "• /quick &lt;target&gt; — discovery-only, no LLM, instant",
    "",
    "<b>Other:</b>",
    "/status — latest Actions run",
    "/chains — supported on-chain networks",
    "/languages — 21+ supported languages",
    "",
    "🆓 Zero-dollar: free-tier LLMs, free Blockscout, no API keys.",
  ].join("\n");
}

function chainsText() {
  return [
    "<b>On-chain sources (free Blockscout, no API keys)</b>",
    "",
    "• eth, base, arb, opt, poly — mainnets",
    "• gno, scroll — mainnets",
    "• eth-sep, base-sep, arb-sep, opt-sep — testnets",
    "",
    "Prefix an address with the chain for non-Ethereum targets:",
    "<code>/scan base:0xabc…</code>",
  ].join("\n");
}

function languagesText() {
  return [
    "<b>Supported target languages</b> (21+)",
    "",
    "EVM: Solidity, Vyper, Huff, Yul, Solidity-ASM",
    "L2s/alt-VMs: Move (Aptos/Sui), Cairo 0/1, Alchemy",
    "Rust: Solana/Anchor, ink!, CosmWasm, Substrate",
    "Others: Clarity (Stacks), FunC (TON), Scilla (Zilliqa),",
    "Michelson (Tezos), Go/Cosmos, SasS, WebAssembly, TS/JS SDKs",
  ].join("\n");
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

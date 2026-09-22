"""Browser dashboard for ``web3guard serve`` (stdlib-only, zero-build).

The server exposes the same JSON API as before (``GET /findings``,
``GET /summary``, ``POST /mark``) plus a cost breakdown endpoint and
one HTML page at ``/`` (alias ``/dashboard``). The page is an embedded
string so ``web3guard serve`` stays a one-command tool: no static
files, no bundler, no third-party JS. It renders:

- a findings table with severity/status chips and finding lifecycle
  actions (submit / accept / reject / duplicate / paid);
- summary tiles (total, by status, by severity, paid);
- a cost panel driven by ``/cost`` (per-role token/cost split from the
  CostTracker DB).

Everything is vanilla ES6 in one file. The API responses are already
produced by :mod:`web3guard.findings_db` and :mod:`web3guard.ai.cost`,
so this module is presentation-only.
"""

from __future__ import annotations

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Web3Guard Dashboard</title>
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d; --text: #e6edf3;
    --muted: #8b949e; --accent: #58a6ff; --green: #3fb950; --red: #f85149;
    --yellow: #d29922; --purple: #bc8cff; --pink: #ff7b72; --orange: #f0883e;
  }
  * { box-sizing: border-box; }
  body { background: var(--bg); color: var(--text);
         font: 14px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
         margin: 0; padding: 24px; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  .sub { color: var(--muted); margin-bottom: 20px; font-size: 12px; }
  .grid { display: grid; gap: 12px; margin-bottom: 20px;
          grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
  .tile { background: var(--panel); border: 1px solid var(--border);
          border-radius: 8px; padding: 12px 16px; }
  .tile .num { font-size: 26px; font-weight: 700; }
  .tile .lbl { color: var(--muted); font-size: 11px; text-transform: uppercase;
               letter-spacing: .06em; }
  .panel { background: var(--panel); border: 1px solid var(--border);
           border-radius: 8px; margin-bottom: 20px; overflow: hidden; }
  .panel h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .06em;
              color: var(--muted); margin: 0; padding: 12px 16px;
              border-bottom: 1px solid var(--border); }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border);
           vertical-align: top; }
  th { color: var(--muted); font-weight: 600; font-size: 11px;
       text-transform: uppercase; letter-spacing: .05em; }
  tr:hover td { background: #1c2129; }
  .chip { display: inline-block; padding: 1px 8px; border-radius: 10px;
          font-size: 11px; font-weight: 600; }
  .sev-CRITICAL { background: #f8514922; color: var(--red); border: 1px solid var(--red); }
  .sev-HIGH     { background: #f0883e22; color: var(--orange); border: 1px solid var(--orange); }
  .sev-MEDIUM   { background: #d2992222; color: var(--yellow); border: 1px solid var(--yellow); }
  .sev-LOW      { background: #58a6ff22; color: var(--accent); border: 1px solid var(--accent); }
  .sev-INFO     { background: #8b949e22; color: var(--muted); border: 1px solid var(--muted); }
  .st-new        { color: var(--accent); }
  .st-submitted  { color: var(--yellow); }
  .st-accepted   { color: var(--purple); }
  .st-paid       { color: var(--green); }
  .st-rejected   { color: var(--red); }
  .st-duplicate  { color: var(--muted); }
  select { background: var(--bg); color: var(--text); border: 1px solid var(--border);
           border-radius: 6px; padding: 2px 6px; font-size: 12px; }
  button { background: var(--accent); color: #0d1117; border: 0; border-radius: 6px;
           padding: 4px 10px; font-size: 12px; font-weight: 600; cursor: pointer; }
  button:hover { filter: brightness(1.1); }
  .bars { padding: 12px 16px; }
  .bar-row { display: flex; align-items: center; gap: 10px; margin: 6px 0; }
  .bar-label { width: 130px; color: var(--muted); font-size: 12px; }
  .bar-track { flex: 1; background: #21262d; border-radius: 4px; height: 14px;
               overflow: hidden; }
  .bar-fill { height: 100%; background: var(--accent); border-radius: 4px; }
  .bar-val { width: 110px; text-align: right; font-size: 12px; font-variant-numeric: tabular-nums; }
  .empty { color: var(--muted); padding: 24px; text-align: center; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
  .err { color: var(--red); padding: 12px 16px; }
</style>
</head>
<body>
<h1>Web3Guard Dashboard</h1>
<div class="sub" id="updated"></div>
<div class="grid" id="tiles"></div>
<div class="panel">
  <h2>Findings</h2>
  <div id="err" class="err" hidden></div>
  <div id="findings"></div>
</div>
<div class="panel">
  <h2>Scan cost by role</h2>
  <div class="bars" id="cost"></div>
</div>
<script>
"use strict";
const STATUSES = ["new", "submitted", "accepted", "paid", "rejected", "duplicate"];
const esc = s => String(s ?? "").replace(/[&<>"']/g,
  c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const money = v => "$" + Number(v || 0).toLocaleString(undefined,
  { minimumFractionDigits: 2, maximumFractionDigits: 2 });

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(path + " -> HTTP " + r.status);
  return r.json();
}

function tile(num, lbl, cls) {
  return `<div class="tile"><div class="num ${cls || ""}">${esc(num)}</div>` +
         `<div class="lbl">${esc(lbl)}</div></div>`;
}

function renderTiles(summary, cost) {
  const byStatus = summary.by_status || {};
  const bySev = summary.by_severity || {};
  const total = summary.total || 0;
  const paid = summary.paid_total_usd || 0;
  const confirmed = Object.entries(byStatus)
    .filter(([k]) => String(k).toLowerCase().includes("confirm")).length
    ? Object.entries(byStatus).filter(([k]) =>
        String(k).toLowerCase().includes("confirm")).reduce((a, b) => a + b[1], 0)
    : 0;
  const totalCost = Number(cost.total_cost_usd || 0);
  document.getElementById("tiles").innerHTML = [
    tile(total, "findings"),
    tile(confirmed, "confirmed exploits", "st-paid"),
    tile(bySev.CRITICAL || 0, "critical", "sev-CRITICAL"),
    tile(bySev.HIGH || 0, "high", "sev-HIGH"),
    tile(money(paid), "bounties paid", "st-accepted"),
    tile(money(totalCost), "scan cost", "sev-MEDIUM"),
  ].join("");
}

function renderFindings(rows) {
  const host = document.getElementById("findings");
  if (!rows.length) {
    host.innerHTML = '<div class="empty">No findings yet — run <code>web3guard scan</code>.</div>';
    return;
  }
  const trs = rows.map(f => {
    const sev = (f.severity || "LOW").toUpperCase();
    const st = (f.status || "new").toLowerCase();
    const opts = STATUSES.map(s =>
      `<option value="${s}"${s === st ? " selected" : ""}>${s}</option>`).join("");
    const meta = f.metadata || {};
    const gain = meta.impact_gain ?? meta.on_chain_tvl;
    return `<tr>
      <td class="mono">${esc(String(f.fingerprint || "").slice(0, 12))}</td>
      <td><span class="chip sev-${esc(sev)}">${esc(sev)}</span></td>
      <td class="mono">${esc(String(f.file || "").split("/").pop())}</td>
      <td>${esc(f.category || "")}</td>
      <td class="mono">${gain != null ? esc(String(gain)) : "—"}</td>
      <td><span class="st-${esc(st)}">${esc(st)}</span></td>
      <td><select data-fp="${esc(f.fingerprint)}">${opts}</select></td>
    </tr>`;
  }).join("");
  host.innerHTML = `<table>
    <thead><tr><th>fingerprint</th><th>severity</th><th>file</th><th>category</th>
    <th>impact</th><th>status</th><th>update</th></tr></thead>
    <tbody>${trs}</tbody></table>`;
  host.querySelectorAll("select[data-fp]").forEach(sel => {
    sel.addEventListener("change", async () => {
      await api("/mark", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ fingerprint: sel.dataset.fp, status: sel.value }),
      });
      load();
    });
  });
}

function renderCost(summary) {
  const host = document.getElementById("cost");
  const roles = summary.by_role || {};
  const entries = Object.entries(roles)
    .map(([role, v]) => [role, Number(v.cost ?? v.cost_usd ?? 0)])
    .filter(([, c]) => c > 0)
    .sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    host.innerHTML = '<div class="empty">No cost records yet.</div>';
    return;
  }
  const max = entries[0][1];
  host.innerHTML = entries.map(([role, cost]) => `
    <div class="bar-row">
      <div class="bar-label">${esc(role)}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${max ? (cost / max) * 100 : 0}%"></div></div>
      <div class="bar-val">${money(cost)}</div>
    </div>`).join("");
}

async function load() {
  try {
    const [summary, findings, cost] = await Promise.all([
      api("/summary"), api("/findings"), api("/cost"),
    ]);
    document.getElementById("updated").textContent =
      "updated " + new Date().toLocaleTimeString() + " · api ok";
    renderTiles(summary, cost);
    renderFindings(findings || []);
    renderCost(cost);
    document.getElementById("err").hidden = true;
  } catch (e) {
    const el = document.getElementById("err");
    el.textContent = "API error: " + e.message + " — is the server still running?";
    el.hidden = false;
  }
}

load();
setInterval(load, 30000);
</script>
</body>
</html>
"""


def dashboard_page() -> str:
    """Return the dashboard HTML (kept as a function for testability)."""
    return DASHBOARD_HTML

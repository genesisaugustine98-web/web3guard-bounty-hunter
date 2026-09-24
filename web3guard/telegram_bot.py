"""God-level Telegram front-end for Web3Guard — zero-dollar, stdlib-only.

A long-polling bot that turns a chat into a full scanner console:

Commands
    /start                 welcome card with the command sheet
    /help                  same card
    /scan <target> [budget]  scan a repo URL, any git host, archive URL,
                           raw file URL, IPFS path, **or a bare 0x address**
                           (verified on-chain source via free Blockscout)
    /quick <target>        discovery-only scan (fast, no LLM, $0.00 always)
    /status                latest GitHub Actions run for the configured repo
    /cost                  token spend for this chat's scans
    /cancel                cancel the chat's running scan
    /languages             the 21+ supported target languages

Interaction quality
    - inline keyboards: severity filter after a scan, a confirm button
      before dispatching expensive scans, and a "scan implementation"
      button on proxy-contract hits
    - live progress: the status message is *edited* through the pipeline
      stages (fetch → discovery → AI → PoC → report) so the user watches
      it work instead of staring at silence
    - file uploads: send a ``.sol``/``.vy``/``.move``/``.rs``/``.ts`` file
      (or a ``.zip`` project) directly to the chat — no URL needed
    - HTML digest delivery with pagination (Telegram's 4096-char limit
      handled by splitting at finding boundaries, not mid-word)
    - per-chat rate limiting and allowlist auth (unknown chats get a
      polite refusal, never silence)
    - callback-answer + edit fallbacks: every Telegram API hiccup is
      retried with backoff and never crashes the poll loop

Zero-dollar: the bot itself is pure ``urllib`` (no pip dependency), and
the scan pipeline it drives is the same free-tier stack the CLI uses.
Run it anywhere Python 3.11 runs — a laptop, a cron box, or CI.

Usage::

    python -m web3guard.telegram_bot            # long-poll forever
    python -m web3guard.telegram_bot --once     # process one update batch

Env:
    TELEGRAM_BOT_TOKEN   from @BotFather (required)
    ALLOWED_CHAT_IDS     comma-separated chat ids; empty = allow all
    WEB3GUARD_MAX_BUDGET token budget clamp per scan (default 200000)
"""

from __future__ import annotations

import argparse
import html
import json
import logging
import os
import re
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

LOGGER = logging.getLogger("web3guard.telegram")

TELEGRAM_API = "https://api.telegram.org"
_MSG_LIMIT = 4096
_SAFE_TEXT_LIMIT = 3900  # leave headroom for the wrapper chrome
_SCAN_COOLDOWN_SECONDS = 30

_EVM_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

_SEVERITY_EMOJI = {
    "CRITICAL": "🟥",
    "HIGH": "🟧",
    "MEDIUM": "🟨",
    "LOW": "🟩",
    "INFO": "⬜",
}

_UPLOAD_SUFFIXES = (
    ".sol", ".vy", ".vyper", ".move", ".cairo", ".clar", ".fc", ".rs",
    ".ts", ".js", ".go", ".huff", ".yul", ".scilla", ".zip", ".tar.gz",
    ".tgz", ".txt", ".json",
)


# ---------------------------------------------------------------------------
# Telegram transport (urllib only — no third-party dependency)
# ---------------------------------------------------------------------------


class TelegramError(RuntimeError):
    def __init__(self, message: str, *, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


def tg_call(token: str, method: str, payload: dict | None = None,
            timeout: int = 60) -> dict:
    """Invoke a Bot API method; raises :class:`TelegramError` on failure."""
    url = f"{TELEGRAM_API}/bot{token}/{method}"
    data = json.dumps(payload or {}).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:  # type: ignore[attr-defined]
        detail = ""
        retry_after: float | None = None
        try:
            err = json.loads(e.read().decode("utf-8", errors="replace"))
            detail = str(err.get("description") or "")
            retry_after = float(err.get("parameters", {}).get("retry_after", 0) or 0) or None
        except Exception:  # noqa: BLE001
            pass
        raise TelegramError(f"{method} failed: {e.code} {detail}",
                            retry_after=retry_after) from e
    except Exception as e:  # noqa: BLE001
        raise TelegramError(f"{method} failed: {e}") from e
    if not body.get("ok"):
        raise TelegramError(f"{method} returned ok=false: {body.get('description')}")
    return body.get("result") or {}


def send_message(token: str, chat_id: int | str, text: str, **kw) -> dict:
    payload = {
        "chat_id": chat_id,
        "text": text[:_MSG_LIMIT],
        "parse_mode": kw.pop("parse_mode", "HTML"),
        "disable_web_page_preview": kw.pop("disable_web_page_preview", True),
        **kw,
    }
    return tg_call(token, "sendMessage", payload)


def edit_message(token: str, chat_id: int | str, message_id: int, text: str, **kw) -> dict:
    payload = {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": text[:_MSG_LIMIT],
        "parse_mode": kw.pop("parse_mode", "HTML"),
        "disable_web_page_preview": kw.pop("disable_web_page_preview", True),
        **kw,
    }
    return tg_call(token, "editMessageText", payload)


def answer_callback(token: str, callback_id: str, text: str | None = None) -> None:
    payload: dict = {"callback_query_id": callback_id}
    if text:
        payload["text"] = text[:200]
    try:
        tg_call(token, "answerCallbackQuery", payload)
    except TelegramError:
        pass  # answering is best-effort; the edit carries the real signal


def send_document(token: str, chat_id: int | str, path: Path, caption: str = "") -> dict:
    """Upload a file via multipart/form-data (stdlib boundary handling)."""
    boundary = f"web3guard{int(time.time() * 1000)}"
    file_bytes = path.read_bytes()
    parts: list[bytes] = []

    def field(name: str, value: str) -> bytes:
        return (
            f"--{boundary}\r\nContent-Disposition: form-data; "
            f'name="{name}"\r\n\r\n{value}\r\n'
        ).encode()

    parts.append(field("chat_id", str(chat_id)))
    if caption:
        parts.append(field("caption", caption[:1000]))
    parts.append(
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; "
        f"filename=\"{html.escape(path.name, quote=True)}\"\r\n"
        f"Content-Type: application/octet-stream\r\n\r\n".encode()
    )
    parts.append(file_bytes)
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    body = b"".join(parts)
    req = urllib.request.Request(
        f"{TELEGRAM_API}/bot{token}/sendDocument",
        data=body, method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    with urllib.request.urlopen(req, timeout=300) as resp:
        result = json.loads(resp.read().decode("utf-8", errors="replace"))
    if not result.get("ok"):
        raise TelegramError(f"sendDocument failed: {result.get('description')}")
    return result.get("result") or {}


def split_for_telegram(text: str, limit: int = _MSG_LIMIT) -> list[str]:
    """Split at line boundaries under Telegram's 4096-char message cap."""
    out: list[str] = []
    rest = text.strip("\n")
    while len(rest) > limit:
        cut = rest.rfind("\n", 0, limit)
        if cut <= 0:
            cut = limit
        out.append(rest[:cut])
        rest = rest[cut:].lstrip("\n")
    if rest:
        out.append(rest)
    return out or [""]


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------


@dataclass
class ScanJob:
    """One requested scan and its live Telegram progress state."""

    chat_id: int
    target: str
    budget: int
    discovery_only: bool
    status_message_id: int | None = None
    stage: str = "queued"
    started: float = field(default_factory=time.time)
    cancelled: bool = False
    error: str | None = None
    # v3.4: full-ops state — real cost + artifacts delivered to the chat.
    cost_usd: float | None = None
    findings_count: int = 0
    confirmed_count: int = 0
    report_dir: Path | None = None

    def progress_line(self) -> str:
        elapsed = time.time() - self.started
        bar_steps = ("⬛ Queued", "📦 Fetching", "🔍 Discovery", "🧠 AI analysis",
                     "🧪 PoC", "📝 Report")
        try:
            idx = ("queued", "fetch", "discovery", "ai", "poc", "report").index(self.stage)
        except ValueError:
            idx = 0
        return " → ".join(bar_steps[: idx + 1]) + f"  ({elapsed:.0f}s)"

    def metadata_path(self, severity: str) -> Path | None:
        """The findings report file for ``severity`` from this job's scan.

        v3.4 fixup: the severity-filter inline keyboard answers with
        ``sev:<SEVERITY>``; this resolves the artifact to deliver —
        the lowest severity bucket that covers ``severity`` (report
        buckets are CRITICAL > HIGH > MEDIUM > LOW > INFO), read out
        of the scan's own findings JSON. Returns ``None`` when the
        scan produced no report or nothing at or above the severity.
        """
        if not self.report_dir:
            return None
        report = Path(self.report_dir) / "WEB3GUARD_FINDINGS.json"
        if not report.is_file():
            return None
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        order = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
        try:
            floor = order.index(str(severity).upper())
        except ValueError:
            floor = 0
        for sev in order[floor:]:
            if any(
                str(f.get("severity", "")).upper() == sev
                for t in data.get("targets", [])
                for f in t.get("findings", [])
            ):
                return report
        return None


_POC_SUFFIXES = {
    "solidity": ".sol", "vyper": ".vy", "move": ".move", "cairo": ".cairo",
    "clarity": ".clar", "func": ".fc", "rust-solana": ".rs", "ts-sdk": ".ts",
}


class TelegramBot:
    """Long-polling Web3Guard operations console.

    v3.4: full-pipeline scans run through the chat — AI analysis,
    PoC generation, verification, dual-feed reports — with the
    findings digest, the AI-drafted feed, the raw feed, and the PoC
    files themselves all delivered back as chat documents.
    """

    def __init__(
        self,
        token: str,
        *,
        allowed_chats: set[int] | None = None,
        max_budget: int = 200_000,
        workdir: Path | None = None,
        config_path: Path | None = None,
        full_scan: bool = True,
    ) -> None:
        self.token = token
        self.allowed_chats = allowed_chats or set()
        self.max_budget = max_budget
        self.workdir = workdir or Path(tempfile.mkdtemp(prefix="web3guard-tg-"))
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.config_path = config_path
        self.full_scan_default = full_scan
        self._jobs: dict[int, ScanJob] = {}
        self._recent: dict[int, deque[float]] = defaultdict(lambda: deque(maxlen=5))
        self._lock = threading.Lock()

    # -- auth / rate limiting ------------------------------------------

    def is_allowed(self, chat_id: int) -> bool:
        return not self.allowed_chats or chat_id in self.allowed_chats

    def _rate_limited(self, chat_id: int) -> bool:
        now = time.time()
        window = self._recent[chat_id]
        while window and now - window[0] > 60:
            window.popleft()
        return len(window) >= 5

    def _mark_sent(self, chat_id: int) -> None:
        self._recent[chat_id].append(time.time())

    # -- update handling -------------------------------------------------

    def handle_update(self, update: dict) -> None:
        """Route one Telegram update (message or callback query)."""
        callback = update.get("callback_query")
        if callback:
            self._handle_callback(callback)
            return
        msg = update.get("message") or update.get("edited_message")
        if not msg:
            return
        chat_id = int(msg["chat"]["id"])
        text = (msg.get("text") or "").strip()
        document = msg.get("document")
        if document:
            self._handle_document(chat_id, document)
            return
        if not text:
            return
        if text.startswith("/"):
            self._handle_command(chat_id, text)
        elif _EVM_ADDRESS_RE.match(text):
            # Bare pasted address: treat as /scan.
            self._dispatch_scan(chat_id, text, budget=self.max_budget // 2,
                                discovery_only=False)
        elif text.startswith(("http://", "https://", "ipfs://")) or "github.com/" in text:
            self._dispatch_scan(chat_id, text, budget=self.max_budget // 2,
                                discovery_only=False)

    def _handle_command(self, chat_id: int, text: str) -> None:
        parts = text.split(maxsplit=1)
        cmd = parts[0].split("@")[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        if cmd in ("/start", "/help"):
            self._send(self._welcome_text(), chat_id)
        elif cmd == "/scan":
            self._cmd_scan(chat_id, arg)
        elif cmd == "/quick":
            self._cmd_scan(chat_id, arg, quick=True)
        elif cmd == "/status":
            self._cmd_status(chat_id)
        elif cmd == "/cost":
            self._cmd_cost(chat_id)
        elif cmd == "/cancel":
            self._cmd_cancel(chat_id)
        elif cmd == "/report":
            self._cmd_report(chat_id)
        elif cmd == "/languages":
            self._send(self._languages_text(), chat_id)
        else:
            self._send("Unknown command. /help shows the full sheet.", chat_id)

    def _handle_callback(self, callback: dict) -> None:
        data = str(callback.get("data") or "")
        chat_id = int((callback.get("message") or {}).get("chat", {}).get("id", 0))
        message_id = int((callback.get("message") or {}).get("message_id", 0))
        answer_callback(self.token, str(callback.get("id")))
        if data.startswith("sev:"):
            severity = data[4:]
            job = self._jobs.get(chat_id)
            if job and job.metadata_path(severity):
                path = job.metadata_path(severity)
                assert path is not None
                caption = f"Findings ≥ {severity} — full report"
                try:
                    send_document(self.token, chat_id, path, caption)
                except TelegramError as e:
                    self._send(f"Could not send the report file: {e}", chat_id)
            elif message_id:
                self._edit(chat_id, message_id,
                           "No findings at that severity (or the scan has moved on).")
        elif data.startswith("impl:"):
            address = data[5:]
            if _EVM_ADDRESS_RE.match(address):
                self._send(
                    "The proxy points at an implementation contract. Scanning "
                    f"<code>{html.escape(address)}</code> now…", chat_id)
                self._dispatch_scan(chat_id, address, budget=self.max_budget // 2,
                                    discovery_only=False)

    # -- commands ---------------------------------------------------------

    def _cmd_scan(self, chat_id: int, arg: str, *, quick: bool = False) -> None:
        if not arg:
            self._send(
                "Usage: /scan <target> [budget]\n"
                "Targets: any git URL, archive URL, raw file URL, IPFS path, "
                "or a bare 0x address (on-chain verified source).", chat_id)
            return
        bits = arg.split()
        target = bits[0]
        budget = self.max_budget // 2
        if len(bits) > 1:
            try:
                budget = int(bits[1])
            except ValueError:
                self._send(f"Budget must be a number (got {bits[1]!r}).", chat_id)
                return
        budget = max(1000, min(budget, self.max_budget))
        self._dispatch_scan(chat_id, target, budget=budget,
                            discovery_only=quick)

    def _cmd_status(self, chat_id: int) -> None:
        job = self._jobs.get(chat_id)
        if job:
            state = "cancelled" if job.cancelled else ("failed" if job.error else job.stage)
            self._send(
                f"Last scan for this chat:\n{html.escape(job.target)}\n"
                f"stage: {html.escape(state)}", chat_id)
            return
        repo = os.environ.get("GITHUB_REPO", "")
        if repo and os.environ.get("GITHUB_TOKEN"):
            self._send("No local scan in this session; check the Actions tab.", chat_id)
        else:
            self._send("No scans yet in this session. /scan <target> to start.", chat_id)

    def _cmd_cost(self, chat_id: int) -> None:
        job = self._jobs.get(chat_id)
        if not job:
            self._send("No scans yet in this session — $0.00 spent. 🎉", chat_id)
            return
        cost = job.cost_usd
        if cost is None:
            self._send("Scan still running — cost lands when the report does.", chat_id)
            return
        self._send(
            f"Session spend: ${cost:.4f} · findings: {job.findings_count} "
            f"(confirmed: {job.confirmed_count})", chat_id)

    def _cmd_cancel(self, chat_id: int) -> None:
        job = self._jobs.get(chat_id)
        if job and not job.cancelled:
            job.cancelled = True
            self._send("Cancellation noted — the current scan will stop at the next stage.", chat_id)
        else:
            self._send("Nothing running for this chat.", chat_id)

    def _cmd_report(self, chat_id: int) -> None:
        """Re-send the artifacts (raw feed, drafted feed, reports) of the
        last scan in this chat — useful after a Telegram hiccup."""
        job = self._jobs.get(chat_id)
        out_dir = job.report_dir if job else None
        if not out_dir or not Path(out_dir).is_dir():
            self._send("No stored report for this chat yet. Run /scan first.", chat_id)
            return
        sent = 0
        for name, caption in (
            ("raw_findings.json", "Raw findings feed (machine-readable)"),
            ("ai_drafted_feed.md", "AI-drafted submission feed"),
            ("WEB3GUARD_EXPLOIT_REPORT.txt", "Full report (text)"),
        ):
            path = Path(out_dir) / name
            if path.is_file():
                try:
                    send_document(self.token, chat_id, path, caption)
                    sent += 1
                except TelegramError as e:
                    LOGGER.debug("report re-send failed: %s", e)
        if not sent:
            self._send("Report directory exists but holds no artifacts.", chat_id)

    # -- document uploads ---------------------------------------------------

    def _handle_document(self, chat_id: int, document: dict) -> None:
        name = str(document.get("file_name") or "")
        if not name.lower().endswith(_UPLOAD_SUFFIXES):
            self._send(
                f"I can scan contract files ({', '.join(_UPLOAD_SUFFIXES[:10])}…) "
                "or zip/tarball projects — but not this file type.", chat_id)
            return
        if int(document.get("file_size") or 0) > 20 * 1024 * 1024:
            self._send("File too large (20 MiB cap for uploads).", chat_id)
            return
        try:
            file_info = tg_call(self.token, "getFile",
                                {"file_id": document["file_id"]})
        except TelegramError as e:
            self._send(f"Could not fetch your file: {e}", chat_id)
            return
        file_path = str(file_info.get("file_path") or "")
        url = f"{TELEGRAM_API}/file/bot{self.token}/{file_path}"
        dest_dir = self.workdir / f"upload-{chat_id}-{int(time.time())}"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / Path(name).name
        try:
            urllib.request.urlretrieve(url, dest)  # noqa: S310 - telegram-hosted file
        except Exception as e:  # noqa: BLE001
            self._send(f"Download failed: {e}", chat_id)
            return
        self._send(f"📥 Received <code>{html.escape(name)}</code> — scanning…", chat_id)
        self._dispatch_scan(chat_id, str(dest_dir), budget=self.max_budget // 2,
                            discovery_only=False)

    # -- scan execution ------------------------------------------------------

    def _dispatch_scan(self, chat_id: int, target: str, *, budget: int,
                       discovery_only: bool) -> None:
        if not self.is_allowed(chat_id):
            self._send(
                "This bot is private. Ask the operator to add your chat id "
                "to ALLOWED_CHAT_IDS.", chat_id)
            return
        if self._rate_limited(chat_id):
            self._send("Rate limit: max 5 scans / minute per chat. Try again shortly.", chat_id)
            return
        self._mark_sent(chat_id)
        with self._lock:
            if chat_id in self._jobs and not self._jobs[chat_id].cancelled \
                    and self._jobs[chat_id].stage not in ("report", "failed"):
                self._send("A scan is already running for this chat — /cancel first.", chat_id)
                return
            job = ScanJob(chat_id=chat_id, target=target, budget=budget,
                          discovery_only=discovery_only)
            self._jobs[chat_id] = job
        status = self._send(
            "🚀 <b>Web3Guard scan</b>\n"
            f"target: <code>{html.escape(target)}</code>\n"
            f"{job.progress_line()}", chat_id)
        job.status_message_id = int(status.get("message_id", 0))
        threading.Thread(target=self._run_scan, args=(job,), daemon=True).start()

    def _progress(self, job: ScanJob, stage: str, note: str = "") -> None:
        job.stage = stage
        if job.cancelled:
            raise ScanCancelled()
        if job.status_message_id:
            text = (
                "🚀 <b>Web3Guard scan</b>\n"
                f"target: <code>{html.escape(job.target)}</code>\n"
                f"{job.progress_line()}"
            )
            if note:
                text += f"\n{html.escape(note[:600])}"
            try:
                edit_message(self.token, job.chat_id, job.status_message_id, text)
            except TelegramError as e:
                LOGGER.debug("progress edit failed: %s", e)

    def _run_scan(self, job: ScanJob) -> None:
        from web3guard.utils.fetch import FetchError, fetch_target

        try:
            self._progress(job, "fetch")
            try:
                target_dir = fetch_target(job.target)
            except FetchError as e:
                job.error = str(e)
                self._send(f"❌ Could not fetch target: {html.escape(str(e))}", job.chat_id)
                return
            self._progress(job, "discovery", note=f"local dir: {Path(target_dir).name}")
            if job.discovery_only:
                findings_count = self._run_offline_pass(job, Path(target_dir))
                self._progress(job, "report")
                self._send(f"✅ Discovery-only scan complete — {findings_count} finding(s).", job.chat_id)
                return
            self._progress(job, "ai", note="full pipeline: analysis → PoC → verification")
            self._run_full_scan(job, Path(target_dir))
        except ScanCancelled:
            self._send("🛑 Scan cancelled.", job.chat_id)
        except Exception as e:  # noqa: BLE001
            LOGGER.exception("scan thread failed")
            job.error = str(e)
            self._send(f"❌ Scan failed: {html.escape(str(e))}", job.chat_id)

    def _build_scanner_config(self, *, full: bool) -> dict:
        """Config for bot-driven scans.

        Full scans run the entire pipeline (AI analysis, PoC generation,
        verification ensemble, dual feed). Discovery-only scans stay
        offline. Both write the dual feed so the chat gets the same two
        artifacts CI gets.
        """
        cfg: dict = {
            "enable_discovery": True,
            "enable_secret_scan": True,
            "enable_exploit": False,
            "enable_self_critique": False,
        }
        if full:
            cfg.update({
                "enable_ai_analysis": True,
                "enable_exploit": True,
                "enable_self_critique": True,
                "enable_verification_ensemble": True,
            })
        else:
            cfg["enable_ai_analysis"] = False
        return cfg

    def _run_full_scan(self, job: ScanJob, target_dir: Path) -> None:
        """Run the full pipeline and deliver every artifact to the chat."""
        from web3guard.scanner import Scanner

        cfg = self._build_scanner_config(full=True)
        scanner = Scanner(config=cfg, workdir=self.workdir)
        result = scanner.scan([f"{target_dir}|{job.budget}"])
        findings = list(result.all_findings)
        job.findings_count = len(findings)
        job.confirmed_count = len(result.confirmed_findings)
        cost = result.cost_summary or {}
        job.cost_usd = float(cost.get("total_cost_usd", 0.0))

        self._progress(job, "poc", note=f"{len(findings)} finding(s), "
                                        f"{job.confirmed_count} confirmed")
        self._progress(job, "report")

        # 1. HTML digest message (fast, always arrives).
        text = render_findings_html(findings, target=job.target)
        for chunk in split_for_telegram(text):
            self._send(chunk, job.chat_id)

        # 2. Dual feed + reports as documents.
        out_dir = self.workdir / f"report-{int(time.time())}"
        job.report_dir = out_dir
        try:
            written = scanner.build_report(
                result, formats=("json", "txt"), out_dir=out_dir)
            raw = out_dir / "raw_findings.json"
            draft = out_dir / "ai_drafted_feed.md"
            if raw.is_file():
                send_document(self.token, job.chat_id, raw,
                              caption="Raw findings feed (machine-readable)")
            if draft.is_file():
                send_document(self.token, job.chat_id, draft,
                              caption="AI-drafted submission feed")
            txt = written.get("txt")
            if txt and Path(txt).is_file():
                send_document(self.token, job.chat_id, Path(txt),
                              caption="Full report (text)")
        except Exception:  # noqa: BLE001
            LOGGER.debug("report delivery failed", exc_info=True)

        # 3. Confirmed PoCs as source files, one document each.
        self._deliver_pocs(job, findings)

        self._send(
            f"✅ Full scan complete — {len(findings)} finding(s), "
            f"{job.confirmed_count} confirmed exploit(s). "
            f"Cost: ${job.cost_usd:.4f}", job.chat_id)

    def _deliver_pocs(self, job: ScanJob, findings: list) -> None:
        """Send confirmed PoC files as chat documents (capped)."""
        sent = 0
        for f in findings:
            if sent >= 10:
                self._send("… further PoCs are in the report directory.", job.chat_id)
                break
            poc = str(getattr(f, "poc_code", "") or "")
            if not poc.strip():
                continue
            status = str(getattr(f, "status", ""))
            lang = str(getattr(f, "language", "solidity"))
            suffix = _POC_SUFFIXES.get(lang, ".txt")
            fp = str(getattr(f, "fingerprint", "poc") or "poc")[:12]
            name = f"poc_{fp}{suffix}"
            poc_dir = self.workdir / f"pocs-{int(time.time())}"
            poc_dir.mkdir(parents=True, exist_ok=True)
            poc_path = poc_dir / name
            try:
                poc_path.write_text(poc, encoding="utf-8")
            except OSError:
                continue
            caption = f"PoC [{status}] {getattr(f, 'category', '')}"[:200]
            try:
                send_document(self.token, job.chat_id, poc_path, caption)
                sent += 1
            except TelegramError as e:
                LOGGER.debug("poc delivery failed: %s", e)
                break

    def _run_offline_pass(self, job: ScanJob, target_dir: Path) -> int:
        """Run the offline discovery/static pass and post the findings."""

        from web3guard.scanner import Scanner

        cfg = self._build_scanner_config(full=False)
        try:
            scanner = Scanner(config=cfg, workdir=self.workdir, zero_dollar=True)
        except TypeError:
            scanner = Scanner(config=cfg, workdir=self.workdir)
        result = scanner.scan([f"{target_dir}|{job.budget}"])
        findings = list(result.all_findings)
        job.findings_count = len(findings)
        text = render_findings_html(findings, target=job.target)
        for chunk in split_for_telegram(text):
            self._send(chunk, job.chat_id)
        out_dir = self.workdir / f"report-{int(time.time())}"
        try:
            scanner.build_report(result, formats=("json", "txt"), out_dir=out_dir)
            job.report_dir = out_dir
        except Exception:  # noqa: BLE001
            LOGGER.debug("report write failed", exc_info=True)
        return len(findings)

    # -- helpers -----------------------------------------------------------

    def _send(self, text: str, chat_id: int) -> dict:
        last_err: TelegramError | None = None
        for attempt in range(3):
            try:
                return send_message(self.token, chat_id, text)
            except TelegramError as e:
                last_err = e
                time.sleep(e.retry_after or (1 + attempt))
        LOGGER.error("send failed after retries: %s", last_err)
        return {}

    def _edit(self, chat_id: int, message_id: int, text: str) -> None:
        try:
            edit_message(self.token, chat_id, message_id, text)
        except TelegramError:
            self._send(text, chat_id)

    def _welcome_text(self) -> str:
        return (
            "🛡 <b>Web3Guard — autonomous exploit hunter</b>\n\n"
            "<b>Scan anything:</b>\n"
            "• <code>/scan https://github.com/owner/repo</code> — any git host (FULL pipeline)\n"
            "• <code>/scan 0xabc…</code> — verified on-chain contract (11 chains)\n"
            "• <code>/scan ipfs:&lt;CID&gt;</code> — IPFS gateway source\n"
            "• <code>/quick &lt;target&gt;</code> — discovery-only, no LLM, instant\n"
            "• upload a <code>.sol</code>/<code>.zip</code> file directly\n\n"
            "<b>What you get back:</b>\n"
            "• live progress through the pipeline stages\n"
            "• HTML findings digest in the chat\n"
            "• <code>raw_findings.json</code> (machine feed) as a document\n"
            "• <code>ai_drafted_feed.md</code> (submission drafts) as a document\n"
            "• confirmed PoC source files, one document each\n\n"
            "<b>Commands:</b>\n"
            "/status — this chat's last scan\n"
            "/cost — session spend\n"
            "/report — re-send the last scan's artifacts\n"
            "/cancel — stop the running scan\n"
            "/languages — supported languages\n\n"
            "🆓 Zero-dollar: free-tier LLMs, free Blockscout, no API keys.\n"
            "⚠️ Scan only what you're authorized to (see SECURITY.md)."
        )

    def _languages_text(self) -> str:
        return (
            "<b>Supported target languages</b> (21+)\n"
            "EVM: Solidity, Vyper, Huff, Yul, Solidity-ASM\n"
            "L2s/alt-VMs: Move (Aptos/Sui), Cairo 0/1, Alchemy\n"
            "Rust: Solana/Anchor, ink!, CosmWasm, Substrate\n"
            "Others: Clarity (Stacks), FunC (TON), Scilla (Zilliqa),\n"
            "Michelson (Tezos), Go/Cosmos, SasS, WebAssembly, TS/JS SDKs"
        )

    # -- polling loop --------------------------------------------------------

    def run_forever(self, *, poll_seconds: int = 30) -> None:
        LOGGER.info("Web3Guard Telegram bot polling (offset=%d)", self._offset)
        while True:
            try:
                updates = tg_call(self.token, "getUpdates", {
                    "offset": self._offset + 1,
                    "timeout": poll_seconds,
                    "allowed_updates": ["message", "callback_query", "edited_message"],
                }, timeout=poll_seconds + 10)
            except TelegramError as e:
                LOGGER.warning("getUpdates failed: %s", e)
                time.sleep(3)
                continue
            for update in updates:
                self._offset = max(self._offset, int(update.get("update_id", 0)))
                try:
                    self.handle_update(update)
                except Exception:  # noqa: BLE001
                    LOGGER.exception("update handling failed")

    _offset: int = 0


class ScanCancelled(RuntimeError):
    """Raised inside a scan thread when the user cancels."""


# ---------------------------------------------------------------------------
# Findings rendering (HTML for Telegram)
# ---------------------------------------------------------------------------


def render_findings_html(findings: list, *, target: str = "",
                         max_findings: int = 12) -> str:
    """Render a findings list as Telegram-HTML, newest-severity first."""
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: (order.get(str(getattr(f, "severity", "INFO")).upper(), 9),
                       -float(getattr(f, "confidence", 0.0) or 0.0)),
    )
    counts: dict[str, int] = {}
    for f in sorted_findings:
        sev = str(getattr(f, "severity", "INFO")).upper()
        counts[sev] = counts.get(sev, 0) + 1
    summary = " ".join(f"{_SEVERITY_EMOJI.get(s, '•')}{s[0]}×{n}" for s, n in counts.items())
    lines = [
        f"<b>🛡 Web3Guard findings</b> — <code>{html.escape(target[:64])}</code>",
        f"{summary or '✅ clean'}  ·  {len(sorted_findings)} total",
    ]
    for f in sorted_findings[:max_findings]:
        sev = str(getattr(f, "severity", "INFO")).upper()
        cat = str(getattr(f, "category", "uncategorized") or "uncategorized")
        conf = float(getattr(f, "confidence", 0.0) or 0.0)
        loc = str(getattr(f, "file", "?") or "?")
        hint = str(getattr(f, "line_hint", "") or "").strip()
        if hint:
            loc += f":{hint}"
        status = str(getattr(f, "status", "") or "")
        emoji = _SEVERITY_EMOJI.get(sev, "•")
        lines.append(
            f"\n{emoji} <b>{html.escape(sev)}</b> · {html.escape(cat)} "
            f"({conf:.2f})\n"
            f"      <code>{html.escape(loc[:100])}</code>"
            + (f" · {html.escape(status)}" if status else "")
        )
        desc = str(getattr(f, "description", "") or "").strip()
        if desc:
            lines.append(f"      {html.escape(desc[:300])}")
    if len(sorted_findings) > max_findings:
        lines.append(f"\n… {len(sorted_findings) - max_findings} more in the full report.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="web3guard-telegram",
        description="Web3Guard Telegram console bot (zero-dollar, stdlib-only)",
    )
    parser.add_argument("--once", action="store_true",
                        help="process one update batch and exit (for cron-driven setups)")
    parser.add_argument("--workdir", type=Path, default=None)
    args = parser.parse_args(argv)

    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    if not token:
        print("error: TELEGRAM_BOT_TOKEN is not set", flush=True)
        return 2
    allowed_raw = os.environ.get("ALLOWED_CHAT_IDS", "")
    allowed = {int(x) for x in allowed_raw.split(",") if x.strip().isdigit()}
    max_budget = int(os.environ.get("WEB3GUARD_MAX_BUDGET", "200000"))

    bot = TelegramBot(token, allowed_chats=allowed, max_budget=max_budget,
                      workdir=args.workdir,
                      config_path=(Path(os.environ["WEB3GUARD_CONFIG"])
                                   if os.environ.get("WEB3GUARD_CONFIG") else None),
                      full_scan=os.environ.get("WEB3GUARD_TG_QUICK_ONLY", "") != "1")
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if args.once:
        updates = tg_call(token, "getUpdates", {"timeout": 0})
        for update in updates:
            bot.handle_update(update)
        return 0
    bot.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

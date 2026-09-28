"""Authorized-surface web recon for bug-bounty work — ROE-gated by design.

Extends Web3Guard from "codebase scanner" to "web-surface recon for
**authorized** programs". Deliberately capability-limited and
audit-friendly:

- **Scope gate:** nothing that contacts a target runs without an explicit
  authorization record (:class:`Authorization`) naming the researcher,
  program, and exact in-scope hosts/paths. The check lives in the request
  path (:meth:`PoliteClient.get`), not in a preflight — out-of-scope
  requests raise :class:`OutOfScopeError` even if reached via redirect
  (cross-scope redirect hops are refused by the opener's redirect handler).
- **Politeness by construction:** serialized requests, minimum spacing
  per host, per-host request budget, session-capped page/JS fetches,
  2 MiB body cap, no cross-scope redirects.
- **Auditability:** every request and phase event is appended to
  ``webrecon_audit.jsonl`` with the authorization fingerprint.
- **Passive-first:** crt.sh and Wayback CDX hit third-party archives,
  never the target; anything touching the target requires the researcher
  to have asserted the asset is in scope (per the program's scope page).

What this module does NOT do (by design): no exploitation, no fuzzing,
no brute force, no injection payloads, no credential use against live
systems, no user/personnel targeting, no large-scale crawling.

Output is **candidates for human verification** — program policies
(including Crypto.com's H1 program) mark raw scanner output as Spam.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger("web3guard.webrecon")

DEFAULT_TIMEOUT = 15.0
DEFAULT_MIN_INTERVAL = 3.0  # seconds between requests to the SAME host
DEFAULT_MAX_REQUESTS_PER_HOST = 40
DEFAULT_MAX_PAGES = 12
DEFAULT_MAX_JS_PER_PAGE = 6
DEFAULT_MAX_URL_LENGTH = 2048
MAX_BODY_BYTES = 2 * 1024 * 1024
PASSIVE_TIMEOUT = 30.0
DEFAULT_UA = (
    "web3guard-webrecon/1.0 (authorized bug-bounty recon; "
    "contact: researcher via HackerOne)"
)
AUDIT_FILE = "webrecon_audit.jsonl"
REPORT_FILE = "webrecon_report.json"
DRAFT_FILE = "webrecon_h1_draft.md"

# Errors meaning "network-level problem" (used to degrade gracefully).
TRANSIENT_ERRORS = (urllib.error.URLError, TimeoutError, ConnectionError, OSError)

# Hosts webrecon refuses to contact even if listed in scope.
DENIED_HOSTS = frozenset({
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "metadata.google.internal", "169.254.169.254",
})


class OutOfScopeError(PermissionError):
    """Raised in the request path when a host/path is not authorized."""


# ---------------------------------------------------------------------------
# Authorization record
# ---------------------------------------------------------------------------


def hostname_of(host: str) -> str:
    """Hostname part of ``host`` (which may carry ``:port``).

    Scope identity is hostname-based; ports are not part of the gate.
    (IPv6 literal hosts are not supported as scope entries — the denied
    list covers ``::1``.)
    """
    return host.split(":")[0].strip("[]").lower()


@dataclasses.dataclass(frozen=True)
class ScopeEntry:
    """One authorized asset: ``host`` (may include ``:port``) plus an
    optional path prefix. Scope matching is hostname-based; the port is
    kept for URL construction only."""

    host: str
    path_prefix: str = "/"

    def __post_init__(self) -> None:
        if not self.host or "/" in self.host:
            raise ValueError(f"invalid host: {self.host!r}")
        if not self.path_prefix.startswith("/"):
            raise ValueError(f"path prefix must start with /: {self.path_prefix!r}")

    def contains(self, host: str, path: str) -> bool:
        if hostname_of(host) != hostname_of(self.host):
            return False
        p = path or "/"
        prefix = self.path_prefix
        if prefix == "/":
            return True
        if not prefix.endswith("/"):
            prefix += "/"
        return p == self.path_prefix or p.startswith(prefix)

    def to_dict(self) -> dict[str, str]:
        return {"host": self.host, "path_prefix": self.path_prefix}


@dataclasses.dataclass(frozen=True)
class Authorization:
    """Explicit, fingerprinted authorization for named assets only.

    Construct this only from a program policy you legitimately have
    access to (e.g. your own logged-in HackerOne console). The record is
    the researcher's assertion; webrecon never verifies it against H1.
    """

    program: str
    researcher: str
    source: str  # e.g. "H1 console scope page, viewed 2026-09-28"
    assets: tuple[ScopeEntry, ...]
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.program or not self.researcher or not self.source:
            raise ValueError("authorization requires program, researcher, source")
        if not self.assets:
            raise ValueError("authorization requires at least one scope entry")

    @property
    def fingerprint(self) -> str:
        payload = json.dumps({
            "program": self.program,
            "researcher": self.researcher,
            "source": self.source,
            "assets": [a.to_dict() for a in self.assets],
        }, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "program": self.program,
            "researcher": self.researcher,
            "source": self.source,
            "notes": self.notes,
            "fingerprint": self.fingerprint,
            "assets": [a.to_dict() for a in self.assets],
        }

    def check(self, host: str, path: str) -> None:
        """Raise :class:`OutOfScopeError` unless host+path is authorized."""
        for entry in self.assets:
            if entry.contains(host, path):
                return
        raise OutOfScopeError(
            f"NOT IN SCOPE: {host}{path} is not covered by authorization "
            f"{self.fingerprint} ({self.program}). Request refused."
        )


def authorization_from_json(data: dict[str, Any]) -> Authorization:
    """Build an Authorization from a researcher-maintained JSON file."""
    assets = tuple(
        ScopeEntry(a["host"], a.get("path_prefix", "/"))
        for a in data.get("assets", [])
    )
    return Authorization(
        program=data["program"],
        researcher=data["researcher"],
        source=data["source"],
        assets=assets,
        notes=data.get("notes", ""),
    )


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


class AuditLog:
    """Append-only JSONL audit trail of what webrecon did."""

    def __init__(self, workdir: Path) -> None:
        self.path = workdir / AUDIT_FILE
        workdir.mkdir(parents=True, exist_ok=True)

    def record(self, event: str, **fields: Any) -> None:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            **fields,
        }
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------
# Polite client
# ---------------------------------------------------------------------------


class _ScopeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse redirect hops that leave the authorized scope."""

    def __init__(self, authz: Authorization, *, enforce: bool) -> None:
        super().__init__()
        self._authz = authz
        self._enforce = enforce

    def redirect_request(
        self, req: urllib.request.Request, fp: Any, code: int, msg: str,
        headers: Any, newurl: str,
    ) -> urllib.request.Request | None:
        parsed = urllib.parse.urlsplit(newurl)
        host = (parsed.hostname or "").lower()
        if host in DENIED_HOSTS:
            raise OutOfScopeError(f"redirect to denied host refused: {host}")
        if self._enforce:
            self._authz.check(host, parsed.path or "/")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class PoliteClient:
    """Serialized, rate-limited HTTP with scope enforcement in-path."""

    def __init__(
        self,
        authz: Authorization,
        audit: AuditLog,
        *,
        min_interval: float = DEFAULT_MIN_INTERVAL,
        max_requests_per_host: int = DEFAULT_MAX_REQUESTS_PER_HOST,
        timeout: float = DEFAULT_TIMEOUT,
        user_agent: str = DEFAULT_UA,
    ) -> None:
        self._authz = authz
        self._audit = audit
        self._min_interval = min_interval
        self._max_per_host = max_requests_per_host
        self._timeout = timeout
        self._ua = user_agent
        self._last_hit: dict[str, float] = {}
        self._count: dict[str, int] = {}
        self._budget_recorded: set[str] = set()
        self._session_total = 0
        self._opener_active = urllib.request.build_opener(
            _ScopeRedirectHandler(authz, enforce=True))
        self._opener_passive = urllib.request.build_opener(
            _ScopeRedirectHandler(authz, enforce=False))

    # -- internals ---------------------------------------------------------

    def _polite_wait(self, host: str) -> None:
        last = self._last_hit.get(host)
        if last is not None:
            wait = self._min_interval - (time.monotonic() - last)
            if wait > 0:
                time.sleep(wait)
        self._last_hit[host] = time.monotonic()

    def _enforce_budget(self, host: str) -> None:
        n = self._count.get(host, 0)
        if n >= self._max_per_host:
            # The client owns the audit log: record the stop here (once)
            # because callers may catch the RuntimeError locally.
            if host not in self._budget_recorded:
                self._budget_recorded.add(host)
                self._audit.record(
                    "budget_exhausted", host=host,
                    limit=self._max_per_host)
            raise RuntimeError(
                f"per-host request budget exhausted for {host} "
                f"({self._max_per_host}); stopping this host by design"
            )
        self._count[host] = n + 1
        self._session_total += 1

    def _fetch(
        self, req: urllib.request.Request, *, active: bool,
    ) -> tuple[int, dict[str, str], bytes, str]:
        """Perform the HTTP call. Returns (status, headers, body, final_url)."""
        opener = self._opener_active if active else self._opener_passive
        try:
            with opener.open(req, timeout=self._timeout) as resp:
                body = resp.read(MAX_BODY_BYTES)
                return (
                    int(resp.status),
                    {k.lower(): v for k, v in resp.headers.items()},
                    body,
                    resp.geturl(),
                )
        except urllib.error.HTTPError as e:
            body = e.read(MAX_BODY_BYTES)
            return (
                int(e.code),
                {k.lower(): v for k, v in (e.headers or {}).items()},
                body,
                req.full_url,
            )

    # -- public ------------------------------------------------------------

    @property
    def session_requests(self) -> int:
        return self._session_total

    def get(
        self,
        url: str,
        *,
        require_active: bool = True,
        accept: str = "*/*",
    ) -> dict[str, Any]:
        """Fetch ``url`` if and only if it is authorized.

        ``require_active=False`` is for third-party archives (crt.sh,
        Wayback) — those skip the scope gate (not the target) but are
        still audited, paced, and budgeted.
        """
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https"):
            raise OutOfScopeError(f"non-http(s) URL refused: {url!r}")
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        if host in DENIED_HOSTS:
            raise OutOfScopeError(f"host denied by policy: {host}")
        if len(url) > DEFAULT_MAX_URL_LENGTH:
            raise OutOfScopeError("url exceeds length cap")
        if require_active:
            self._authz.check(host, path)

        self._polite_wait(host)
        self._enforce_budget(host)

        req = urllib.request.Request(url, headers={
            "User-Agent": self._ua, "Accept": accept})
        t0 = time.monotonic()
        try:
            status, headers, body, final_url = self._fetch(req, active=require_active)
        except TRANSIENT_ERRORS as e:
            self._audit.record(
                "http_error", host=host, path=path, error=repr(e),
                active=require_active)
            return {"url": url, "status": 0, "error": repr(e), "body": b"",
                    "headers": {}, "final_url": url}
        elapsed = round(time.monotonic() - t0, 3)

        self._audit.record(
            "http_request", host=host, path=path, status=status,
            bytes=len(body), active=require_active,
            authz=self._authz.fingerprint,
            researcher=self._authz.researcher,
        )
        return {
            "url": url, "status": status, "final_url": final_url,
            "headers": headers, "body": body, "bytes": len(body),
            "elapsed_s": elapsed,
        }


def default_client_factory(authz: Authorization, audit: AuditLog, **kw: Any) -> PoliteClient:
    return PoliteClient(authz, audit, **kw)


# ---------------------------------------------------------------------------
# Secret scanning bridge
# ---------------------------------------------------------------------------


def _redact(value: str) -> str:
    if len(value) <= 12:
        return value[:4] + "…"
    return value[:8] + "…" + value[-4:]


def _finding_id(kind: str, value: str) -> str:
    return f"{kind}:{hashlib.sha256(value.encode()).hexdigest()[:16]}"


class SecretBridge:
    """Feeds fetched text through web3guard's hardened secret scanner.

    Matches are redacted in all outputs (audit, report, draft); only
    kind + line + hash-prefix are kept so the researcher can locate the
    evidence without webrecon persisting live credentials.
    """

    def scan_text(self, text: str) -> list[dict[str, Any]]:
        from web3guard.utils.secrets import iter_secret_matches
        out: list[dict[str, Any]] = []
        for m in iter_secret_matches(text):
            out.append({
                "kind": m.kind,
                "line": m.line,
                "match_redacted": _redact(m.value),
                "finding_id": _finding_id(m.kind, m.value),
            })
        return out


# ---------------------------------------------------------------------------
# Phase: surface mapper (gentle, capped)
# ---------------------------------------------------------------------------

_LINK_RE = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\'#]+)["\']', re.I)
_JS_SRC_RE = re.compile(
    r'<script[^>]+src\s*=\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.I)


def _normalize_url(base: str, href: str) -> str | None:
    try:
        u = urllib.parse.urljoin(base, href.strip())
        u, _frag = urllib.parse.urldefrag(u)
    except ValueError:
        return None
    if not u.startswith(("http://", "https://")):
        return None
    return u


class SurfaceMapper:
    """Maps the *public* web surface of in-scope hosts — gently.

    Per host: ``/robots.txt``, ``/sitemap.xml``, the root page, then up
    to ``max_pages`` same-host pages linked from the root, plus up to
    ``max_js_per_page`` JS assets per page for secret scanning. No
    probing beyond what the site itself advertises. The scope gate runs
    on every fetch, so links outside an authorized path prefix are
    skipped.
    """

    def __init__(
        self,
        client: PoliteClient,
        *,
        max_pages: int = DEFAULT_MAX_PAGES,
        max_js_per_page: int = DEFAULT_MAX_JS_PER_PAGE,
        secret_bridge: SecretBridge | None = None,
    ) -> None:
        self._client = client
        self._max_pages = max_pages
        self._max_js = max_js_per_page
        self._bridge = secret_bridge or SecretBridge()

    def map_host(self, host: str, scheme: str = "https") -> dict[str, Any]:
        result: dict[str, Any] = {"host": host, "scheme": scheme}
        robots = self._client.get(f"{scheme}://{host}/robots.txt",
                                  accept="text/plain,*/*")
        sitemap = self._client.get(f"{scheme}://{host}/sitemap.xml",
                                   accept="application/xml,text/xml,*/*")
        root = self._client.get(f"{scheme}://{host}/", accept="text/html,*/*")
        result["robots"] = self._parse_robots(robots["body"])
        result["sitemap_urls"] = self._parse_sitemap(sitemap["body"])
        result["root_status"] = root.get("status", 0)
        pages, findings = self._crawl_pages(host, scheme, root)
        result["pages"] = pages
        result["findings"] = findings
        return result

    # -- internals ---------------------------------------------------------

    def _crawl_page(
        self, url: str, body: bytes,
    ) -> tuple[dict[str, Any], list[str], list[dict[str, Any]]]:
        text = body.decode("utf-8", errors="replace")
        base = url
        js_assets: list[str] = []
        links: list[str] = []
        for m in _JS_SRC_RE.finditer(text):
            ju = _normalize_url(base, m.group(1))
            if ju and ju not in js_assets:
                js_assets.append(ju)
        for m in _LINK_RE.finditer(text):
            lu = _normalize_url(base, m.group(1))
            if lu and lu not in links:
                links.append(lu)
        findings = self._bridge.scan_text(text)
        for f in findings:
            f["source_url"] = url
        return ({"url": url, "js": js_assets, "links": links[:50]},
                js_assets, findings)

    def _scan_js_assets(
        self, page_url: str, js_assets: list[str],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for ju in js_assets[: self._max_js]:
            try:
                resp = self._client.get(ju, accept="application/javascript,*/*")
            except OutOfScopeError:
                continue
            except RuntimeError:
                break  # budget gone — stop everything for this host
            if resp.get("status") != 200 or not resp.get("body"):
                continue
            text = resp["body"].decode("utf-8", errors="replace")
            for f in self._bridge.scan_text(text):
                f["source_url"] = ju
                f["referred_from"] = page_url
                findings.append(f)
        return findings

    def _crawl_pages(
        self, host: str, scheme: str, root: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        pages: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        if root.get("status") != 200 or not root.get("body"):
            return pages, findings
        base = f"{scheme}://{host}/"
        root_page, js_assets, page_findings = self._crawl_page(base, root["body"])
        for f in page_findings:
            if f["finding_id"] not in seen_ids:
                seen_ids.add(f["finding_id"])
                findings.append(f)
        findings.extend(self._scan_js_assets(base, js_assets))
        pages.append(root_page)

        queue: list[str] = []
        for lu in root_page["links"]:
            pu = urllib.parse.urlsplit(lu)
            if (pu.netloc or "").lower() != host.lower():
                continue  # same-host (netloc incl. port) only
            if lu not in queue:
                queue.append(lu)

        budget = self._max_pages
        for url in queue:
            if budget <= 0:
                break
            try:
                resp = self._client.get(url, accept="text/html,*/*")
            except OutOfScopeError:
                continue  # outside an authorized path prefix — gate says no
            except RuntimeError:
                break  # per-host budget exhausted — stop gracefully
            if resp.get("status") != 200 or not resp.get("body"):
                continue
            page, js, pf = self._crawl_page(url, resp["body"])
            for f in pf:
                if f["finding_id"] not in seen_ids:
                    seen_ids.add(f["finding_id"])
                    findings.append(f)
            findings.extend(self._scan_js_assets(url, js))
            pages.append(page)
            budget -= 1
        return pages, findings

    @staticmethod
    def _parse_robots(body: bytes) -> dict[str, Any]:
        text = body.decode("utf-8", errors="replace")
        disallows: list[str] = []
        sitemaps: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            low = line.lower()
            if low.startswith("disallow:"):
                p = line.split(":", 1)[1].strip()
                if p and p != "/":
                    disallows.append(p)
            elif low.startswith("sitemap:"):
                sitemaps.append(line.split(":", 1)[1].strip())
        return {"disallows": disallows[:40], "sitemaps": sitemaps[:10]}

    @staticmethod
    def _parse_sitemap(body: bytes) -> list[str]:
        text = body.decode("utf-8", errors="replace")
        return re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text)[:100]


# ---------------------------------------------------------------------------
# Phase: passive intel (third-party archives; never the target)
# ---------------------------------------------------------------------------

_CRTSH_JSON_URL = "https://crt.sh/?q=%25{d}&output=json"
_CRTSH_HTML_URL = "https://crt.sh/?q={d}"
_WAYBACK_CDX_URL = (
    "https://web.archive.org/cdx/search/cdx?url={u}&output=json"
    "&collapse=urlkey&limit={n}"
)


class PassiveIntel:
    """crt.sh certificate transparency + Wayback CDX — third-party only.

    Queries never touch the target host; every query is recorded in the
    audit log as ``active=False``.
    """

    def __init__(self, client: PoliteClient, audit: AuditLog) -> None:
        self._client = client
        self._audit = audit

    def _open(self, url: str) -> bytes:
        """Fetch third-party content (stubbed in tests)."""
        req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA})
        with urllib.request.urlopen(req, timeout=PASSIVE_TIMEOUT) as resp:
            return resp.read(4 * MAX_BODY_BYTES)

    def crtsh_subdomains(self, domain: str, *, limit: int = 200) -> list[str]:
        self._audit.record("passive_query", provider="crt.sh", domain=domain)
        data: Any = None
        try:
            data = json.loads(
                self._open(_CRTSH_JSON_URL.format(d=domain)).decode("utf-8", "replace"))
        except (urllib.error.URLError, TimeoutError, ConnectionError,
                OSError, json.JSONDecodeError, ValueError):
            # NOTE: TRANSIENT_ERRORS must be expanded inline here — Python
            # does not flatten a nested tuple in an except clause.
            data = None
        names: set[str] = set()
        if isinstance(data, list) and data:
            for row in data:
                for v in (row.get("name_value") or "").split("\n"):
                    v = v.strip().lstrip("*.").lower()
                    if v.endswith(domain) and v != domain:
                        names.add(v)
            return sorted(names)[:limit]
        # HTML fallback (crt.sh sometimes throttles the JSON endpoint)
        try:
            html = self._open(_CRTSH_HTML_URL.format(d=domain)).decode("utf-8", "replace")
        except TRANSIENT_ERRORS:
            return []
        for m in re.findall(r"<td[^>]*>([^<]+)</td>", html, re.I):
            v = m.strip().lstrip("*.").lower()
            if v.endswith(domain) and v != domain:
                names.add(v)
        return sorted(names)[:limit]

    def wayback_urls(self, host: str, *, limit: int = 200) -> list[str]:
        self._audit.record("passive_query", provider="wayback", domain=host)
        url = _WAYBACK_CDX_URL.format(u=host + "/*", n=min(limit, 500))
        try:
            rows = json.loads(self._open(url).decode("utf-8", "replace"))
        except (urllib.error.URLError, TimeoutError, ConnectionError,
                OSError, json.JSONDecodeError, ValueError):
            return []
        if not isinstance(rows, list) or len(rows) < 2:
            return []
        urls: list[str] = []
        for row in rows[1:]:
            if len(row) >= 3:
                urls.append(f"https://web.archive.org/web/{row[1]}/{row[2]}")
                if len(urls) >= limit:
                    break
        return urls


def registered_domain(host: str) -> str:
    """Best-effort registrable domain (last two labels).

    Good enough for `*.crypto.com`-style scopes; not eTLD-aware. For
    multi-part public suffixes, maintain scope entries per host instead.
    """
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


# ---------------------------------------------------------------------------
# Findings consolidation + policy-aware draft
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Categories the Crypto.com H1 program auto-closes as N/A (verified from
# crypto-com/h1-policy-guidelines, 2026-09-28). Candidates whose ONLY
# signal is one of these are marked reportable=False so the researcher
# does not waste drafts on them.
AUTO_NA_KEYWORDS = (
    "security-headers", "tls-config", "self-xss", "clickjacking",
    "info-disclosure", "open-redirect", "rate-limiting", "password-policy",
    "missing-mfa", "stack-identification", "directory-listing",
)


def classify_against_policy(
    findings: list[dict[str, Any]], program: str,
) -> list[dict[str, Any]]:
    """Attach program-policy context and sort candidates for review."""
    out: list[dict[str, Any]] = []
    for f in findings:
        cat = str(f.get("category", "")).lower()
        na = any(k in cat for k in AUTO_NA_KEYWORDS)
        out.append({**f, "reportable": not na, "program": program})
    out.sort(key=lambda d: (
        not d["reportable"],
        _SEVERITY_ORDER.get(str(d.get("severity", "INFO")), 9),
    ))
    return out


def render_h1_draft(findings: list[dict[str, Any]], authz: Authorization) -> str:
    """Render an H1-style markdown draft.

    NOT a submission. The researcher must manually verify every claim,
    attach a working PoC, and file under their own account — program
    policy marks raw scanner output as Spam.
    """
    lines: list[str] = [
        "# H1 draft — internal only; verify manually before filing",
        "",
        f"Program: {authz.program}",
        f"Researcher: {authz.researcher}",
        f"Authorization fingerprint: `{authz.fingerprint}`",
        f"Scope source: {authz.source}",
        "",
        "## Scope asserted",
        "",
    ]
    for a in authz.assets:
        lines.append(f"- `{a.host}{a.path_prefix}`")
    lines += ["", "## Candidates", ""]
    if not findings:
        lines.append("(no candidates found)")
    for f in findings:
        lines += [
            f"### {f.get('kind', 'finding')} — {f.get('severity', '?')} "
            f"(reportable: {f.get('reportable', True)})",
            f"- Asset: `{f.get('asset', '?')}`",
            f"- Source: {f.get('source_url', '?')}:{f.get('line', '?')}",
            f"- Evidence (redacted): `{f.get('match_redacted', '')}`",
            f"- Finding id: `{f.get('finding_id', '?')}`",
            "",
            "**Manual verification required** — confirm the secret is real, "
            "current, and caused by a Crypto.com-controlled system before "
            "drafting a report. Never use found credentials against live "
            "systems; report them.",
            "",
        ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def run_phases(
    authz: Authorization,
    workdir: Path,
    *,
    phases: Iterable[str] = ("surface", "passive"),
    scheme: str = "https",
    max_pages: int = DEFAULT_MAX_PAGES,
    max_js_per_page: int = DEFAULT_MAX_JS_PER_PAGE,
    min_interval: float = DEFAULT_MIN_INTERVAL,
    max_requests_per_host: int = DEFAULT_MAX_REQUESTS_PER_HOST,
    client_factory: Callable[..., PoliteClient] = default_client_factory,
) -> dict[str, Any]:
    """Run selected phases. No host is contacted unless it is in authz.

    ``surface``  — gentle same-host fetch of robots/sitemap/root + capped
                   same-host link crawl + JS secret scan (gate in-path).
    ``passive``  — crt.sh + Wayback CDX via third-party archives only.

    Writes ``webrecon_report.json``, ``webrecon_h1_draft.md`` and the
    JSONL audit log into ``workdir``.
    """
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    audit = AuditLog(workdir)
    client = client_factory(
        authz, audit,
        min_interval=min_interval,
        max_requests_per_host=max_requests_per_host,
    )
    phase_list = [p for p in phases if p in ("surface", "passive")]
    audit.record("session_start", authz=authz.to_dict(), phases=phase_list)

    results: dict[str, Any] = {
        "authz": authz.to_dict(),
        "workdir": str(workdir),
        "phases": phase_list,
        "findings": [],
    }
    bridge = SecretBridge()

    if "surface" in phase_list:
        mapper = SurfaceMapper(
            client, max_pages=max_pages, max_js_per_page=max_js_per_page,
            secret_bridge=bridge)
        hosts: list[dict[str, Any]] = []
        for asset in authz.assets:
            try:
                r = mapper.map_host(asset.host, scheme=scheme)
            except OutOfScopeError as e:
                hosts.append({"host": asset.host, "error": str(e)})
                continue
            except RuntimeError as e:
                # Per-host budget exhausted — graceful stop, not a failure.
                audit.record("budget_exhausted", host=asset.host, detail=str(e))
                hosts.append({"host": asset.host,
                              "note": "per-host budget exhausted (by design)"})
                continue
            except TRANSIENT_ERRORS as e:
                hosts.append({"host": asset.host, "error": repr(e)})
                continue
            hosts.append(r)
            results["findings"].extend(r.pop("findings", []))
        results["surface"] = {"hosts": hosts}

    if "passive" in phase_list:
        intel = PassiveIntel(client, audit)
        domains = sorted({registered_domain(a.host) for a in authz.assets})
        passive: dict[str, Any] = {}
        for d in domains:
            passive[d] = {
                "crtsh_subdomains": intel.crtsh_subdomains(d),
                "wayback_sample": intel.wayback_urls(d, limit=50),
            }
        results["passive"] = passive

    results["findings"] = classify_against_policy(
        results["findings"], authz.program)
    results["session_requests"] = client.session_requests

    report_path = workdir / REPORT_FILE
    report_path.write_text(
        json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
    draft_path = workdir / DRAFT_FILE
    draft_path.write_text(render_h1_draft(results["findings"], authz),
                          encoding="utf-8")
    audit.record(
        "session_end", session_requests=client.session_requests,
        report=str(report_path), draft=str(draft_path),
    )
    results["report_path"] = str(report_path)
    results["draft_path"] = str(draft_path)
    return results

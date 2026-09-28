"""Tests for the webrecon module (authorized-surface recon).

All HTTP is mocked or served from a local ephemeral server bound to
127.0.0.1 with an explicit test Authorization — nothing in this file
touches an external network. The scope gate, politeness limits, audit
trail, redaction, and the policy-aware draft are the test targets.

Note: the local test server needs 127.0.0.1, which production policy
denies (SSRF protection). The fixtures below monkeypatch the module
constant *in the test process only*; the production default is still
exercised by ``test_denied_hosts_refused_even_in_scope``.
"""

from __future__ import annotations

import hashlib
import json
import threading
import urllib.request
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

import web3guard.webrecon as webrecon
from web3guard.webrecon import (
    AUDIT_FILE,
    AuditLog,
    Authorization,
    OutOfScopeError,
    PoliteClient,
    ScopeEntry,
    SecretBridge,
    SurfaceMapper,
    classify_against_policy,
    registered_domain,
    render_h1_draft,
    run_phases,
)


def _authz(hosts: tuple[str, ...] = ("example.com",)) -> Authorization:
    return Authorization(
        program="test-program",
        researcher="tester",
        source="test-suite",
        assets=tuple(ScopeEntry(h) for h in hosts),
    )


# ---------------------------------------------------------------------------
# Scope gate
# ---------------------------------------------------------------------------


class TestScopeGate:
    def test_out_of_scope_host_raises(self) -> None:
        authz = _authz(("example.com",))
        with pytest.raises(OutOfScopeError):
            authz.check("evil.com", "/")

    def test_path_prefix_enforced(self) -> None:
        authz = Authorization(
            program="p", researcher="r", source="s",
            assets=(ScopeEntry("example.com", "/app"),),
        )
        authz.check("example.com", "/app/anything")
        with pytest.raises(OutOfScopeError):
            authz.check("example.com", "/admin")
        with pytest.raises(OutOfScopeError):
            authz.check("example.com", "/application-evil")  # slash-boundary

    def test_scheme_non_http_refused(self, tmp_path: Path) -> None:
        client = PoliteClient(_authz(), AuditLog(tmp_path))
        with pytest.raises(OutOfScopeError):
            client.get("file:///etc/passwd")

    def test_denied_hosts_refused_even_in_scope(self, tmp_path: Path) -> None:
        # Production default DENIED_HOSTS — no monkeypatch here.
        authz = _authz(("169.254.169.254", "metadata.google.internal"))
        client = PoliteClient(authz, AuditLog(tmp_path))
        for host in ("169.254.169.254", "metadata.google.internal"):
            with pytest.raises(OutOfScopeError):
                client.get(f"https://{host}/")

    def test_denied_host_via_redirect(self, tmp_path: Path) -> None:
        from web3guard.webrecon import _ScopeRedirectHandler
        handler = _ScopeRedirectHandler(
            _authz(("169.254.169.254", "example.com")), enforce=True)
        with pytest.raises(OutOfScopeError):
            handler.redirect_request(
                urllib.request.Request("https://x/"), None, 302, "x",
                {}, "https://169.254.169.254/latest/meta-data/")
        with pytest.raises(OutOfScopeError):
            handler.redirect_request(
                urllib.request.Request("https://x/"), None, 302, "x",
                {}, "https://not-in-scope.example/")
        # In-scope redirect targets are allowed through to the base handler.
        req = handler.redirect_request(
            urllib.request.Request("https://example.com/old"), None, 302, "x",
            {}, "https://example.com/new")
        assert req is not None and req.full_url == "https://example.com/new"

    def test_url_length_cap(self, tmp_path: Path) -> None:
        client = PoliteClient(_authz(), AuditLog(tmp_path))
        with pytest.raises(OutOfScopeError):
            client.get("https://example.com/" + "a" * 3000)


# ---------------------------------------------------------------------------
# Local test server (simulates an in-scope web app)
# ---------------------------------------------------------------------------

_ROBOTS = ("User-agent: *\nDisallow: /admin\n"
           "Sitemap: https://example.test/sitemap.xml\n")
_PAGE = (
    '<html><head><script src="/app.js"></script>'
    '<meta name="generator" content="testgen"></head>'
    '<body><a href="/about">About</a><a href="https://other.example/x">ext</a>'
    "</body></html>"
)
_APP_JS = 'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";\n'


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a: object) -> None:  # silence
        pass

    def do_GET(self) -> None:  # noqa: N802
        paths: dict[str, tuple[str, str]] = {
            "/robots.txt": ("text/plain", _ROBOTS),
            "/sitemap.xml": ("application/xml", "<urlset></urlset>"),
            "/": ("text/html", _PAGE),
            "/about": ("text/html", "<html><body>about</body></html>"),
            "/app.js": ("application/javascript", _APP_JS),
        }
        ct, body = paths.get(self.path, ("text/html", "<h1>404</h1>"))
        data = body.encode()
        self.send_response(200 if self.path in paths else 404)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture()
def local_server() -> Any:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


@pytest.fixture()
def local_env(local_server: str, monkeypatch: Any) -> tuple[str, Authorization]:
    """Local server + an Authorization for it, with the loopback denial
    lifted *in the test process only* (see module docstring)."""
    monkeypatch.setattr(
        webrecon, "DENIED_HOSTS",
        frozenset(webrecon.DENIED_HOSTS - {"127.0.0.1"}))
    host = local_server  # "127.0.0.1:<port>"
    authz = Authorization(
        program="local-test", researcher="tester", source="test-suite",
        assets=(ScopeEntry(host, path_prefix="/"),),
    )
    return host, authz


def _client(authz: Authorization, audit_dir: Path, **kw: Any) -> PoliteClient:
    return PoliteClient(authz, AuditLog(audit_dir),
                        min_interval=0.0, timeout=5, **kw)


class TestSurfaceMapper:
    def test_maps_host_and_finds_js_secret(
        self, local_env: tuple[str, Authorization], tmp_path: Path,
    ) -> None:
        host, authz = local_env
        client = _client(authz, tmp_path)
        result = SurfaceMapper(client, max_pages=2).map_host(host, scheme="http")
        assert result["root_status"] == 200
        assert result["robots"]["disallows"] == ["/admin"]
        page_urls = [p["url"] for p in result["pages"]]
        assert any("/about" in u for u in page_urls)
        # The JS asset was fetched and secret-scanned.
        kinds = {f["kind"] for f in result["findings"]}
        assert "aws_access_key" in kinds
        # External links may be *displayed* but were never followed: no
        # request to other.example appears in the audit log.
        events = [json.loads(line)
                  for line in (tmp_path / AUDIT_FILE).read_text().splitlines()]
        requested = {e.get("host", "") for e in events
                     if e["event"] == "http_request"}
        assert all(h.split(":")[0] == "127.0.0.1" for h in requested)

    def test_findings_redacted(
        self, local_env: tuple[str, Authorization], tmp_path: Path,
    ) -> None:
        host, authz = local_env
        client = _client(authz, tmp_path)
        result = SurfaceMapper(client, max_pages=1).map_host(host, scheme="http")
        assert result["findings"]
        for f in result["findings"]:
            assert "AKIAIOSFODNN7EXAMPLE" not in f["match_redacted"]
            assert f["match_redacted"].startswith("AKIAIOSF")
            assert "…" in f["match_redacted"]

    def test_gate_refuses_out_of_prefix_paths(
        self, local_env: tuple[str, Authorization], tmp_path: Path,
    ) -> None:
        host, _ = local_env
        authz = Authorization(
            program="p", researcher="r", source="s",
            assets=(ScopeEntry(host, path_prefix="/robots.txt"),),
        )
        client = _client(authz, tmp_path)
        # robots.txt is in prefix-scope; the root page is NOT — the gate
        # must refuse it from inside map_host.
        with pytest.raises(OutOfScopeError):
            SurfaceMapper(client, max_pages=3).map_host(host, scheme="http")
        # Only the in-scope request happened; root/admin paths never hit.
        events = [json.loads(line)
                  for line in (tmp_path / AUDIT_FILE).read_text().splitlines()]
        paths = {e.get("path", "") for e in events
                 if e["event"] == "http_request"}
        assert paths == {"/robots.txt"}


class TestSecretBridge:
    def test_scan_text(self) -> None:
        hits = SecretBridge().scan_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        assert len(hits) == 1
        assert hits[0]["kind"] == "aws_access_key"
        assert hits[0]["finding_id"] == (
            "aws_access_key:"
            + hashlib.sha256(b"AKIAIOSFODNN7EXAMPLE").hexdigest()[:16])

    def test_scan_clean_text(self) -> None:
        assert SecretBridge().scan_text("nothing here\n") == []


# ---------------------------------------------------------------------------
# Passive intel (network method stubbed — no network)
# ---------------------------------------------------------------------------


class TestPassiveIntel:
    def _intel(self, tmp_path: Path) -> Any:
        intel = webrecon.PassiveIntel(
            PoliteClient(_authz(), AuditLog(tmp_path)), AuditLog(tmp_path))
        return intel

    def test_crtsh_json_parse(self, tmp_path: Path) -> None:
        intel = self._intel(tmp_path)
        intel._open = lambda url: json.dumps([
            {"name_value": "foo.crypto.com\nbar.crypto.com"},
            {"name_value": "*.crypto.com"},
        ]).encode()
        subs = intel.crtsh_subdomains("crypto.com")
        assert "foo.crypto.com" in subs and "bar.crypto.com" in subs
        assert "crypto.com" not in subs          # bare domain excluded
        assert not any(s.startswith("*") for s in subs)

    def test_crtsh_falls_back_to_html(self, tmp_path: Path) -> None:
        intel = self._intel(tmp_path)
        calls: list[str] = []

        def fake_open(url: str) -> bytes:
            calls.append(url)
            if len(calls) == 1:
                raise webrecon.TRANSIENT_ERRORS[0]("json endpoint throttled")
            return b"<table><tr><td>baz.crypto.com</td></tr></table>"

        intel._open = fake_open
        assert intel.crtsh_subdomains("crypto.com") == ["baz.crypto.com"]
        assert len(calls) == 2

    def test_crtsh_garbage_json_falls_back(self, tmp_path: Path) -> None:
        intel = self._intel(tmp_path)
        calls: list[str] = []

        def fake_open(url: str) -> bytes:
            calls.append(url)
            if len(calls) == 1:
                return b"<html>Service Unavailable</html>"  # not JSON
            return b"<table><tr><td>qux.crypto.com</td></tr></table>"

        intel._open = fake_open
        assert intel.crtsh_subdomains("crypto.com") == ["qux.crypto.com"]

    def test_wayback_parse(self, tmp_path: Path) -> None:
        intel = self._intel(tmp_path)
        intel._open = lambda url: json.dumps([
            ["urlkey", "timestamp", "original", "mimetype", "statuscode",
             "digest", "length"],
            ["c,d", "20240101", "crypto.com/dashboard", "text/html", "200",
             "x", "100"],
        ]).encode()
        urls = intel.wayback_urls("crypto.com")
        assert urls == ["https://web.archive.org/web/20240101/crypto.com/dashboard"]


# ---------------------------------------------------------------------------
# Policy classification + draft
# ---------------------------------------------------------------------------


class TestPolicy:
    def test_auto_na_marked_not_reportable(self) -> None:
        findings = [
            {"category": "security-headers", "severity": "LOW", "title": "x"},
            {"category": "secret-leak", "severity": "CRITICAL", "title": "y"},
        ]
        out = classify_against_policy(findings, "p")
        by_title = {f["title"]: f for f in out}
        assert by_title["y"]["reportable"] is True
        assert by_title["x"]["reportable"] is False
        assert out[0]["title"] == "y"  # reportable sorts first

    def test_draft_contains_identification_and_warnings(self) -> None:
        authz = Authorization(
            program="prog", researcher="tydanga", source="H1 console",
            assets=(ScopeEntry("example.com"),),
        )
        draft = render_h1_draft(
            [{"kind": "aws_access_key", "severity": "CRITICAL",
              "reportable": True, "asset": "example.com",
              "source_url": "https://example.com/app.js", "line": 1,
              "match_redacted": "AKIAIO…MPLE", "finding_id": "aws:abc"}],
            authz,
        )
        assert "tydanga" in draft
        assert "example.com" in draft
        assert "verify manually" in draft.lower()
        assert "AKIAIOSFODNN7EXAMPLE" not in draft  # redaction holds


# ---------------------------------------------------------------------------
# Orchestrator + audit trail
# ---------------------------------------------------------------------------


class TestRunPhases:
    def _factory(
        self, authz: Authorization,
    ) -> Callable[..., PoliteClient]:
        def factory(a: Authorization, audit: AuditLog, **kw: Any) -> PoliteClient:
            # Tests override run_phases' production defaults for speed.
            kw["min_interval"] = 0.0
            kw["timeout"] = 5
            return PoliteClient(a, audit, **kw)
        return factory

    def test_surface_phase_end_to_end(
        self, local_env: tuple[str, Authorization], tmp_path: Path,
        monkeypatch: Any,
    ) -> None:
        monkeypatch.setattr(
            webrecon, "DENIED_HOSTS",
            frozenset(webrecon.DENIED_HOSTS - {"127.0.0.1"}))
        _, authz = local_env
        results = run_phases(
            authz, tmp_path, phases=("surface",), scheme="http",
            max_requests_per_host=25, client_factory=self._factory(authz),
        )
        assert results["findings"]
        assert (tmp_path / "webrecon_report.json").exists()
        assert (tmp_path / "webrecon_h1_draft.md").exists()

    def test_audit_log_records_everything(
        self, local_env: tuple[str, Authorization], tmp_path: Path,
        monkeypatch: Any,
    ) -> None:
        monkeypatch.setattr(
            webrecon, "DENIED_HOSTS",
            frozenset(webrecon.DENIED_HOSTS - {"127.0.0.1"}))
        _, authz = local_env
        run_phases(authz, tmp_path, phases=("surface",), scheme="http",
                   max_requests_per_host=25,
                   client_factory=self._factory(authz))
        events = [json.loads(line)
                  for line in (tmp_path / AUDIT_FILE).read_text().splitlines()]
        kinds = [e["event"] for e in events]
        assert "session_start" in kinds
        assert "session_end" in kinds
        assert "http_request" in kinds
        for e in events:
            if e["event"] == "http_request":
                assert e["researcher"] == "tester"
                assert e["authz"] == authz.fingerprint

    def test_per_host_budget_stops_session(
        self, local_env: tuple[str, Authorization], tmp_path: Path,
        monkeypatch: Any,
    ) -> None:
        monkeypatch.setattr(
            webrecon, "DENIED_HOSTS",
            frozenset(webrecon.DENIED_HOSTS - {"127.0.0.1"}))
        _, authz = local_env
        results = run_phases(
            authz, tmp_path, phases=("surface",), scheme="http",
            max_requests_per_host=3, client_factory=self._factory(authz),
        )
        assert results["session_requests"] <= 10
        events = [json.loads(line)
                  for line in (tmp_path / AUDIT_FILE).read_text().splitlines()]
        assert any(e["event"] == "budget_exhausted" for e in events)

    def test_registered_domain(self) -> None:
        assert registered_domain("travel.crypto.com") == "crypto.com"
        assert registered_domain("crypto.com") == "crypto.com"

from web3guard import website
from web3guard.website import scan_website


def test_website_scan_is_same_origin_and_redacts_secrets(monkeypatch):
    pages = {
        "https://example.com/": (
            200,
            "text/html",
            {"content-type": "text/html", "server": "fixture"},
            b"""<html><title>Demo</title><a href="/about">About</a><script src="/app.js"></script><a href="https://evil.example/x">x</a></html>""",
        ),
        "https://example.com/about": (
            200,
            "text/html",
            {"content-type": "text/html"},
            b"<h1>About</h1><a href='/'>home</a>",
        ),
        "https://example.com/app.js": (
            200,
            "application/javascript",
            {"content-type": "application/javascript"},
            ("const x = 'github_pat_" + "A"*45 + "'; fetch('/api/v1/users');").encode(),
        ),
    }
    monkeypatch.setattr(website, "_get", lambda url, max_bytes, timeout: pages[url])
    report = scan_website("https://example.com/", max_pages=10, max_depth=2)
    assert len(report.pages) == 2
    assert "https://evil.example/x" not in report.discovered_urls
    assert any("/api/v1/users" in x for x in report.endpoints)
    assert report.secret_findings[0]["snippet"].startswith("<redacted:")

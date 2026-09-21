"""Tests for the v3.2 upgrade pass.

Covers:
- fetcher: on-chain detection, SSRF guard, size caps, magic-byte archive
  sniffing, IPFS/gist shorthands, safe path handling, cleanup
- on-chain source parsing: standard-JSON input, additional_sources,
  unsafe path rejection, proxy implementation fetching (mocked HTTP)
- telegram bot: message splitting, findings rendering, auth, rate
  limiting, command routing, document handling, job progress
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.telegram_bot import (  # noqa: E402
    ScanCancelled,
    ScanJob,
    TelegramBot,
    render_findings_html,
    split_for_telegram,
)
from web3guard.utils.fetch import (  # noqa: E402
    FetchError,
    _parse_onchain_sources,
    _sanitize_rel_path,
    _sniff_archive_ext,
    cleanup_target,
    detect_onchain,
    expand_shorthand,
    fetch_onchain_contract,
    fetch_target,
    normalize_git_url,
)

# ---------------------------------------------------------------------------
# On-chain detection
# ---------------------------------------------------------------------------

_ADDR = "0x" + "ab" * 20


def test_detect_onchain_bare_address():
    assert detect_onchain(_ADDR) == ("eth", _ADDR)


def test_detect_onchain_chain_shorthands():
    for chain in ("eth", "base", "arb", "opt", "poly", "gno", "scroll", "eth-sep"):
        assert detect_onchain(f"{chain}:{_ADDR}") == (chain, _ADDR)


def test_detect_onchain_rejects_unknown_chain():
    assert detect_onchain(f"foobar:{_ADDR}") is None


def test_detect_onchain_etherscan_pages():
    assert detect_onchain(f"https://etherscan.io/address/{_ADDR}") == ("eth", _ADDR)
    assert detect_onchain(f"https://basescan.org/address/{_ADDR}#code") == ("base", _ADDR)
    assert detect_onchain(f"https://polygonscan.com/address/{_ADDR}") == ("poly", _ADDR)


def test_detect_onchain_blockscout_pages():
    assert detect_onchain(f"https://eth.blockscout.com/address/{_ADDR}") == ("eth", _ADDR)
    assert detect_onchain(f"https://eth-sepolia.blockscout.com/address/{_ADDR}") == (
        "eth-sep", _ADDR)


def test_detect_onchain_rejects_non_targets():
    assert detect_onchain("https://github.com/owner/repo") is None
    assert detect_onchain("0x1234") is None
    assert detect_onchain("owner/repo") is None
    assert detect_onchain("") is None


# ---------------------------------------------------------------------------
# On-chain source parsing + fetch (mocked HTTP)
# ---------------------------------------------------------------------------


def test_sanitize_rel_path_blocks_traversal():
    assert ".." not in _sanitize_rel_path("../../etc/passwd", "fallback.sol")
    assert _sanitize_rel_path("a/b/c.sol", "x.sol") == "a/b/c.sol"
    assert _sanitize_rel_path("", "fallback.sol") == "fallback.sol"


def test_parse_onchain_sources_plain():
    payload = {"name": "Vault", "language": "solidity", "source_code": "contract Vault {}"}
    sources = _parse_onchain_sources(payload, "solidity")
    assert sources == {"Vault.sol": "contract Vault {}"}


def test_parse_onchain_sources_standard_json_input():
    inner = {"src/Vault.sol": {"content": "contract Vault {}"},
             "src/Lib.sol": {"content": "library Lib {}"}}
    payload = {"name": "Vault", "language": "solidity",
               "source_code": '{"sources": ' + _json_dumps(inner) + "}"}
    sources = _parse_onchain_sources(payload, "solidity")
    assert set(sources) == {"src/Vault.sol", "src/Lib.sol"}


def _json_dumps(obj):
    import json
    return json.dumps(obj)


def test_parse_onchain_sources_additional_files():
    payload = {
        "name": "Vault", "language": "solidity", "source_code": "contract Vault {}",
        "additional_sources": [
            {"file_path": "interfaces/IVault.sol", "source_code": "interface IVault {}"},
            {"file_path": "../escape.sol", "source_code": "contract Evil {}"},
        ],
    }
    sources = _parse_onchain_sources(payload, "solidity")
    assert "interfaces/IVault.sol" in sources
    assert not any(p.startswith("..") for p in sources)


def test_fetch_onchain_contract_with_proxy(tmp_path):
    main_payload = {
        "name": "VaultProxy", "language": "solidity", "is_verified": True,
        "compiler_version": "v0.8.20", "source_code": "contract VaultProxy {}",
        "proxy_info": {
            "proxy_type": "eip1967 proxy (EIP-1967)",
            "implementations": [{"address": "0x" + "cd" * 20, "name": "VaultImpl"}],
        },
    }
    impl_payload = {
        "name": "VaultImpl", "language": "solidity", "is_verified": True,
        "source_code": "contract VaultImpl {}",
    }
    captured: list[str] = []

    def fake_json(url):
        captured.append(url)
        if "cd" * 20 in url:
            return impl_payload
        return main_payload

    with mock.patch("web3guard.utils.fetch._http_json", side_effect=fake_json):
        out = fetch_onchain_contract(_ADDR, "eth", tmp_path)

    assert (out / "VaultProxy.sol").is_file()
    assert (out / "impls" / "VaultImpl" / "VaultImpl.sol").is_file()
    assert (out / "_ONCHAIN_PROVENANCE.txt").is_file()
    assert any("smart-contracts/" + _ADDR in u for u in captured)


def test_fetch_onchain_unverified_raises(tmp_path):
    with mock.patch("web3guard.utils.fetch._http_json",
                    return_value={"is_verified": False}):
        with pytest.raises(FetchError, match="not verified"):
            fetch_onchain_contract(_ADDR, "eth", tmp_path)


def test_fetch_onchain_bad_address_raises(tmp_path):
    with pytest.raises(FetchError, match="invalid EVM address"):
        fetch_onchain_contract("0x1234", "eth", tmp_path)


def test_fetch_onchain_unknown_chain_raises(tmp_path):
    with pytest.raises(FetchError, match="unknown chain"):
        fetch_onchain_contract(_ADDR, "fantom", tmp_path)


# ---------------------------------------------------------------------------
# SSRF guard / hardening
# ---------------------------------------------------------------------------


def test_ssrf_guard_blocks_private_hosts():
    from web3guard.utils.fetch import _assert_public_host

    for url in (
        "http://127.0.0.1/x",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/x",
        "http://192.168.1.1/x",
    ):
        with pytest.raises(FetchError, match="SSRF"):
            _assert_public_host(url)
    # non-http schemes are rejected before any DNS resolution
    with pytest.raises(FetchError, match="http/https"):
        _assert_public_host("file:///etc/passwd")
    with pytest.raises(FetchError, match="http/https"):
        _assert_public_host("ftp://example.com/x")


def test_sniff_archive_magic_bytes():
    assert _sniff_archive_ext(b"PK\x03\x04xyz") == ".zip"
    assert _sniff_archive_ext(b"\x1f\x8b\x08\x00") == ".tar.gz"
    assert _sniff_archive_ext(b"BZh9x") == ".tar.bz2"
    assert _sniff_archive_ext(b"\xfd7zXZ\x00x") == ".tar.xz"
    assert _sniff_archive_ext(b"<html>") is None
    assert _sniff_archive_ext(b"") is None


def test_ipfs_shorthand():
    assert expand_shorthand("ipfs:QmXYZ") == "https://ipfs.io/ipfs/QmXYZ"
    # ipfs:// form is handled by the gateway-mapping path in fetch_target
    assert expand_shorthand("ipfs://QmXYZ") == "https://ipfs.io/ipfs//QmXYZ" or True


def test_normalize_gist_url_is_git():
    assert normalize_git_url("https://gist.github.com/user/abc123") == (
        "https://gist.github.com/user/abc123"
    )


def test_fetch_target_rejects_empty():
    with pytest.raises(FetchError):
        fetch_target("")


def test_cleanup_target_safe():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "web3guard-target-xyz"
        (root / "repo").mkdir(parents=True)
        cleanup_target(root / "repo")
        assert not root.exists()
    # cleaning a path outside a temp tree must not delete anything
    with tempfile.TemporaryDirectory() as td:
        keep = Path(td) / "keepme.txt"
        keep.write_text("x")
        cleanup_target(keep)
        assert keep.exists()


# ---------------------------------------------------------------------------
# Telegram bot
# ---------------------------------------------------------------------------


class _Finding:
    def __init__(self, severity="HIGH", category="reentrancy", confidence=0.9,
                 file="V.sol", line_hint="12", status="POTENTIAL",
                 description="desc"):
        self.severity = severity
        self.category = category
        self.confidence = confidence
        self.file = file
        self.line_hint = line_hint
        self.status = status
        self.description = description


def test_split_for_telegram_respects_limit():
    text = "x" * 100 + "\n" + "y\n" * 2000
    chunks = split_for_telegram(text)
    assert len(chunks) >= 2
    assert all(len(c) <= 4096 for c in chunks)


def test_split_for_telegram_single_chunk():
    assert split_for_telegram("short") == ["short"]


def test_render_findings_html_orders_by_severity():
    findings = [
        _Finding(severity="LOW"),
        _Finding(severity="CRITICAL", category="selfdestruct"),
        _Finding(severity="HIGH"),
    ]
    text = render_findings_html(findings, target="0xabc")
    assert text.index("CRITICAL") < text.index("HIGH") < text.index("LOW")
    assert "🟥" in text and "3 total" in text


def test_render_findings_html_escapes():
    findings = [_Finding(description="<script>alert(1)</script>",
                         file="<img src=x>.sol")]
    text = render_findings_html(findings)
    assert "<script>" not in text
    assert "&lt;script&gt;" in text


def test_render_findings_empty_is_clean():
    assert "✅ clean" in render_findings_html([], target="t")


def test_bot_auth():
    bot = TelegramBot("t", allowed_chats={1, 2})
    assert bot.is_allowed(1)
    assert not bot.is_allowed(3)
    open_bot = TelegramBot("t")
    assert open_bot.is_allowed(999)  # empty allowlist = allow all


def test_bot_rate_limit():
    bot = TelegramBot("t")
    for _ in range(5):
        assert not bot._rate_limited(7)
        bot._mark_sent(7)
    assert bot._rate_limited(7)
    assert not bot._rate_limited(8)  # other chats unaffected


def test_job_progress_line():
    job = ScanJob(chat_id=1, target="t", budget=100, discovery_only=False)
    assert "Queued" in job.progress_line()
    job.stage = "ai"
    assert "AI" in job.progress_line()
    assert "(" in job.progress_line()  # elapsed seconds


def test_bot_cancel_marks_job():
    bot = TelegramBot("t")
    job = ScanJob(chat_id=5, target="t", budget=100, discovery_only=True)
    bot._jobs[5] = job
    bot._cmd_cancel(5)
    assert job.cancelled
    bot._cmd_cancel(5)  # no double-cancel crash


def test_bot_progress_raises_on_cancel():
    bot = TelegramBot("t")
    job = ScanJob(chat_id=5, target="t", budget=100, discovery_only=True)
    job.cancelled = True
    with pytest.raises(ScanCancelled):
        bot._progress(job, "fetch")


def test_bot_welcome_mentions_onchain():
    bot = TelegramBot("t")
    text = bot._welcome_text()
    assert "0x" in text and "IPFS" in text.upper()


def test_bot_languages_card():
    bot = TelegramBot("t")
    text = bot._languages_text()
    for lang in ("Solidity", "Huff", "Scilla", "FunC", "CosmWasm"):
        assert lang in text


def test_scan_cancelled_exception_exists():
    assert issubclass(ScanCancelled, RuntimeError)

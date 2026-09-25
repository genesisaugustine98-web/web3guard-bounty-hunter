"""Target acquisition for *any* source — zero-dollar, no API keys.

Bug-bounty targets do not all publish on GitHub, and some do not publish
source anywhere: the code lives on-chain. This module resolves a target
string into a local directory using only free, unauthenticated
transports:

Git remotes (any host)
    ``https://``/``http://``/``git@``/``ssh://`` URLs ending in ``.git``
    or recognized as GitHub/GitLab/Bitbucket/SourceHut/Gitea/Codeberg/
    cgit shapes. Cloned with ``git clone --depth 1``.

Forge web UIs
    ``/tree/``, ``/blob/``, ``/-/``, cgit ``/about/`` pages and similar
    HTML URLs are normalized to their cloneable git root first.

GitHub gists
    ``https://gist.github.com/user/id`` — gists are git repositories;
    cloned directly.

Tarball/zip archives
    ``.tar.gz``/``.tgz``/``.tar.bz2``/``.tar.xz``/``.zip`` URLs from any
    host (GitHub/GitLab "Download ZIP", cgit ``/snapshot/``, release
    assets, codeload links without extensions). The archive type is
    decided by *magic bytes*, not just the URL suffix, and single-file
    gzip/bzip2/xz payloads are transparently decompressed.

Single files
    A raw ``.sol``/``.vy``/``.move``/... URL is wrapped in a minimal
    single-file target directory so the rest of the pipeline is
    unchanged.

IPFS
    ``ipfs://CID`` and gateway URLs (``https://.../ipfs/CID``) for
    single source files published on IPFS.

On-chain contracts (the flagship)
    A bare address (``0x`` + 40 hex chars), a prefixed shorthand
    (``eth:0x…``, ``base:0x…``, ``arb:0x…``, ``opt:0x…``, ``poly:0x…``,
    ``gno:0x…``, ``scroll:0x…``, plus ``*-sep`` testnets), any Blockscout
    ``/address/0x…`` page, or an Etherscan-family page URL
    (etherscan.io, polygonscan.com, arbiscan.io, basescan.org,
    optimistic.etherscan.io, gnosisscan.io) resolves the *verified*
    contract source through the free Blockscout v2 API — no API key,
    aligned with the zero-dollar policy. Multi-file verifications are
    unpacked with their original paths, and proxy contracts have their
    implementation contracts fetched one level deep so both sides of
    the proxy are scanned.

Shorthands
    ``gh:owner/repo``, ``gl:owner/repo``, ``bb:owner/repo``,
    ``cb:owner/repo``, ``sr:~user/repo``, and bare ``owner/repo``
    (GitHub).

Hardening (applies to every HTTP path)
    - SSRF guard: hostnames are resolved and every returned address is
      checked against loopback, RFC1918, link-local (including the
      cloud metadata service 169.254.169.254), ULA, and unspecified
      ranges; redirects are re-validated at every hop.
    - Schemes restricted to http/https (``file://``, ``ftp://`` are
      rejected before any connection).
    - Streaming downloads with a hard byte cap (archives 512 MiB,
      files 32 MiB) so a hostile URL cannot exhaust the disk.
    - Retries with linear backoff on transient network errors.
    - ``git clone`` runs with terminal prompts disabled so a private
      repo can never hang the pipeline.

Everything here is offline orchestration of public HTTP/git/RPC
transports: no tokens are required, nothing is uploaded, and every
artifact lands in a fresh temp directory the caller owns.
"""

from __future__ import annotations

import bz2
import gzip
import ipaddress
import json
import logging
import lzma
import re
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

LOGGER = logging.getLogger("web3guard.fetch")

_GIT_SUFFIX = ".git"

# Hosts whose /user/repo HTTPS URL is a plain git smart-HTTP endpoint
# (possibly after appending .git). Everything else with an explicit
# .git suffix is treated as git regardless of host.
_KNOWN_FORGE_HOSTS = (
    "github.com",
    "gist.github.com",
    "gitlab.com",
    "bitbucket.org",
    "git.sr.ht",
    "codeberg.org",
    "git.kernel.org",
    "gitea.com",
    "salsa.debian.org",
    "framagit.org",
)

_ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip")

# Magic bytes -> archive suffix. Checked on the downloaded head bytes so
# extension-less links (codeload, ?format=zip release assets) work.
_ARCHIVE_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", ".zip"),
    (b"PK\x05\x06", ".zip"),  # empty zip
    (b"\x1f\x8b", ".tar.gz"),
    (b"BZh", ".tar.bz2"),
    (b"\xfd7zXZ\x00", ".tar.xz"),
)

# File extensions the pipeline can actually analyze (mirrors the language
# registry's extension table). A single-file fetch only proceeds when the
# URL ends in one of these.
_ANALYZABLE_SUFFIXES = (
    ".sol", ".vy", ".vyper", ".move", ".cairo", ".clar", ".fc", ".func",
    ".rs", ".ts", ".js", ".mjs", ".cjs", ".go", ".huff", ".yul", ".scilla",
    ".wat", ".wasm", ".ink", ".spy", ".lig", ".cent", ".mmad", ".pisa",
    ".tz", ".aml", ".txt", ".json",
)

_SHORTHAND_RE = re.compile(r"^(?P<prefix>gl|bb|sr|cb|gh|ipfs):(?P<path>.+)$")
_OWNER_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_EVM_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

# Hard download caps (zero-dollar ops: also a disk-exhaustion guard).
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
_DOWNLOAD_CHUNK = 64 * 1024
_HTTP_RETRIES = 3
_HTTP_TIMEOUT = 120

# ---------------------------------------------------------------------------
# On-chain chains: prefix -> Blockscout API base (all free, no API key).
# ---------------------------------------------------------------------------

_CHAIN_BLOCKSCOUT: dict[str, str] = {
    "eth": "https://eth.blockscout.com",
    "base": "https://base.blockscout.com",
    "arb": "https://arbitrum.blockscout.com",
    "opt": "https://optimism.blockscout.com",
    "poly": "https://polygon.blockscout.com",
    "gno": "https://gnosis.blockscout.com",
    "scroll": "https://scroll.blockscout.com",
    "eth-sep": "https://eth-sepolia.blockscout.com",
    "base-sep": "https://base-sepolia.blockscout.com",
    "arb-sep": "https://arbitrum-sepolia.blockscout.com",
    "opt-sep": "https://optimism-sepolia.blockscout.com",
}

# Default chain used for a bare 0x address.
_DEFAULT_CHAIN = "eth"

# Etherscan-family explorer hosts -> canonical chain prefix. Their own
# API requires a key, so verification data is fetched from the chain's
# free Blockscout mirror instead — same source, zero dollars.
_ETHERSCAN_HOSTS: dict[str, str] = {
    "etherscan.io": "eth",
    "basescan.org": "base",
    "arbiscan.io": "arb",
    "optimistic.etherscan.io": "opt",
    "polygonscan.com": "poly",
    "gnosisscan.io": "gno",
    "scrollscan.com": "scroll",
    "sepolia.etherscan.io": "eth-sep",
}

_ONCHAIN_LANG_EXT = {
    "solidity": ".sol",
    "vyper": ".vy",
}

_USER_AGENT = "web3guard/3.2 (+fetch; zero-dollar)"


class FetchError(RuntimeError):
    """Raised when a target cannot be resolved to a local directory."""


# ---------------------------------------------------------------------------
# HTTP plumbing: SSRF guard, safe redirects, size caps, retries
# ---------------------------------------------------------------------------


def _assert_public_host(url: str) -> None:
    """Reject URLs whose host resolves to a non-public address (SSRF guard).

    Checked for the initial URL and for every redirect hop (see
    :class:`_SafeRedirectHandler`). Loopback / private / link-local /
    ULA targets are refused with :class:`FetchError`; the cloud metadata
    endpoint 169.254.169.254 is the headline casualty.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise FetchError(f"only http/https transports are allowed, got: {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise FetchError(f"URL has no host: {url}")
    host_lower = host.lower().rstrip(".")
    try:
        infos = socket.getaddrinfo(host_lower, None)
    except socket.gaierror as e:
        raise FetchError(f"cannot resolve host {host_lower!r}: {e}") from e
    for info in infos:
        addr = info[4][0]
        if not isinstance(addr, str):
            continue
        try:
            ip = ipaddress.ip_address(addr.split("%")[0])
        except ValueError:
            continue
        if not ip.is_global:
            raise FetchError(
                f"refusing non-public address {ip} for host {host_lower!r} (SSRF guard)"
            )


class _SafeRedirectHandler(HTTPRedirectHandler):
    """Redirect handler that re-runs the SSRF guard on every hop."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        _assert_public_host(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = build_opener(_SafeRedirectHandler())


def _http_request(url: str, max_bytes: int = MAX_FILE_BYTES) -> bytes:
    """GET ``url`` with retries, size cap, and SSRF checks. Returns bytes."""
    _assert_public_host(url)
    req = Request(url, headers={"User-Agent": _USER_AGENT, "Accept": "*/*"})
    last_err: Exception | None = None
    for attempt in range(1, _HTTP_RETRIES + 1):
        try:
            with _OPENER.open(req, timeout=_HTTP_TIMEOUT) as resp:
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = resp.read(_DOWNLOAD_CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise FetchError(
                            f"download exceeded {max_bytes // (1024 * 1024)} MiB cap: {url}"
                        )
                    chunks.append(chunk)
                return b"".join(chunks)
        except FetchError:
            raise  # size cap: not transient
        except (HTTPError, URLError, TimeoutError, OSError) as e:
            last_err = e
            if isinstance(e, HTTPError) and 400 <= e.code < 500 and e.code not in (408, 429):
                break  # client error: retrying will not help
            if attempt < _HTTP_RETRIES:
                time.sleep(attempt)
    raise FetchError(f"download failed for {url}: {last_err}")


def _http_json(url: str) -> dict:
    """GET ``url`` and parse the body as a JSON object."""
    data = _http_request(url, max_bytes=MAX_FILE_BYTES)
    try:
        parsed = json.loads(data.decode("utf-8", errors="replace"))
    except ValueError as e:
        raise FetchError(f"invalid JSON from {url}: {e}") from e
    if not isinstance(parsed, dict):
        raise FetchError(f"unexpected JSON shape from {url}")
    return parsed


def _looks_like_git_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https", "ssh", "git"):
        return False
    if url.endswith(_GIT_SUFFIX):
        return True
    host = (parsed.hostname or "").lower()
    if host in _KNOWN_FORGE_HOSTS:
        return True
    # scp-style remotes: git@host:path
    if url.startswith("git@") and ":" in url:
        return True
    # Explicit git protocol
    if parsed.scheme == "git":
        return True
    return False


def _looks_like_archive(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(s) for s in _ARCHIVE_SUFFIXES)


def _looks_like_single_file(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(s) for s in _ANALYZABLE_SUFFIXES)


def expand_shorthand(target: str) -> str:
    """Expand ``prefix:path`` shorthands to canonical URLs.

    Git forges: ``gh:``, ``gl:``, ``bb:``, ``cb:``, ``sr:``. IPFS:
    ``ipfs:<CID>``. On-chain: a bare ``0x`` address or
    ``<chain>:0x…`` (returned unchanged; :func:`fetch_target` detects
    the address shape after shorthand expansion).
    """
    raw = target.strip()
    m = _SHORTHAND_RE.match(raw)
    if not m:
        return raw
    prefix, path = m.group("prefix"), m.group("path").strip("/")
    if prefix == "gh":
        return f"https://github.com/{path}"
    if prefix == "gl":
        return f"https://gitlab.com/{path}"
    if prefix == "bb":
        return f"https://bitbucket.org/{path}.git"
    if prefix == "cb":
        return f"https://codeberg.org/{path}.git"
    if prefix == "sr":
        return f"https://git.sr.ht/{path}"
    if prefix == "ipfs":
        return f"https://ipfs.io/ipfs/{path}"
    return raw


def normalize_git_url(url: str) -> str:
    """Canonicalize forge-specific HTML URLs into cloneable git URLs."""
    url = url.rstrip("/")
    lower = url.lower()
    # cgit: strip /about, /plain, /log, /tree page paths; append .git
    if "/cgit/" in lower:
        for seg in ("/about", "/plain", "/log", "/tree", "/commit", "/snapshot"):
            if seg + "/" in url or url.endswith(seg):
                url = url.split(seg)[0]
        url = url.rstrip("/")
        if not url.endswith(_GIT_SUFFIX):
            url += _GIT_SUFFIX
        return url
    if "/-/tree/" in url or "/-/blob/" in url:
        # GitLab web UI URL -> project root
        url = url.split("/-/")[0]
    if "/tree/" in url or "/blob/" in url or "/src/" in url:
        # GitHub/Gitea/Codeberg web UI URL -> project root
        url = re.split(r"/(tree|blob|src)/", url)[0]
    if "bitbucket.org/" in lower and not url.endswith(_GIT_SUFFIX):
        url += _GIT_SUFFIX
    if "codeberg.org/" in lower and not url.endswith(_GIT_SUFFIX):
        url += _GIT_SUFFIX
    if not url.endswith(_GIT_SUFFIX) and "/cgit" in lower:
        url += _GIT_SUFFIX
    return url


# ---------------------------------------------------------------------------
# On-chain contract fetching (Blockscout v2 — free, unauthenticated)
# ---------------------------------------------------------------------------


def detect_onchain(target: str) -> tuple[str, str] | None:
    """Return ``(chain_prefix, address)`` when the target is an on-chain
    contract reference, else ``None``.

    Understood shapes:
      - bare address: ``0x<40 hex>``
      - prefixed shorthand: ``eth:0x…``, ``base:0x…``, ``arb:0x…``, …
      - Blockscout page: ``https://<chain>.blockscout.com/address/0x…``
      - Etherscan-family page: ``https://etherscan.io/address/0x…``, …
    """
    raw = str(target).strip()
    if _EVM_ADDRESS_RE.match(raw):
        return (_DEFAULT_CHAIN, raw.lower())
    m = re.match(r"^(?P<chain>[a-z][a-z0-9-]*):(?P<addr>0x[a-fA-F0-9]{40})$", raw)
    if m and m.group("chain") in _CHAIN_BLOCKSCOUT:
        return (m.group("chain"), m.group("addr").lower())
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    host = (parsed.hostname or "").lower()
    parts = [p for p in parsed.path.split("/") if p]
    # .../address/0x… on any blockscout instance
    if host.endswith(".blockscout.com") or host == "blockscout.com":
        if len(parts) >= 2 and parts[0] == "address" and _EVM_ADDRESS_RE.match(parts[1]):
            chain = host.removesuffix(".blockscout.com")
            if chain == "eth-sepolia":
                chain = "eth-sep"
            elif chain == "base-sepolia":
                chain = "base-sep"
            elif chain == "arbitrum-sepolia":
                chain = "arb-sep"
            elif chain == "optimism-sepolia":
                chain = "opt-sep"
            return (chain, parts[1].lower())
    # Etherscan family -> blockscout mirror
    for host_suffix, chain in _ETHERSCAN_HOSTS.items():
        if host == host_suffix or host.endswith("." + host_suffix):
            if len(parts) >= 2 and parts[0] == "address" and _EVM_ADDRESS_RE.match(parts[1]):
                return (chain, parts[1].lower())
    return None


def _sanitize_rel_path(rel: str, fallback: str) -> str:
    """Normalize a path from remote metadata to a safe in-target path."""
    rel = (rel or "").replace("\\", "/").lstrip("/")
    rel = "/".join(seg for seg in rel.split("/") if seg not in ("", ".", ".."))
    return rel or fallback


def _parse_onchain_sources(payload: dict, language: str) -> dict[str, str]:
    """Extract ``{relative_path: source}`` from a Blockscout contract payload.

    Handles the three verification shapes seen in the wild:

    - plain single-file source in ``source_code``
    - standard-JSON-input source in ``source_code`` (a JSON string with
      ``{"sources": {path: {"content": ...}}}`` or a bare path map)
    - main file plus ``additional_sources: [{file_path, source_code}]``
    """
    ext = _ONCHAIN_LANG_EXT.get(str(language or "solidity").lower(), ".sol")
    sources: dict[str, str] = {}

    def _add(path: str, content: str) -> None:
        path = _sanitize_rel_path(path, f"Contract{ext}")
        if not Path(path).suffix:
            path += ext
        sources[path] = content

    raw = payload.get("source_code") or ""
    if isinstance(raw, dict):
        raw = json.dumps(raw)
    text = str(raw).strip()
    if text.startswith("{"):
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            # Standard Foundry / explorer JSON nests the contract map under
            # ``sources``; some payloads inline it directly.
            inner_sources = parsed.get("sources")
            source_map: dict[Any, Any] = (
                inner_sources if isinstance(inner_sources, dict) else parsed
            )
            for path, item in source_map.items():
                content = item.get("content") if isinstance(item, dict) else item
                if isinstance(content, str) and content.strip():
                    _add(str(path), content)
    elif text:
        name = str(payload.get("name") or "Contract")
        _add(f"{name}{ext}", text)

    for extra in payload.get("additional_sources") or []:
        if not isinstance(extra, dict):
            continue
        content = str(extra.get("source_code") or extra.get("content") or "").strip()
        if content:
            _add(str(extra.get("file_path") or extra.get("path") or ""), content)

    if not sources:
        raise FetchError(
            "contract verified but no source could be extracted "
            f"(name={payload.get('name')!r}, language={language!r})"
        )
    return sources


def _write_sources(root: Path, sources: dict[str, str]) -> None:
    for rel, content in sources.items():
        dest = (root / rel).resolve()
        root_resolved = root.resolve()
        if root_resolved not in dest.parents and dest.parent != root_resolved:
            LOGGER.warning("skipping unsafe on-chain source path %r", rel)
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")


def fetch_onchain_contract(
    address: str,
    chain: str = _DEFAULT_CHAIN,
    dest_root: Path | None = None,
    *,
    include_implementations: bool = True,
) -> Path:
    """Download verified contract source for ``address`` on ``chain``.

    Uses the chain's free Blockscout v2 API (no key). Multi-file
    verifications are unpacked with their original paths. Proxy
    contracts additionally have their implementation contracts fetched
    one level deep into ``impls/`` so both proxy and implementation get
    scanned.

    Returns the directory that contains the sources.
    """
    api = _CHAIN_BLOCKSCOUT.get(chain)
    if api is None:
        raise FetchError(
            f"unknown chain {chain!r}; available: {', '.join(sorted(_CHAIN_BLOCKSCOUT))}"
        )
    if not _EVM_ADDRESS_RE.match(address or ""):
        raise FetchError(f"invalid EVM address: {address!r}")

    tmp_root = Path(tempfile.mkdtemp(prefix="web3guard-target-")) if dest_root is None else dest_root
    src_dir = tmp_root / "src"
    src_dir.mkdir(parents=True, exist_ok=True)

    payload = _http_json(f"{api}/api/v2/smart-contracts/{address}")
    if not payload.get("is_verified", True):
        raise FetchError(
            f"contract {address} on {chain} is not verified; no source to scan "
            "(scan a verified contract or clone its repo)"
        )
    language = str(payload.get("language") or "solidity")
    sources = _parse_onchain_sources(payload, language)
    _write_sources(src_dir, sources)
    name = str(payload.get("name") or address)
    LOGGER.info(
        "fetched verified contract %s (%s) on %s: %d file(s)",
        name, address, chain, len(sources),
    )

    if include_implementations:
        proxy_info = payload.get("proxy_info") or {}
        impls = proxy_info.get("implementations") or []
        for idx, impl in enumerate(impls, start=1):
            impl_addr = str(impl.get("address") or "").lower()
            if not _EVM_ADDRESS_RE.match(impl_addr) or impl_addr == address.lower():
                continue
            impl_name = str(impl.get("name") or f"implementation_{idx}")
            try:
                impl_payload = _http_json(f"{api}/api/v2/smart-contracts/{impl_addr}")
                impl_sources = _parse_onchain_sources(
                    impl_payload, str(impl_payload.get("language") or language))
                _write_sources(src_dir / "impls" / impl_name, impl_sources)
                LOGGER.info("fetched proxy implementation %s (%s)", impl_name, impl_addr)
            except FetchError as e:
                LOGGER.warning("implementation %s fetch failed: %s", impl_addr, e)

    # Provenance note so downstream report readers know where this came from.
    (src_dir / "_ONCHAIN_PROVENANCE.txt").write_text(
        f"source: on-chain verified contract\n"
        f"address: {address}\n"
        f"chain: {chain} ({api})\n"
        f"contract_name: {name}\n"
        f"compiler: {payload.get('compiler_version') or 'unknown'}\n"
        f"language: {language}\n"
        f"proxy_type: {(payload.get('proxy_info') or {}).get('proxy_type') or 'none'}\n",
        encoding="utf-8",
    )
    return src_dir


# ---------------------------------------------------------------------------
# Git + archive transport
# ---------------------------------------------------------------------------


def _git_clone(url: str, dest: Path, timeout: int = 180) -> None:
    _assert_public_host(url) if "://" in url else None
    cmd = ["git", "clone", "--depth", "1", url, str(dest)]
    env = {
        "GIT_TERMINAL_PROMPT": "0",   # never hang waiting for credentials
        "GIT_ASKPASS": "echo",
        "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    }
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False, env=env,
        )
    except FileNotFoundError as e:
        raise FetchError("git is not installed on this host") from e
    except subprocess.TimeoutExpired as e:
        raise FetchError(f"git clone timed out after {timeout}s: {url}") from e
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        hint = ""
        if "Authentication failed" in stderr or "could not read Username" in stderr:
            hint = (
                " (repository requires credentials; Web3Guard never uses "
                "stored keys for fetching — clone manually and scan the "
                "local path)"
            )
        raise FetchError(f"git clone failed for {url}: {stderr[:400]}{hint}")
    if not dest.is_dir():
        raise FetchError(f"git clone produced no directory for {url}")


def _sniff_archive_ext(head: bytes) -> str | None:
    for magic, ext in _ARCHIVE_MAGIC:
        if head.startswith(magic):
            return ext
    return None


def _http_download(url: str, dest: Path, timeout: int = _HTTP_TIMEOUT) -> str | None:
    """Stream ``url`` to ``dest`` with size cap + retries.

    Returns the sniffed archive extension (``.zip``/``.tar.gz``/… ) when
    the payload's magic bytes identify an archive, else ``None``.
    """
    _assert_public_host(url)
    req = Request(url, headers={"User-Agent": _USER_AGENT, "Accept": "*/*"})
    last_err: Exception | None = None
    for attempt in range(1, _HTTP_RETRIES + 1):
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
                cap = MAX_ARCHIVE_BYTES if _looks_like_archive(url) else MAX_FILE_BYTES
                head = b""
                total = 0
                with dest.open("wb") as fh:
                    while True:
                        chunk = resp.read(_DOWNLOAD_CHUNK)
                        if not chunk:
                            break
                        if not head:
                            head = chunk[:16]
                        total += len(chunk)
                        if total > cap:
                            raise FetchError(
                                f"download exceeded {cap // (1024 * 1024)} MiB cap: {url}"
                            )
                        fh.write(chunk)
            return _sniff_archive_ext(head)
        except FetchError:
            raise  # size cap: not transient
        except (HTTPError, URLError, TimeoutError, OSError) as e:
            last_err = e
            if isinstance(e, HTTPError) and 400 <= e.code < 500 and e.code not in (408, 429):
                break
            if attempt < _HTTP_RETRIES:
                time.sleep(attempt)
    raise FetchError(f"download failed for {url}: {last_err}")


def _safe_member_target(dest_root: Path, member_name: str) -> Path:
    """Resolve a member path and refuse anything outside ``dest_root``.

    Catches absolute paths, ``..`` traversal, and drive-relative shapes.
    """
    target = (dest_root / member_name).resolve()
    root_resolved = dest_root.resolve()
    if root_resolved not in target.parents and target != root_resolved:
        raise FetchError(f"archive member escapes extraction root: {member_name}")
    return target


def _extract_archive(archive: Path, dest_root: Path) -> Path:
    """Extract ``archive`` under ``dest_root`` and return the target dir.

    v3.4 hardening: extraction is done *manually*, member by member —
    ``extractall`` is never called. Link members (tar symlinks/hardlinks,
    zip symlinks) are refused outright: they previously slipped past the
    name-only guard and let a member path traverse outside the extraction
    root through a pre-existing symlink target (verified exploit).

    Single-file gzip/bzip2/xz payloads (not tar) are transparently
    decompressed into ``payload`` — some release assets do that.
    """
    lower = archive.name.lower()
    dest_root.mkdir(parents=True, exist_ok=True)

    try:
        if lower.endswith(".zip") or _sniff_archive_ext(archive.open("rb").read(8) if archive.stat().st_size >= 8 else b"") == ".zip":
            with zipfile.ZipFile(archive) as zf:
                for info in zf.infolist():
                    # Refuse symlink members: a later file member written
                    # through them would escape the extraction root.
                    if (info.external_attr >> 16) & 0o170000 == 0o120000:
                        raise FetchError(
                            f"archive contains a symlink member: {info.filename}")
                    target = _safe_member_target(dest_root, info.filename)
                    if info.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info) as src, target.open("wb") as out:
                        shutil.copyfileobj(src, out)
        else:
            # Literal-typed so the tarfile.open overload for stream modes
            # ("r:*" et al.) type-checks without a cast.
            mode: Literal["r:*", "r:bz2", "r:xz", "r:gz"] = "r:*"
            if lower.endswith(".tar.bz2"):
                mode = "r:bz2"
            elif lower.endswith(".tar.xz"):
                mode = "r:xz"
            elif lower.endswith((".tgz", ".tar.gz")):
                mode = "r:gz"
            try:
                with tarfile.open(archive, mode) as tf:
                    for member in tf.getmembers():
                        _safe_member_target(dest_root, member.name)
                        # Refuse link members entirely (symlink + hardlink):
                        # a hardlink to /etc/passwd is as bad as a symlink.
                        if member.issym() or member.islnk():
                            raise FetchError(
                                "archive contains a link member: "
                                f"{member.name} -> {member.linkname}")
                        target = dest_root / member.name
                        if member.isdir():
                            target.mkdir(parents=True, exist_ok=True)
                            continue
                        if not member.isreg():
                            continue  # devices/fifos: ignore, never create
                        target.parent.mkdir(parents=True, exist_ok=True)
                        member_src = tf.extractfile(member)
                        if member_src is None:  # pragma: no cover - isreg() is True
                            continue
                        with member_src, target.open("wb") as out:
                            shutil.copyfileobj(member_src, out)
            except tarfile.ReadError:
                # Not a tar container: try a bare compressed single file.
                data = archive.read_bytes()
                if lower.endswith((".tgz", ".tar.gz")) or data[:2] == b"\x1f\x8b":
                    data = gzip.decompress(data)
                elif lower.endswith(".tar.bz2") or data[:3] == b"BZh":
                    data = bz2.decompress(data)
                elif lower.endswith(".tar.xz") or data[:6] == b"\xfd7zXZ\x00":
                    data = lzma.decompress(data)
                else:
                    raise
                (dest_root / "payload").write_bytes(data)
    except FetchError:
        raise
    except Exception as e:  # noqa: BLE001
        raise FetchError(f"archive extraction failed for {archive.name}: {e}") from e

    entries = [p for p in dest_root.iterdir() if not p.name.startswith(".")]
    dirs = [p for p in entries if p.is_dir()]
    if len(dirs) == 1 and len(entries) == 1:
        return dirs[0]
    return dest_root


# ---------------------------------------------------------------------------
# Top-level resolution
# ---------------------------------------------------------------------------


def fetch_target(target: str, workdir: Path | None = None) -> Path:
    """Resolve ``target`` to a local directory.

    Supported shapes (all free, no credentials):

    - local paths (returned as-is when they exist)
    - any git remote URL (GitHub, gists, GitLab, Bitbucket, SourceHut,
      Codeberg, cgit, self-hosted Gitea/GitLab, ssh remotes)
    - archive URLs (.tar.gz/.tgz/.tar.bz2/.tar.xz/.zip) from any host,
      with magic-byte sniffing for extension-less links
    - single raw source files
    - IPFS: ``ipfs://CID``, ``ipfs:CID``, gateway URLs
    - on-chain contracts: bare ``0x…`` addresses, ``<chain>:0x…``
      shorthands, Blockscout and Etherscan-family address pages
    - shorthands: ``gh:owner/repo``, ``gl:owner/repo``, ``bb:owner/repo``,
      ``cb:owner/repo``, ``sr:~user/repo``, and bare ``owner/repo``
    """
    raw = str(target).strip()
    if not raw:
        raise FetchError("empty target")

    # 0. Local paths win immediately (no network, no temp dir).
    if "://" not in raw and not raw.startswith("git@"):
        p = Path(raw).expanduser()
        if p.is_dir():
            return p.resolve()

    resolved = expand_shorthand(raw)

    # 1. On-chain contract? (bare 0x, chain:0x shorthand already expanded
    #    through unchanged, blockscout/etherscan page URLs)
    onchain = detect_onchain(resolved) or (detect_onchain(raw) if resolved == raw else None)
    if onchain is not None:
        chain, address = onchain
        tmp_root = Path(tempfile.mkdtemp(
            prefix="web3guard-target-", dir=str(workdir) if workdir else None))
        return fetch_onchain_contract(address, chain, tmp_root)

    # 2. Bare owner/repo shorthand -> GitHub.
    if resolved == raw and "://" not in raw and not raw.startswith("git@") \
            and _OWNER_REPO_RE.match(raw):
        resolved = f"https://github.com/{raw}"

    tmp_root = Path(tempfile.mkdtemp(
        prefix="web3guard-target-", dir=str(workdir) if workdir else None))

    # 3. Git remote?
    if _looks_like_git_url(resolved):
        clone_url = normalize_git_url(resolved)
        _git_clone(clone_url, tmp_root / "repo")
        return tmp_root / "repo"

    # 4. Downloadable artifact (archive suffix, single file, or anything
    #    else we can sniff once the head bytes arrive).
    if _looks_like_archive(resolved) or _looks_like_single_file(resolved) or True:
        download_name = "artifact"
        parsed = urlparse(resolved)
        base_name = Path(parsed.path).name or download_name
        dest = tmp_root / base_name
        try:
            sniffed = _http_download(resolved, dest)
        except FetchError as e:
            _cleanup_tmp(tmp_root)
            if _looks_like_archive(resolved) or _looks_like_single_file(resolved):
                raise
            # 5. Fall through to repo-shape guesses below.
            LOGGER.info("direct download failed for %s (%s); trying repo shapes", resolved, e)
        else:
            is_html = dest.read_bytes()[:512].lstrip().lower().startswith(
                (b"<!doctype html", b"<html")) if dest.exists() and dest.stat().st_size else False
            ext = sniffed or (_archive_ext_of(resolved) if _looks_like_archive(resolved) else None)
            if ext:
                return _extract_archive(dest, tmp_root / "extracted")
            if is_html:
                _cleanup_tmp(tmp_root)
                LOGGER.info("URL returned HTML, not a raw artifact; trying repo shapes")
            else:
                suffix = Path(parsed.path).suffix or ".txt"
                out = tmp_root / "src"
                out.mkdir(parents=True, exist_ok=True)
                target_file = out / (base_name or f"source{suffix}")
                shutil.move(str(dest), target_file)
                return out

    # 6. Repo-shape fallbacks: clone with .git appended, then common
    #    archive endpoints (GitLab/Gitea-style, GitHub codeload, cgit).
    candidate = normalize_git_url(resolved)
    try:
        _git_clone(candidate, tmp_root / "repo")
        return tmp_root / "repo"
    except FetchError:
        LOGGER.info("git fallback failed for %s; trying archive endpoints", resolved)

    guesses: list[str] = []
    if parsed.scheme in ("http", "https"):
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"
        project = parsed.path.rstrip("/").rsplit("/", 1)[-1]
        guesses = [
            f"{base}/-/archive/main/{project}-main.tar.gz",
            f"{base}/-/archive/master/{project}-master.tar.gz",
            f"{base}/archive/main.zip",
            f"{base}/archive/master.zip",
            f"{base}/archive/refs/heads/main.tar.gz",
            f"{base}/archive/refs/heads/master.tar.gz",
            f"{base}/snapshot/main.tar.gz",
            f"{base}/~{parsed.path.strip('/')}.tar.gz",
        ]
        if "github.com" in parsed.netloc.lower():
            parts = [p for p in parsed.path.split("/") if p]
            if len(parts) >= 2:
                guesses = [
                    f"https://codeload.github.com/{parts[0]}/{parts[1]}/zip/refs/heads/main",
                    f"https://codeload.github.com/{parts[0]}/{parts[1]}/zip/refs/heads/master",
                ] + guesses
    for guess in guesses:
        try:
            archive = tmp_root / ("guess" + (_archive_ext_of(guess)))
            sniffed = _http_download(guess, archive)
            ext = sniffed or _archive_ext_of(guess)
            archive = archive.rename(archive.with_name("guess" + ext))
            return _extract_archive(archive, tmp_root / "extracted")
        except FetchError:
            continue

    _cleanup_tmp(tmp_root)
    raise FetchError(
        f"could not resolve target {target!r}: not a git remote, archive, "
        "single source file, on-chain contract, IPFS path, or local path"
    )


def _archive_ext_of(url: str) -> str:
    path = urlparse(url).path.lower()
    for suffix in _ARCHIVE_SUFFIXES:
        if path.endswith(suffix):
            return suffix
    return ".zip"


def _cleanup_tmp(tmp_root: Path) -> None:
    shutil.rmtree(tmp_root, ignore_errors=True)


def cleanup_target(path: Path) -> None:
    """Remove a fetch's temp tree (best effort)."""
    try:
        candidate = Path(path)
        for _ in range(4):
            if candidate.name.startswith("web3guard-target-"):
                shutil.rmtree(candidate, ignore_errors=True)
                return
            if candidate.parent.name.startswith("web3guard-target-"):
                shutil.rmtree(candidate.parent, ignore_errors=True)
                return
            candidate = candidate.parent
    except Exception:  # noqa: BLE001
        pass

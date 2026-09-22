"""
Stale-deployment verification via chain RPC.

Feature v3.3: ``enable_deployment_verification``. For every Solidity
target, fetch the *deployed* bytecode through a JSON-RPC provider
(``eth_getCode``) and compare it against the source that is about to
be scanned:

- **no code at the address** — the contract is not deployed (source
  may be unaudited WIP); the scan proceeds with a note.
- **match** — compiled source reproduces the deployed bytecode once
  the trailing CBOR metadata section is stripped from both (so a
  different compiler build of the same source is still a match).
- **divergent** — the deployed code differs from the source: findings
  from this file may not apply to what is actually live. The result is
  surfaced in the report and the target metadata so a researcher does
  not waste budget on a stale tree.

Design notes:
- JSON-RPC POST bodies are tiny, so the share-nothing stdlib client
  keeps this dependency-free and easy to stub in tests.
- Every URL passes the same SSRF guard as target fetching — a config
  file can point the verifier at ``http://169.254.169.254`` and it
  will be refused like any other private address.
- Bytecode comparison strips the trailing ``a264``-prefixed CBOR
  metadata section (Solidity appends it; it embeds compiler flags and
  the IPFS hash and legitimately differs across environments).
- A failure to *reach* the RPC is never fatal: verification degrades
  to ``unknown`` and scanning continues.

Config keys::

    enable_deployment_verification: false   # opt-in
    rpc_urls:                               # optional; derived per-chain
      eth: "https://eth.llamarpc.com"       #   from the chain prefix
    rpc_timeout_seconds: 15
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from web3guard.utils.fetch import (
    detect_onchain,
)

LOGGER = logging.getLogger("web3guard.deploy_verify")

# Public JSON-RPC endpoints used when the config does not name one.
# Free, no-key endpoints chosen for read-only reliability; override
# with ``rpc_urls`` in config for production use.
_CHAIN_RPC: dict[str, str] = {
    "eth": "https://eth.llamarpc.com",
    "base": "https://base.llamarpc.com",
    "arb": "https://arb1.arbitrum.io/rpc",
    "opt": "https://mainnet.optimism.io",
    "poly": "https://polygon-rpc.com",
    "gno": "https://rpc.gnosischain.com",
    "scroll": "https://rpc.scroll.io",
    "eth-sep": "https://ethereum-sepolia-rpc.publicnode.com",
    "base-sep": "https://base-sepolia-rpc.publicnode.com",
    "arb-sep": "https://sepolia-rollup.arbitrum.io/rpc",
    "opt-sep": "https://sepolia.optimism.io",
}

# Fallback public endpoints tried in order if the first one fails.
_CHAIN_RPC_FALLBACK: dict[str, list[str]] = {
    "eth": ["https://rpc.ankr.com/eth", "https://cloudflare-eth.com"],
    "base": ["https://base.publicnode.com"],
    "eth-sep": ["https://rpc.sepolia.org"],
}

_EVM_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_EVM_RUNTIME_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]*$")
# Solidity appends a CBOR metadata blob starting with the bytes a2 64
# ("ipfs" CBOR map) or a2 65 ("bzzr"). Everything from that marker to
# the end of the runtime code is compilation metadata.
_METADATA_MARKERS = ("a264", "a265")


class DeploymentVerificationError(RuntimeError):
    """Raised for caller mistakes (bad address/URL), not network issues."""


@dataclass
class VerificationResult:
    """Outcome of comparing source against deployed bytecode."""

    address: str
    chain: str
    rpc_url: str
    verdict: str  # match | divergent | not-deployed | unknown
    detail: str = ""
    deployed_codehash: str = ""
    source_codehash: str = ""

    def to_metadata(self) -> dict[str, str]:
        return {
            "deployment_chain": self.chain,
            "deployment_address": self.address,
            "deployment_verdict": self.verdict,
            "deployment_detail": self.detail,
        }


# ---------------------------------------------------------------------------
# JSON-RPC plumbing (stdlib, SSRF-guarded)
# ---------------------------------------------------------------------------


def _rpc_call(url: str, method: str, params: list, *, timeout: float) -> str:
    """One JSON-RPC call; returns ``result`` as a raw JSON string value.

    Raises :class:`DeploymentVerificationError` on any failure — callers
    treat that as "verification unavailable" rather than fatal.
    """
    from web3guard.utils.fetch import FetchError, _assert_public_host

    try:
        # SSRF guard first: a config-file URL pointing at a private
        # address (e.g. the cloud metadata endpoint) is refused before
        # any request leaves the process.
        _assert_public_host(url)
        body = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
        }).encode("utf-8")
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except FetchError as e:
        raise DeploymentVerificationError(f"url refused: {e}") from e
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as e:
        raise DeploymentVerificationError(f"rpc unreachable: {e}") from e
    if payload.get("error"):
        raise DeploymentVerificationError(f"rpc error: {payload['error']}")
    result = payload.get("result")
    if not isinstance(result, str):
        raise DeploymentVerificationError("rpc returned no string result")
    return result


def get_code(
    address: str,
    rpc_url: str,
    *,
    timeout: float = 15.0,
) -> str:
    """``eth_getCode`` for ``address``; raises on RPC failure."""
    if not _EVM_ADDRESS_RE.match(address):
        raise DeploymentVerificationError(f"not an EVM address: {address!r}")
    return _rpc_call(rpc_url, "eth_getCode", [address, "latest"], timeout=timeout)


# ---------------------------------------------------------------------------
# Bytecode comparison
# ---------------------------------------------------------------------------


def _strip_metadata(code_hex: str) -> str:
    """Drop the trailing Solidity CBOR metadata section.

    The runtime bytecode ends with a two-byte big-endian length followed
    by the CBOR blob (starting ``a264``/``a265``). Re-compiles with a
    different compiler build differ only there, so comparison ignores it.
    A code string without the marker is returned unchanged.
    """
    c = code_hex.lower().removeprefix("0x")
    for marker in _METADATA_MARKERS:
        idx = c.rfind(marker)
        if idx > 0:
            # Marker found and at least one length byte precedes it:
            # everything from the marker on is metadata.
            return c[:idx]
    return c


def classify_bytecode(source_code: str, deployed_code: str) -> str:
    """Compare compiled-source bytecode with deployed bytecode.

    Both sides are stripped of the CBOR metadata tail first, so a
    re-compilation with a different compiler build (which differs only
    in the metadata hash) classifies as ``match``. Any remaining body
    difference is ``divergent`` — a different opcode layout is a
    different program, not a metadata artifact.

    Returns ``match`` | ``divergent``. Empty strings short-circuit to
    ``divergent`` so a caller that lost one side never reports a false
    "match".
    """
    s = _strip_metadata(source_code)
    d = _strip_metadata(deployed_code)
    if not s or not d:
        return "divergent"
    return "match" if s == d else "divergent"


# ---------------------------------------------------------------------------
# Target-level entry point
# ---------------------------------------------------------------------------


def resolve_rpc(chain: str, config: dict) -> str:
    """Pick the RPC URL for ``chain`` from config or the public table."""
    configured = config.get("rpc_urls") or {}
    if isinstance(configured, dict) and configured.get(chain):
        return str(configured[chain])
    if chain not in _CHAIN_RPC:
        raise DeploymentVerificationError(
            f"no known public RPC for chain {chain!r}; set rpc_urls.{chain} in config"
        )
    return _CHAIN_RPC[chain]


def _find_deployed_address(target_path: Path, target: str) -> tuple[str, str] | None:
    """Best-effort (chain, address) for a target.

    Order: explicit on-chain reference in the target string (the fetch
    layer's shapes), else an address recorded in the repo's deployment
    artifacts (``deployments/*/*.json`` etc.).
    """
    onchain = detect_onchain(target)
    if onchain and _EVM_ADDRESS_RE.match(onchain[1]):
        return onchain
    # Look for addresses in common deployment-output layouts.
    addr_re = re.compile(r"\b(0x[a-fA-F0-9]{40})\b")
    skip = {"node_modules", ".git", "out", "cache", "artifacts", "lib"}
    for pattern in ("deployments/*/*.json", "deployments/*.json",
                    "broadcast/*/*/*.json", "*.deploy.json"):
        for path in sorted(target_path.glob(pattern)):
            if any(part in skip for part in path.parts):
                continue
            try:
                text = path.read_text(errors="ignore")[:200_000]
            except OSError:
                continue
            m = addr_re.search(text)
            if m:
                return ("eth", m.group(1).lower())
    return None


def _find_compiled_bytecode(target_path: Path) -> str:
    """Best-effort runtime bytecode compiled from the local source.

    Prefers a Forge build output (``out/*.sol/*.json`` -> ``bytecode``
    -> ``object``); falls back to running nothing — we do not compile
    here, we reuse artifacts the developer's build already produced.
    """
    out_dir = target_path / "out"
    if not out_dir.is_dir():
        return ""
    best = ""
    for artifact in sorted(out_dir.rglob("*.json")):
        try:
            data = json.loads(artifact.read_text(errors="ignore"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        obj = (
            data.get("bytecode", {}).get("object", "")
            if isinstance(data.get("bytecode"), dict) else ""
        )
        if isinstance(obj, str) and _EVM_RUNTIME_RE.match(obj) and len(obj) > len(best):
            best = obj
    return best


def verify_target(
    target_path: Path,
    target: str,
    config: dict,
) -> VerificationResult:
    """Verify the deployed bytecode for ``target`` against local artifacts.

    Never raises for network/RPC problems — those collapse to
    ``verdict="unknown"`` with the reason in ``detail``. Caller mistakes
    (unresolvable chain) also degrade to ``unknown``: verification is a
    signal, not a gate.
    """
    timeout = float(config.get("rpc_timeout_seconds", 15))
    found = _find_deployed_address(target_path, target)
    if found is None:
        return VerificationResult("", "", "", "unknown",
                                  detail="no deployed address found for target")
    chain, address = found
    try:
        rpc_url = resolve_rpc(chain, config)
    except DeploymentVerificationError as e:
        return VerificationResult(address, chain, "", "unknown", detail=str(e))

    last_err = ""
    for url in [rpc_url, *_CHAIN_RPC_FALLBACK.get(chain, [])]:
        try:
            deployed = get_code(address, url, timeout=timeout)
            break
        except DeploymentVerificationError as e:
            last_err = str(e)
            deployed = ""
    if not deployed:
        return VerificationResult(address, chain, rpc_url, "unknown",
                                  detail=last_err or "no RPC answered")
    if deployed.lower().removeprefix("0x") in ("", "0x"):
        return VerificationResult(address, chain, rpc_url, "not-deployed",
                                  detail="eth_getCode returned empty bytecode")

    source_code = _find_compiled_bytecode(target_path)
    if not source_code:
        return VerificationResult(
            address, chain, rpc_url, "unknown",
            detail="no compiled bytecode artifacts (run forge build first)",
        )
    verdict = classify_bytecode(source_code, deployed)
    detail = {
        "match": "compiled source matches deployed bytecode",
    }.get(verdict, "deployed bytecode differs from compiled source")
    return VerificationResult(
        address, chain, rpc_url, verdict, detail=detail,
        deployed_codehash=f"len:{len(deployed)}",
        source_codehash=f"len:{len(source_code)}",
    )

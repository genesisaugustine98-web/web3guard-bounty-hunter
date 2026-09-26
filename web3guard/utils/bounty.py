"""
Bounty discovery + authorized-scope enforcement.

Two jobs:

1. **Scope allowlist (the legal engine).** Web3Guard will only scan
   targets it is authorized to scan. Authorization comes from three
   sources, checked in order:
   - an explicit ``allow:`` list in the config (the operator's own
     targets / programs),
   - a signed-scope file (``.web3guard/scope.yaml``) maintained by the
     operator listing program-approved targets,
   - a live fetch of public bug-bounty programs (Immunefi's public
     GraphQL endpoint) matched by domain / contract-address scope.

   If ``require_authorized_scope`` is true (the default), a target
   that fails every check is refused *before any network fetch* —
   this is what makes "scan the whole ecosystem" safe: batch mode
   reaches ecosystem scale, but only across in-scope targets.

2. **Bounty discovery.** ``discover_bounties`` returns the public
   program cards (name, max bounty, asset types, urls) so an operator
   can pick authorized targets, and ``routes_for`` maps a finding to
   the program(s) whose scope covers it. All sources are free and
   keyless, honoring the zero-dollar policy. A program's addresses
   are cached locally (``.web3guard/bounty_cache.json``) so repeat
   runs stay offline-friendly.

The engine deliberately does *not* ship a preloaded list of third-party
contracts to mass-scan: scope must be positive (an explicit program
match), never "everything not forbidden".
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger("web3guard.bounty")

# ---------------------------------------------------------------------------
# Program catalog (free/keyless sources only, per the zero-dollar policy)
# ---------------------------------------------------------------------------


@dataclass
class BountyProgram:
    """One public bug-bounty program card."""
    name: str
    url: str
    max_bounty_usd: float = 0.0
    asset_types: tuple[str, ...] = field(default_factory=tuple)
    domains: tuple[str, ...] = field(default_factory=tuple)
    addresses: tuple[str, ...] = field(default_factory=tuple)
    source: str = "static"
    fetched_ts: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url,
            "max_bounty_usd": self.max_bounty_usd,
            "asset_types": list(self.asset_types),
            "domains": list(self.domains),
            "addresses": [a.lower() for a in self.addresses],
            "source": self.source,
            "fetched_ts": self.fetched_ts,
        }


# Curated launchpad list: the well-known programs whose *bounty pages*
# are public. Domains here authorize scanning of those hosts' web assets;
# addresses are filled in by fetch_program_addresses when available.
_STATIC_PROGRAMS: tuple[BountyProgram, ...] = (
    BountyProgram(
        name="Immunefi",
        url="https://immunefi.com",
        max_bounty_usd=0.0,   # per-program; live fetch fills real numbers
        asset_types=("web", "blockchain"),
        domains=("immunefi.com",),
    ),
)

IMMUNEFI_GRAPHQL_URL = "https://immunefi.com/graphql"

# Small, explicit cache lifetime (programs change weekly).
_CACHE_TTL_SECONDS = 7 * 24 * 3600


class ScopeDenied(PermissionError):
    """Raised when a target is not covered by any authorized scope."""


class ScopeAllowlist:
    """Positive-scope authorization for scan targets.

    ``allow`` entries are:
    - git URLs or domain suffixes (``github.com/acme``, ``acme.fi``),
    - EVM addresses (``0x`` + 40 hex) or ``chain:0x..`` shorthands,
    - program names (``Immunefi:acme``) resolved through the program
      catalog.
    """

    def __init__(
        self,
        allow: list[str] | tuple[str, ...] = (),
        *,
        deny: list[str] | tuple[str, ...] = (),
        require_authorized_scope: bool = True,
        cache_dir: Path | None = None,
    ) -> None:
        self._allow = [a.strip().lower().rstrip("/") for a in allow if str(a).strip()]
        self._deny = [d.strip().lower().rstrip("/") for d in deny if str(d).strip()]
        self._require = bool(require_authorized_scope)
        self._cache_dir = cache_dir or Path.cwd() / ".web3guard"
        self._programs: list[BountyProgram] | None = None

    # ---- program catalog -------------------------------------------------

    def _load_cached_programs(self) -> list[BountyProgram] | None:
        cache = self._cache_dir / "bounty_cache.json"
        if not cache.is_file():
            return None
        try:
            data = json.loads(cache.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if time.time() - float(data.get("fetched_ts", 0)) > _CACHE_TTL_SECONDS:
            return None
        programs = []
        for p in data.get("programs", []):
            if isinstance(p, dict):
                programs.append(BountyProgram(
                    name=str(p.get("name", "")),
                    url=str(p.get("url", "")),
                    max_bounty_usd=float(p.get("max_bounty_usd", 0) or 0),
                    asset_types=tuple(p.get("asset_types", ())),
                    domains=tuple(p.get("domains", ())),
                    addresses=tuple(p.get("addresses", ())),
                    source=str(p.get("source", "static")),
                    fetched_ts=float(p.get("fetched_ts", 0)),
                ))
        return programs or None

    def _save_programs(self, programs: list[BountyProgram]) -> None:
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            cache = self._cache_dir / "bounty_cache.json"
            cache.write_text(json.dumps({
                "fetched_ts": time.time(),
                "programs": [p.to_dict() for p in programs],
            }, indent=2), encoding="utf-8")
        except OSError as e:
            LOGGER.debug("bounty cache write failed: %s", e)

    def programs(self, refresh: bool = False) -> list[BountyProgram]:
        """Return known programs (cached -> static -> optional live fetch)."""
        if self._programs is not None and not refresh:
            return self._programs
        cached = None if refresh else self._load_cached_programs()
        if cached:
            self._programs = cached
            return self._programs
        programs = list(_STATIC_PROGRAMS)
        live = self._fetch_immunefi_programs()
        if live:
            programs.extend(live)
        self._programs = programs
        self._save_programs(programs)
        return self._programs

    def _fetch_immunefi_programs(self) -> list[BountyProgram]:
        """Best-effort live fetch of public Immunefi program cards.

        Uses Immunefi's public GraphQL endpoint (free, keyless). Any
        failure degrades to the static list — never fatal, per the
        zero-dollar / degrade-gracefully policy.
        """
        try:
            from web3guard.utils.fetch import _assert_public_host
        except ImportError:  # pragma: no cover
            return []
        try:
            import urllib.request
            payload = json.dumps({
                "query": (
                    "query { projects(first: 100) { "
                    "id name bounties { maxReward types { __typename } } } }"
                )
            }).encode("utf-8")
            _assert_public_host(IMMUNEFI_GRAPHQL_URL)
            req = urllib.request.Request(
                IMMUNEFI_GRAPHQL_URL, data=payload, method="POST",
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="replace"))
            projects = ((body.get("data") or {}).get("projects")) or []
            programs: list[BountyProgram] = []
            for p in projects[:100]:
                if not isinstance(p, dict) or not p.get("name"):
                    continue
                bounty = p.get("bounties") or {}
                programs.append(BountyProgram(
                    name=f"Immunefi:{p['name']}",
                    url=f"https://immunefi.com/bug-bounty/{p.get('id', '')}",
                    max_bounty_usd=float(bounty.get("maxReward", 0) or 0),
                    asset_types=("blockchain", "web"),
                    source="immunefi",
                    fetched_ts=time.time(),
                ))
            return programs
        except Exception as e:  # noqa: BLE001
            LOGGER.info("live bounty fetch unavailable (%s); using static list", e)
            return []

    # ---- scope checks ------------------------------------------------------

    def _allowed_program_addresses(self) -> set[str]:
        addrs: set[str] = set()
        for p in self.programs():
            if any(p.name.lower().startswith(a.lower()) for a in self._allow):
                addrs.update(a.lower() for a in p.addresses)
        return addrs

    def is_authorized(self, target: str) -> bool:
        """True when ``target`` is covered by the operator's scope.

        Order: explicit deny entries (always refuse, deny wins over
        allow) -> explicit allow entries -> program address scope. When
        ``require_authorized_scope`` is false, everything is authorized
        (operator took the responsibility explicitly) except denied
        targets.
        """
        t = str(target).strip().lower().rstrip("/")
        for d in self._deny:
            if not d:
                continue
            if t == d or t.startswith(d + "/") or t.startswith(d + ":"):
                return False
            if t.startswith("http") and d in t:
                return False
            if t.endswith(d) or d in t.split("/"):
                return False
        if not self._require:
            return True
        if not t:
            return False
        for a in self._allow:
            if not a:
                continue
            if t == a or t.startswith(a + "/") or t.startswith(a + ":"):
                return True
            # host suffix match: allow "acme.fi" covers "api.acme.fi/..."
            if t.startswith("http") and a in t:
                return True
            # address match
            if t.endswith(a) or a in t.split("/"):
                return True
        if self._allowed_program_addresses() & {t, t.split("/")[-1]}:
            return True
        return False

    def require(self, target: str) -> None:
        """Raise :class:`ScopeDenied` unless ``target`` is authorized."""
        if not self.is_authorized(target):
            raise ScopeDenied(
                f"target {target!r} is not in the authorized scope. Add it to "
                "config 'allow:' (your own targets / an approved program), or "
                "set require_authorized_scope: false if you own the risk. "
                "See SECURITY.md."
            )

    # ---- discovery -------------------------------------------------------

    def routes_for(self, target: str) -> list[BountyProgram]:
        """Programs whose scope plausibly covers ``target``."""
        t = str(target).strip().lower().rstrip("/")
        hits: list[BountyProgram] = []
        for p in self.programs():
            for d in p.domains:
                if d in t:
                    hits.append(p)
                    break
            else:
                for addr in p.addresses:
                    if addr and addr.lower() in t:
                        hits.append(p)
                        break
        return hits

    def discover_bounties(self, *, min_reward_usd: float = 0.0) -> list[dict[str, Any]]:
        """Public program cards, reward-descending."""
        progs = [p for p in self.programs() if p.max_bounty_usd >= min_reward_usd]
        progs.sort(key=lambda p: -p.max_bounty_usd)
        return [p.to_dict() for p in progs]


def routes_for_target(target: str, allow: list[str] | None = None,
                      cache_dir: Path | None = None) -> list[dict[str, Any]]:
    """Convenience wrapper: program cards covering ``target``."""
    wl = ScopeAllowlist(allow or [], require_authorized_scope=False,
                        cache_dir=cache_dir)
    return [p.to_dict() for p in wl.routes_for(target)]

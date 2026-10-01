"""Long-tail protocol sweep — a resumable, rate-limited target runner.

Sweeps a target list from a YAML config file (``name -> repo URL or
contract address``). This is the "hunt the long tail" primitive: small,
unaudited forks and fresh deployments that the big scanners ignore.

ROE gating mirrors ``docs/WEBRECON.md`` exactly — the restrictions are
re-stated here because this module must never loosen them:

1. **Explicit opt-in per target.** A target is only swept if the user
   listed it in *their* config file. The config is the user's
   assertion that they are authorized to assess the target (same role
   as webrecon's authorization file). Nothing is ever added
   automatically.
2. **Deny-list before allow-list.** ``localhost``, loopback, link-local
   and cloud metadata endpoints are refused *even if listed* (SSRF /
   self-scan protection) — for repo URL hosts and for any host the
   runner would contact.
3. **Politeness.** Serialized execution, a minimum interval between
   targets (default 2 s), and a hard per-run target budget (default
   25). Budgets stop the run gracefully, never as a failure.
4. **Audit trail.** ``sweep_audit.jsonl`` records ``session_start``
   (with the config fingerprint), every per-target decision, budget
   stops, and ``session_end``.
5. **Passive by default.** :meth:`SweepRunner.plan` and
   :meth:`SweepRunner.run` never touch the network. Cloning a listed
   repo URL is an explicit opt-in (``allow_network=True``) and even
   then is only ``git clone --depth 1`` of the exact listed URL — no
   crawling, no probing, no parameter mining. Contract addresses are
   resolved only through the opt-in
   :class:`~web3guard.discovery.deployer_watch.ChainClient`.

The default target list is a small **template** the user edits; every
entry is commented out and clearly marked as an example.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from web3guard.discovery.base import safe_run_subprocess
from web3guard.discovery.deployer_watch import ChainClient, NoopChainClient
from web3guard.discovery.targeting_state import open_targeting_state
from web3guard.state import StateStore

LOGGER = logging.getLogger("web3guard.discovery.sweep")

AUDIT_FILE = "sweep_audit.jsonl"
DEFAULT_MIN_INTERVAL_SECONDS = 2.0
DEFAULT_MAX_TARGETS_PER_RUN = 25

# Refused even when explicitly listed — SSRF / self-scan protection,
# mirroring webrecon's deny-list.
_DENIED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "169.254.169.254",
}


class SweepScopeError(RuntimeError):
    """A target was refused by the ROE gate (deny-list or not listed)."""


def _host_denied(host: str) -> bool:
    host = (host or "").lower().split(":")[0].strip("[]")
    if not host:
        return True
    if host in _DENIED_HOSTNAMES:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_private


def _check_url_host(url: str, target_name: str) -> None:
    """Refuse deny-listed hosts in a repo URL, even when listed."""
    try:
        host = urllib.parse.urlparse(url).hostname or ""
    except ValueError:
        host = ""
    if _host_denied(host):
        raise SweepScopeError(
            f"target {target_name!r}: host {host!r} is deny-listed "
            "(localhost / loopback / link-local / metadata are never "
            "contacted, even when listed)"
        )


@dataclass
class SweepTarget:
    """One sweep target, exactly as listed in the user's config file."""
    name: str
    repo_url: str = ""
    contract_address: str = ""
    chain: str = ""
    notes: str = ""

    def kind(self) -> str:
        if self.repo_url:
            return "repo"
        if self.contract_address:
            return "contract"
        return "unknown"


@dataclass
class SweepJob:
    """An executable unit of sweep work for one target."""
    target: SweepTarget
    kind: str
    local_path: Path | None = None   # clone dir, when allow_network cloned it
    status: str = "pending"          # pending | done | failed | skipped
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.name,
            "kind": self.kind,
            "status": self.status,
            "detail": self.detail,
            "local_path": str(self.local_path) if self.local_path else "",
        }


@dataclass
class SweepConfig:
    targets: list[SweepTarget] = field(default_factory=list)
    min_interval_seconds: float = DEFAULT_MIN_INTERVAL_SECONDS
    max_targets_per_run: int = DEFAULT_MAX_TARGETS_PER_RUN

    @classmethod
    def from_yaml(cls, path: Path) -> SweepConfig:
        import yaml

        if not path.exists():
            LOGGER.info("no sweep config at %s; nothing to sweep", path)
            return cls()
        data = yaml.safe_load(path.read_text()) or {}
        targets = [
            SweepTarget(
                name=str(t.get("name", "")),
                repo_url=str(t.get("repo_url", "") or ""),
                contract_address=str(t.get("contract_address", "") or ""),
                chain=str(t.get("chain", "") or ""),
                notes=str(t.get("notes", "") or ""),
            )
            for t in (data.get("targets") or [])
        ]
        return cls(
            targets=targets,
            min_interval_seconds=float(
                data.get("min_interval_seconds", DEFAULT_MIN_INTERVAL_SECONDS)),
            max_targets_per_run=int(
                data.get("max_targets_per_run", DEFAULT_MAX_TARGETS_PER_RUN)),
        )

    @classmethod
    def example_yaml(cls) -> str:
        return (
            "# Web3Guard long-tail sweep config (TEMPLATE — edit me).\n"
            "#\n"
            "# Every target listed here is YOUR assertion that you are\n"
            "# authorized to assess it (same role as webrecon's auth file).\n"
            "# Nothing is swept unless you list it. Clone locally first\n"
            "# when you can; network cloning is opt-in and deny-listed\n"
            "# hosts (localhost, metadata endpoints) are always refused.\n"
            "targets:\n"
            "  # --- EXAMPLE entries: replace with your own, then uncomment ---\n"
            "  # - name: \"example-fork\"\n"
            "  #   repo_url: \"https://github.com/example/some-fork\"\n"
            "  #   chain: \"ethereum\"\n"
            "  #   notes: \"unaudited Uniswap v4 fork, $2m TVL\"\n"
            "  # - name: \"example-deployment\"\n"
            "  #   contract_address: \"0xDeployedContractAddressHere\"\n"
            "  #   chain: \"base\"\n"
            "min_interval_seconds: 2.0\n"
            "max_targets_per_run: 25\n"
        )


class SweepAudit:
    """Append-only JSONL audit trail for a sweep session."""

    def __init__(self, workdir: Path, config_fingerprint: str) -> None:
        self.path = workdir / AUDIT_FILE
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8")
        self.record("session_start", config_fingerprint=config_fingerprint)

    def record(self, event: str, **fields: Any) -> None:
        line = {"ts": time.time(), "event": event, **fields}
        self._fh.write(json.dumps(line, default=str) + "\n")
        self._fh.flush()

    def close(self) -> None:
        try:
            self.record("session_end")
        finally:
            self._fh.close()


def _config_fingerprint(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    except OSError:
        return "no-config"


class SweepRunner:
    """Rate-limited, resumable sweep over the configured target list.

    ``plan()`` is pure and passive: it validates the config against
    the ROE gate, applies the deny-list, skips already-completed
    targets (resume), and returns the jobs for this run — no network.
    ``run()`` executes the plan; per-target work is local only unless
    ``allow_network=True``, which permits ``git clone --depth 1`` of
    the exact listed repo URL and nothing else.
    """

    def __init__(
        self,
        config: SweepConfig,
        *,
        config_path: Path | None = None,
        state: StateStore | None = None,
        workdir: Path = Path("."),
        client: ChainClient | None = None,
        allow_network: bool = False,
        clone_dir: Path | None = None,
    ) -> None:
        self.config = config
        self.config_path = config_path
        self.state = state or open_targeting_state(workdir)
        self.workdir = workdir
        self.client = client or NoopChainClient()
        self.allow_network = allow_network
        self.clone_dir = clone_dir or (workdir / ".web3guard" / "sweep_clones")
        self._last_target_ts = 0.0

    # -- planning (passive, no network) ------------------------------------

    def plan(self) -> list[SweepJob]:
        """Build this run's job list: ROE gate + deny-list + resume."""
        jobs: list[SweepJob] = []
        for target in self.config.targets:
            if len(jobs) >= self.config.max_targets_per_run:
                LOGGER.info("sweep: per-run budget reached (%d targets)",
                            self.config.max_targets_per_run)
                break
            if not target.name:
                continue
            status = self.state.get(self._status_key(target.name), "pending")
            if status == "done":
                continue  # resume: already swept
            kind = target.kind()
            if kind == "unknown":
                jobs.append(SweepJob(target, kind, status="skipped",
                                     detail="no repo_url or contract_address"))
                continue
            if kind == "repo":
                # Deny-list is checked at plan time, even for local-only
                # runs: a listed-but-denied host must fail loudly, not
                # silently pass.
                _check_url_host(target.repo_url, target.name)
            jobs.append(SweepJob(target, kind))
        return jobs

    def run(self) -> list[SweepJob]:
        """Execute the plan with politeness pacing; persist progress."""
        audit = SweepAudit(
            self.workdir,
            _config_fingerprint(self.config_path) if self.config_path else "no-config",
        )
        jobs = self.plan()
        audit.record("plan_ready", jobs=[j.to_dict() for j in jobs],
                     allow_network=self.allow_network)
        try:
            for job in jobs:
                self._polite_wait()
                try:
                    self._execute(job, audit)
                except SweepScopeError as e:
                    job.status, job.detail = "skipped", str(e)
                    audit.record("target_refused", **job.to_dict())
                except Exception as e:  # noqa: BLE001 - per-target isolation
                    job.status, job.detail = "failed", f"{type(e).__name__}: {e}"
                    audit.record("target_failed", **job.to_dict())
                self.state.set(self._status_key(job.target.name), job.status)
                audit.record("target_done", **job.to_dict())
        finally:
            audit.close()
        return jobs

    def reset(self, name: str | None = None) -> None:
        """Clear persisted progress (one target, or all when name is None)."""
        if name is None:
            for target in self.config.targets:
                self.state.delete(self._status_key(target.name))
        else:
            self.state.delete(self._status_key(name))

    # -- internals -----------------------------------------------------------

    def _status_key(self, name: str) -> str:
        return f"sweep:status:{name}"

    def _polite_wait(self) -> None:
        wait = (self.config.min_interval_seconds
                - (time.monotonic() - self._last_target_ts))
        if wait > 0:
            time.sleep(wait)
        self._last_target_ts = time.monotonic()

    def _execute(self, job: SweepJob, audit: SweepAudit) -> None:
        target = job.target
        if job.kind == "repo":
            _check_url_host(target.repo_url, target.name)  # re-check at exec
            if not self.allow_network:
                job.status = "done"
                job.detail = ("planned (no network): clone the repo locally "
                              "or re-run with allow_network=True")
                return
            dest = self.clone_dir / target.name
            if dest.exists():
                job.local_path = dest
                job.status = "done"
                job.detail = "already cloned"
                return
            self.clone_dir.mkdir(parents=True, exist_ok=True)
            rc, _out, err = safe_run_subprocess(
                ["git", "clone", "--depth", "1", target.repo_url, str(dest)],
                cwd=self.workdir, timeout=600,
            )
            if rc != 0:
                raise RuntimeError(f"git clone failed: {err.strip()[:300]}")
            job.local_path = dest
            job.status = "done"
            job.detail = f"cloned to {dest}"
        elif job.kind == "contract":
            # Contract targets resolve through the opt-in chain client
            # only; with the default NoopChainClient this is a no-op
            # plan entry the scanner can pick up later.
            job.status = "done"
            job.detail = (f"contract target registered "
                          f"(chain client: {self.client.chain_label()})")
        else:
            job.status = "skipped"
            job.detail = "unknown target kind"
        audit.record("target_executed", **job.to_dict())

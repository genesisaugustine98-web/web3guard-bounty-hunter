"""Tests for the v3.4 upgrade pass.

Covers:
- F1 fix: timeout kills the child's process group, never the caller's
- F2 fix: link members refused during archive extraction
- F3 fix: deploy verification uses runtime (deployedBytecode) bytecode
  and binds artifacts to the verified address
- F4 fix: sandbox:/security: config keys actually shape policy
- graceful cost-ceiling abort (partial results kept)
- dual feed (raw_findings.json + ai_drafted_feed.md)
- verification ensemble verdict application
- bounty discovery + scope allowlist (legal ecosystem-scale scanning)
- CLI: --targets-file batch mode, --parallel, bounties/scope commands
- serve hardening: token auth, body cap, scan semaphore
- resilience helpers
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# ---------------------------------------------------------------------------
# F1: timeout kill targets the child's process group, not the caller's
# ---------------------------------------------------------------------------


def _spawn_sleeper(seconds: int = 30) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-c", f"import time; time.sleep({seconds})"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)


def test_kill_process_tree_kills_child_group_not_caller():
    from web3guard.security.sandbox_guard import _kill_process_tree

    child = _spawn_sleeper()
    try:
        time.sleep(0.3)
        assert child.poll() is None
        _kill_process_tree(child)   # must NOT raise or kill us
        rc = child.wait(timeout=10)
        assert rc != 0              # killed
        assert os.getpgrp() == os.getpgid(0)  # caller's group untouched
    finally:
        if child.poll() is None:
            child.kill()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX only")
def test_run_sandboxed_timeout_survives_and_returns_124(tmp_path):
    """End-to-end: a real timed-out subprocess must return 124 with the
    caller alive — the exact scenario that used to kill the scanner."""
    from web3guard.security.sandbox_guard import run_sandboxed

    start = time.monotonic()
    rc, out, err = run_sandboxed(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        cwd=tmp_path, timeout=2)
    elapsed = time.monotonic() - start
    assert rc == 124
    assert "timed out" in err
    assert elapsed < 15  # returned promptly instead of hanging forever


def test_sandbox_policy_from_config_maps_documented_keys():
    from web3guard.security.sandbox_guard import SandboxPolicy

    policy = SandboxPolicy.from_config({
        "sandbox": {
            "max_cpu_seconds": 30,
            "max_address_space_bytes": 1073741824,
            "max_processes": 64,
            "max_revert_reason_bytes": 512,
            "force_tempdir": False,
            "drop_privileges_to_uid": 1000,
        }
    })
    assert policy.max_cpu_seconds == 30
    assert policy.max_address_space_bytes == 1073741824
    assert policy.max_processes == 64
    assert policy.max_revert_reason_bytes == 512
    assert policy.force_tempdir is False
    assert policy.drop_privileges_to_uid == 1000
    # invalid values fall back to defaults, never crash
    bad = SandboxPolicy.from_config({"sandbox": {"max_cpu_seconds": "lots"}})
    assert bad.max_cpu_seconds == SandboxPolicy().max_cpu_seconds


def test_sandbox_policy_security_sandbox_env_lists_apply():
    from web3guard.security.sandbox_guard import SandboxPolicy

    policy = SandboxPolicy.from_config({
        "security": {"sandbox": {"env_allowlist": ["PATH", "MY_CUSTOM_VAR"]}}
    })
    assert "MY_CUSTOM_VAR" in policy.env_allowlist
    assert "HOME" not in policy.env_allowlist  # replaced, not merged


def test_scanner_builds_guard_from_config(tmp_path):
    from web3guard.scanner import Scanner
    from web3guard.security.sandbox_guard import SandboxGuard

    with tempfile.TemporaryDirectory() as td:
        s = Scanner(config={
            "ai_providers": [{
                "type": "openai-compatible", "name": "fake",
                "base_url": "http://127.0.0.1:9/v1",
                "api_key_env": "NO_SUCH_KEY_XYZ", "rpm": 1000,
            }],
            "sandbox": {"max_cpu_seconds": 42},
        }, workdir=Path(td))
        assert isinstance(s.sandbox_guard, SandboxGuard)
        assert s.sandbox_guard.policy.max_cpu_seconds == 42


# ---------------------------------------------------------------------------
# F2: archive link members are refused
# ---------------------------------------------------------------------------


def _tar_with_symlink(dir: Path) -> Path:
    evil = dir / "evil.tar"
    with tarfile.open(evil, "w") as tf:
        link = tarfile.TarInfo("sub")
        link.type = tarfile.SYMTYPE
        link.linkname = str(dir / "esc")
        tf.addfile(link)
        data = b"symlink-traversal-proof"
        f = tarfile.TarInfo("sub/payload.txt")
        f.size = len(data)
        tf.addfile(f, io.BytesIO(data))
    return evil


def test_tar_symlink_member_refused(tmp_path):
    from web3guard.utils.fetch import FetchError, _extract_archive

    esc = tmp_path / "esc"
    esc.mkdir()
    dest = tmp_path / "out"
    dest.mkdir()
    evil = _tar_with_symlink(tmp_path)
    with pytest.raises(FetchError, match="link member"):
        _extract_archive(evil, dest)
    assert not (esc / "payload.txt").exists()  # the previously-exploitable write


def test_tar_hardlink_member_refused(tmp_path):
    from web3guard.utils.fetch import FetchError, _extract_archive

    target_file = tmp_path / "outside.txt"
    target_file.write_text("sensitive")
    evil = tmp_path / "hard.tar"
    with tarfile.open(evil, "w") as tf:
        link = tarfile.TarInfo("etc_passwd_like")
        link.type = tarfile.LNKTYPE
        link.linkname = str(target_file)
        tf.addfile(link)
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(FetchError, match="link member"):
        _extract_archive(evil, dest)


def test_tar_traversal_and_absolute_still_refused(tmp_path):
    from web3guard.utils.fetch import FetchError, _extract_archive

    dest = tmp_path / "out"
    dest.mkdir()
    evil = tmp_path / "trav.tar"
    with tarfile.open(evil, "w") as tf:
        data = b"x"
        info = tarfile.TarInfo("../../escaped.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    with pytest.raises(FetchError):
        _extract_archive(evil, dest)

    evil2 = tmp_path / "abs.tar"
    with tarfile.open(evil2, "w") as tf:
        data = b"x"
        info = tarfile.TarInfo("/tmp/absolute_escape.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    with pytest.raises(FetchError):
        _extract_archive(evil2, dest)


def test_normal_tar_still_extracts(tmp_path):
    from web3guard.utils.fetch import _extract_archive

    evil = tmp_path / "good.tar"
    with tarfile.open(evil, "w") as tf:
        data = b"contract A {}"
        info = tarfile.TarInfo("src/A.sol")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    dest = tmp_path / "out"
    out = _extract_archive(evil, dest)
    # Single-dir payloads are collapsed to that dir by the resolver.
    assert (out / "A.sol").read_bytes() == b"contract A {}"


# ---------------------------------------------------------------------------
# F3: deploy verification compares runtime bytecode, bound to the address
# ---------------------------------------------------------------------------


def _write_broadcast(tmp_path: Path, name: str, address: str) -> None:
    bc = tmp_path / "broadcast" / "Deploy.s.sol" / "31337"
    bc.mkdir(parents=True)
    (bc / "run.json").write_text(json.dumps({"transactions": [
        {"contractName": name, "contractAddress": address,
         "transactionType": "CREATE"},
    ]}))


def test_deploy_verify_prefers_deployed_bytecode(tmp_path):
    from web3guard.utils.deploy_verify import verify_target

    addr = "0x" + "ab" * 20
    _write_broadcast(tmp_path, "Token", addr)
    runtime = "6080" + "ab" * 40
    out = tmp_path / "out" / "Token.sol"
    out.mkdir(parents=True)
    # creation code (with constructor prefix) + deployedBytecode (runtime)
    (out / "Token.json").write_text(json.dumps({
        "bytecode": {"object": "6023" + runtime + "a264" + "ee" * 6},
        "deployedBytecode": {"object": runtime + "a264" + "ee" * 6},
    }))
    deployed = "0x" + runtime + "a264" + "ff" * 6
    with mock.patch("web3guard.utils.deploy_verify.get_code",
                    return_value=deployed):
        r = verify_target(tmp_path, addr, {})
    assert r.verdict == "match"  # runtime-to-runtime: was 'divergent' before


def test_deploy_verify_binds_artifact_to_address(tmp_path):
    from web3guard.utils.deploy_verify import verify_target

    addr = "0x" + "cd" * 20
    _write_broadcast(tmp_path, "Vault", addr)
    other = tmp_path / "out" / "Other.sol"
    other.mkdir(parents=True)
    (other / "Other.json").write_text(json.dumps({
        "deployedBytecode": {"object": "6080" + "ff" * 60},
    }))
    with mock.patch("web3guard.utils.deploy_verify.get_code",
                    return_value="0x" + "12" * 40):
        r = verify_target(tmp_path, addr, {})
    assert r.verdict == "unknown"   # unrelated artifact must not count
    assert "no compiled runtime" in r.detail


def test_deploy_verify_creation_only_artifact_is_unknown(tmp_path):
    """An artifact with only creation bytecode must NOT classify as
    divergent (the old misclassification) — there is no runtime evidence."""
    from web3guard.utils.deploy_verify import verify_target

    addr = "0x" + "ab" * 20
    out = tmp_path / "out" / "A.sol"
    out.mkdir(parents=True)
    (out / "A.json").write_text(json.dumps({
        "bytecode": {"object": "6023" + "6080" + "ab" * 40},
    }))  # no deployedBytecode field
    with mock.patch("web3guard.utils.deploy_verify.get_code",
                    return_value="0x" + "6080" + "ab" * 40):
        r = verify_target(tmp_path, addr, {})
    assert r.verdict == "unknown"


# ---------------------------------------------------------------------------
# Graceful cost-ceiling abort
# ---------------------------------------------------------------------------


def test_cost_ceiling_raises_typed_error():
    from web3guard.ai.cost import CostCeilingExceeded, CostTracker

    tracker = CostTracker(max_cost_usd=0.001)
    with pytest.raises(CostCeilingExceeded):
        tracker.record(provider="p", model="gpt-4o",
                       prompt_tokens=200_000, completion_tokens=50_000)


def test_scanner_scan_survives_cost_ceiling(tmp_path):
    """The scan loop keeps prior targets and records the ceiling instead
    of crashing the run."""
    from web3guard.ai.cost import CostCeilingExceeded
    from web3guard.scanner import Scanner

    with tempfile.TemporaryDirectory() as td:
        s = Scanner.__new__(Scanner)
        s.config = {}
        s.workdir = Path(td)
        s.findings_db = mock.Mock()

        calls = {"n": 0}

        def fake_scan_one(url, budget, *, min_severity):
            calls["n"] += 1
            if calls["n"] == 2:
                raise CostCeilingExceeded("ceiling")
            tr = mock.Mock()
            tr.findings = []
            tr.metadata = {}
            return tr

        s._parse_targets = lambda targets: [(t, 1000) for t in targets]
        s._scan_one = fake_scan_one
        s._scan_dependencies = lambda *a, **k: []
        result_cost = {"total_cost_usd": 0.0, "calls": 0}
        s.ai_client = mock.Mock()
        s.ai_client.cost_tracker.return_value.summary.return_value = result_cost
        s._sanitize_config = lambda: {}

        real = s.scan(["t1", "t2", "t3"])
        assert calls["n"] == 2                # loop stopped at the ceiling...
        assert len(real.targets) == 2         # ...but kept what it had
        assert "cost_ceiling" in real.metadata


# ---------------------------------------------------------------------------
# Dual feed
# ---------------------------------------------------------------------------


def _mk_finding(**kw):
    from web3guard.scanner import Finding
    defaults = dict(
        target="t", language="solidity", file="src/A.sol", function="f",
        category="reentrancy", severity="HIGH", confidence=0.7,
        status="CONFIRMED EXPLOIT", poc_code="// poc", exploit_log="passed!",
        fingerprint="a" * 32,
    )
    defaults.update(kw)
    return Finding(**defaults)


def test_dual_feed_writes_both_files(tmp_path):
    from web3guard.reports.dual_feed import DRAFT_FILENAME, RAW_FILENAME, write_dual_feed
    from web3guard.scanner import ScanResult, TargetResult

    tr = TargetResult(target="t", language=mock.Mock())
    tr.findings = [_mk_finding()]
    result = ScanResult(started_at="s", finished_at="e", config={})
    result.targets = [tr]
    result.cost_summary = {"total_cost_usd": 0.5, "calls": 3}
    write_dual_feed(result, tmp_path)
    raw = json.loads((tmp_path / RAW_FILENAME).read_text())
    assert raw["counts"]["findings"] == 1
    assert raw["counts"]["confirmed"] == 1
    assert raw["findings"][0]["suggested_route"] == "submit-after-manual-verification"
    draft = (tmp_path / DRAFT_FILENAME).read_text()
    assert "reentrancy" in draft and "Proof of concept" in draft


def test_dual_feed_route_gates_unconfirmed(tmp_path):
    from web3guard.reports.dual_feed import build_raw_feed

    class R:
        targets = []
        metadata = {}
        cost_summary = {}
        started_at = finished_at = ""

    tr = mock.Mock()
    tr.target = "t"
    tr.findings = [_mk_finding(status="POTENTIAL (PoC unconfirmed: x)")]
    result = mock.Mock()
    result.targets = [tr]
    result.metadata = {}
    result.cost_summary = {}
    result.started_at = result.finished_at = ""
    raw = build_raw_feed(result)
    assert raw["findings"][0]["suggested_route"] == "internal-review"


def test_scanner_build_report_includes_dual_feed(tmp_path):
    from dataclasses import dataclass, field

    from web3guard.scanner import Scanner

    @dataclass
    class _EmptyResult:
        started_at: str = ""
        finished_at: str = ""
        config: dict = field(default_factory=dict)
        targets: list = field(default_factory=list)
        metadata: dict = field(default_factory=dict)
        cost_summary: dict = field(default_factory=dict)

        @property
        def all_findings(self) -> list:
            return [f for t in self.targets for f in t.findings]

    with tempfile.TemporaryDirectory() as td:
        s = Scanner.__new__(Scanner)
        s.config = {}
        s.workdir = Path(td)
        s.findings_db = mock.Mock()
        result = _EmptyResult()
        written = s.build_report(result, formats=["txt"], out_dir=Path(td))
        assert "raw" in written and "draft" in written


# ---------------------------------------------------------------------------
# Verification ensemble
# ---------------------------------------------------------------------------


class _EnsembleProvider:
    name = "fake"

    def __init__(self, content: str) -> None:
        self.content = content
        self.roles = []

    def chat(self, system, user, *, max_tokens=0, temperature=0.0, role="analysis",
             response_format=None, seed=None):
        self.roles.append(role)
        return mock.Mock(content=self.content, model="m2")


def test_ensemble_overturn_rejects_finding():
    from web3guard.ai.verification import VerificationEnsemble

    provider = _EnsembleProvider(json.dumps({
        "verdict": "overturn", "confidence": 0.9,
        "reasoning": "the function is behind onlyOwner",
        "mitigating_controls": ["onlyOwner"],
    }))
    client = mock.Mock()
    client.chat = lambda *a, **k: provider.chat(*a, **k)
    f = _mk_finding(status="POTENTIAL", confidence=0.6)
    ens = VerificationEnsemble(client)
    ens.apply([f], lambda _f: "contract A {}")
    assert f.status == "REJECTED"
    assert f.metadata["verification_ensemble"]["verdict"] == "overturn"


def test_ensemble_uphold_and_downgrade():
    from web3guard.ai.verification import VerificationEnsemble

    f_up = _mk_finding(status="POTENTIAL", confidence=0.5)
    f_dn = _mk_finding(status="POTENTIAL", confidence=0.8, category="oracle")

    class _Route(_EnsembleProvider):
        def chat(self, system, user, **kw):
            if "oracle" in user:
                self.content = json.dumps({
                    "verdict": "downgrade", "confidence": 0.7,
                    "reasoning": "heartbeat staleness check limits impact",
                })
            else:
                self.content = json.dumps({
                    "verdict": "uphold", "confidence": 0.9,
                    "reasoning": "confirmed", "corrected_severity": "CRITICAL",
                })
            return mock.Mock(content=self.content, model="m2")

    client = mock.Mock()
    provider = _Route("x")
    client.chat = lambda *a, **k: provider.chat(*a, **k)
    ens = VerificationEnsemble(client)
    ens.apply([f_up, f_dn], lambda _f: "code")
    assert f_up.severity == "CRITICAL" and f_up.confidence > 0.5
    assert f_dn.confidence < 0.8
    assert f_dn.metadata["manual_review_required"] is True


def test_ensemble_skips_runtime_confirmed():
    from web3guard.ai.verification import VerificationEnsemble

    client = mock.Mock()
    called = {"n": 0}

    def _chat(*a, **k):
        called["n"] += 1
        return mock.Mock(content="{}", model="m")

    client.chat = _chat
    f = _mk_finding(status="CONFIRMED EXPLOIT")
    ens = VerificationEnsemble(client)
    ens.apply([f], lambda _f: "code")
    assert called["n"] == 0   # PoC evidence beats a second opinion


# ---------------------------------------------------------------------------
# Bounty discovery + scope allowlist
# ---------------------------------------------------------------------------


def test_scope_allowlist_positive_match():
    from web3guard.utils.bounty import ScopeAllowlist, ScopeDenied

    wl = ScopeAllowlist(["github.com/acme", "acme.fi", "0x" + "ab" * 20],
                        require_authorized_scope=True)
    assert wl.is_authorized("https://github.com/acme/vault")
    assert wl.is_authorized("https://api.acme.fi/thing")
    assert wl.is_authorized("0x" + "AB" * 20)
    with pytest.raises(ScopeDenied):
        wl.require("https://github.com/someone-else/repo")


def test_scope_disabled_allows_everything():
    from web3guard.utils.bounty import ScopeAllowlist

    wl = ScopeAllowlist([], require_authorized_scope=False)
    assert wl.is_authorized("anything/anywhere")


def test_scanner_scope_gate_blocks_and_records(tmp_path):
    """With require_authorized_scope on, a denied target is never fetched."""
    from web3guard.scanner import Scanner

    with tempfile.TemporaryDirectory() as td:
        s = Scanner.__new__(Scanner)
        s.config = {
            "require_authorized_scope": True,
            "allow": ["github.com/acme"],
        }
        s.workdir = Path(td)
        result_cost = {"total_cost_usd": 0.0, "calls": 0}
        s.ai_client = mock.Mock()
        s.ai_client.cost_tracker.return_value.summary.return_value = result_cost
        s._parse_targets = lambda targets: [(t, 1000) for t in targets]
        s._scan_one = mock.Mock(side_effect=AssertionError("must not be called"))

        real = s.scan(["https://github.com/attacker/repo"])
        assert len(real.targets) == 1
        assert real.targets[0].metadata["scope_denied"] is True
        s._scan_one.assert_not_called()


def test_bounties_discovery_shape(tmp_path):
    from web3guard.utils.bounty import ScopeAllowlist

    wl = ScopeAllowlist([], require_authorized_scope=False,
                        cache_dir=tmp_path)
    progs = wl.programs()          # static list; live fetch is best-effort
    assert isinstance(progs, list)
    cards = wl.discover_bounties()
    assert isinstance(cards, list) and cards
    assert {"name", "url", "max_bounty_usd"} <= set(cards[0].keys())


# ---------------------------------------------------------------------------
# CLI batch/parallel + bounties/scope
# ---------------------------------------------------------------------------


def test_targets_file_merging(tmp_path, capsys):
    """--targets-file lines join positional targets (smoke through the parser)."""
    from web3guard.cli import build_parser

    tf = tmp_path / "targets.txt"
    tf.write_text("# comment\nhttps://github.com/a/b|1000\n")
    parser = build_parser()
    args = parser.parse_args([
        "scan", "local1|500", "--targets-file", str(tf), "--parallel", "2"])
    assert args.parallel == 2
    assert args.targets_file == tf


def test_bounties_command_smoke(tmp_path, capsys):
    from web3guard.cli import _cmd_bounties

    args = mock.Mock(workdir=tmp_path, min_reward=0.0, as_json=True,
                     refresh=False)
    assert _cmd_bounties(args) == 0
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, list)


def test_scope_command_authorized_vs_denied(tmp_path, capsys):
    from web3guard.cli import _cmd_scope

    cfg = tmp_path / "config.yaml"
    cfg.write_text("require_authorized_scope: true\nallow:\n  - github.com/acme\n")
    args_ok = mock.Mock(target="https://github.com/acme/repo", config=cfg,
                        workdir=tmp_path)
    assert _cmd_scope(args_ok) == 0
    args_bad = mock.Mock(target="https://github.com/evil/repo", config=cfg,
                         workdir=tmp_path)
    assert _cmd_scope(args_bad) == 1


# ---------------------------------------------------------------------------
# Serve hardening
# ---------------------------------------------------------------------------


def _start_server(workdir: Path, port: int, token: str | None):
    from web3guard.cli import _cmd_serve

    args = mock.Mock(workdir=workdir, host="127.0.0.1", port=port,
                     token=token)
    t = threading.Thread(target=_cmd_serve, args=(args,), daemon=True)
    t.start()
    time.sleep(0.4)
    return t


def test_serve_token_blocks_unauthenticated_post(tmp_path):
    import urllib.error
    import urllib.request

    with tempfile.TemporaryDirectory() as td:
        port = 18411
        _start_server(Path(td), port, token="s3cret")
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/mark",
            data=json.dumps({"fingerprint": "x", "status": "new"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                raise AssertionError(f"expected 401, got {r.status}")
        except urllib.error.HTTPError as e:
            assert e.code == 401


def test_serve_token_allows_authorized_post(tmp_path):
    import urllib.request

    from web3guard.findings_db import FindingRecord, FindingsDB

    with tempfile.TemporaryDirectory() as td:
        port = 18412
        db = FindingsDB(Path(td) / ".web3guard" / "findings.db")
        rec = FindingRecord(fingerprint="f" * 32, target="t",
                            language="solidity", file="a.sol")
        db.upsert(rec)
        _start_server(Path(td), port, token="s3cret")
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/mark",
            data=json.dumps({"fingerprint": "f" * 32, "status": "new"}).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": "Bearer s3cret"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            assert json.loads(r.read())["ok"] is True


# ---------------------------------------------------------------------------
# Resilience helpers
# ---------------------------------------------------------------------------


def test_resilience_classification():
    from web3guard.utils.resilience import classify_error, disk_preflight

    assert classify_error(RuntimeError("connection timed out")) == "retry"
    assert classify_error(RuntimeError("cost ceiling exceeded: $1 > $0.5")) == "abort"
    assert disk_preflight(Path("/tmp"))


def test_resilience_low_disk_raises():
    from web3guard.utils.resilience import disk_ok_or_raise

    with pytest.raises(RuntimeError, match="low disk"):
        disk_ok_or_raise(Path("/tmp"), floor=(1 << 60))  # absurd floor


# ---------------------------------------------------------------------------
# v3.4 fixup regressions (stitch pass)
# ---------------------------------------------------------------------------


def test_scanjob_metadata_path_resolves_severity_bucket(tmp_path):
    """The sev: inline-keyboard callback calls ScanJob.metadata_path;
    before the fixup it did not exist and crashed delivery."""
    from web3guard.telegram_bot import ScanJob

    job = ScanJob(chat_id=1, target="t", budget=1, discovery_only=False)
    assert job.metadata_path("HIGH") is None  # no report yet -> no crash

    report = tmp_path / "WEB3GUARD_FINDINGS.json"
    report.write_text(json.dumps({"targets": [{"findings": [
        {"severity": "HIGH", "category": "reentrancy"}]}
    ]}), encoding="utf-8")
    job.report_dir = tmp_path
    assert job.metadata_path("CRITICAL") is None   # nothing >= CRITICAL
    assert job.metadata_path("HIGH") == report     # exact bucket
    assert job.metadata_path("LOW") == report      # LOW bucket includes HIGH
    assert job.metadata_path("bogus") == report    # unknown -> floor INFO


def test_scope_cmd_handles_bounty_program_dataclasses(tmp_path, capsys):
    """_cmd_scope printed program dicts but routes_for returns
    BountyProgram dataclasses — attribute access required."""
    from unittest import mock as _mock

    from web3guard.cli import _cmd_scope
    from web3guard.utils.bounty import BountyProgram, ScopeAllowlist

    cfg = {"require_authorized_scope": True, "allow": ["acme.fi"]}
    fake_program = BountyProgram(
        name="Immunefi:acme", url="https://immunefi.com/bug-bounty/acme",
        max_bounty_usd=1000.0, asset_types=("blockchain",),
        domains=("acme.fi",))
    args = _mock.Mock(target="https://api.acme.fi/x", config=None,
                      workdir=tmp_path)
    with _mock.patch("web3guard.cli.load_config", return_value=dict(cfg)), \
            _mock.patch.object(ScopeAllowlist, "programs",
                               return_value=[fake_program]):
        assert _cmd_scope(args) == 0
    out = capsys.readouterr().out
    assert "AUTHORIZED" in out
    assert "Immunefi:acme" in out  # program card rendered via attributes


def test_scanner_disk_floor_aborts_cleanly(tmp_path):
    """Scanner consults the resilience disk floor between targets and
    aborts with partial results kept (metadata['disk_abort']), instead
    of dying with ENOSPC halfway through a batch."""
    from web3guard import scanner as scanner_mod
    from web3guard.scanner import Scanner

    cfg = {
        "ai_providers": [{
            "type": "openai-compatible", "name": "fake",
            "base_url": "http://127.0.0.1:9/v1",
            "api_key_env": "NO_SUCH_KEY_XYZ", "rpm": 1000,
        }],
        "enable_discovery": False, "enable_ai_analysis": False,
        "enable_exploit": False, "enable_self_critique": False,
        "enable_secret_scan": False, "enable_dependency_scan": False,
        "enable_incremental_scan": False,
    }
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "A.sol").write_text(
        "pragma solidity ^0.8.24; contract A { function f() external {} }",
        encoding="utf-8")
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "B.sol").write_text(
        "pragma solidity ^0.8.24; contract B { function f() external {} }",
        encoding="utf-8")
    scanner = Scanner(config=cfg, workdir=tmp_path / "work")

    with mock.patch.object(scanner_mod, "disk_ok_or_raise") as fake_floor:
        # Plenty of disk for the first target, none after it.
        fake_floor.side_effect = [None, RuntimeError("low disk: 0 MiB free")]
        result = scanner.scan([str(tmp_path / "a"), str(tmp_path / "b")])

    # Guard runs before each target: passes for the first, trips on the
    # second — the batch stops with partial results kept.
    assert fake_floor.call_count == 2
    assert "low disk" in str(result.metadata.get("disk_abort", ""))
    assert len(result.targets) == 1              # first target's result kept


def test_cli_parallel_merge_keeps_metadata_and_survives_chunk_failure(tmp_path):
    """The parallel merge dropped per-chunk metadata (cost_ceiling /
    disk_abort) and let one chunk's exception lose the whole batch."""
    from web3guard.cli import _cmd_scan

    cfg: dict = {
        "ai_providers": [{
            "type": "openai-compatible", "name": "fake",
            "base_url": "http://127.0.0.1:9/v1",
            "api_key_env": "NO_SUCH_KEY_XYZ", "rpm": 1000,
        }],
        "enable_discovery": False, "enable_ai_analysis": False,
        "enable_exploit": False, "enable_self_critique": False,
        "enable_secret_scan": False, "enable_dependency_scan": False,
        "enable_incremental_scan": False,
    }
    for name in ("a", "b", "c", "d"):
        d = tmp_path / name
        d.mkdir()
        (d / f"{name.upper()}.sol").write_text(
            f"pragma solidity ^0.8.24; contract {name.upper()} {{ }}",
            encoding="utf-8")

    from web3guard.languages import TargetLanguage
    from web3guard.scanner import Scanner, ScanResult, TargetResult

    def _fake_scan(self, targets, min_severity=None):
        if any(str(t).endswith("b") for t in targets):
            raise RuntimeError("connection reset by peer")
        result = ScanResult(started_at="s", finished_at="e", config={})
        result.targets = [
            TargetResult(target=str(t), language=TargetLanguage.UNKNOWN)
            for t in targets]
        result.metadata = {"cost_ceiling": "fake ceiling"}
        result.cost_summary = {"total_cost_usd": 0.25, "calls": 1}
        return result

    args = mock.Mock(
        targets=[str(tmp_path / p) for p in ("a", "b", "c", "d")],
        targets_file=None, parallel=2, config=None, workdir=tmp_path,
        no_exploit=False, no_self_critique=False, discovery_only=False,
        ai_only=False, fork_url=None, seed=None, scan_dependencies=False,
        min_severity="LOW", formats=["json"], out=tmp_path / "reports")
    with mock.patch.object(Scanner, "scan", _fake_scan), \
            mock.patch("web3guard.cli.load_config", return_value=dict(cfg)):
        rc = _cmd_scan(args)

    assert rc == 0
    report = json.loads(
        (tmp_path / "reports" / "WEB3GUARD_FINDINGS.json").read_text())
    # parallel=2 over [a,b,c,d] -> chunks [a,c] and [b,d]; the failing
    # chunk loses its targets, the healthy chunk's results are kept.
    kept = sorted(Path(t["target"]).name for t in report["targets"])
    assert kept == ["a", "c"]
    # merged metadata survives (fixup) + chunk error recorded
    assert report["metadata"].get("cost_ceiling") == "fake ceiling"
    assert any("chunk" in e for e in report["metadata"]["batch_chunk_errors"])

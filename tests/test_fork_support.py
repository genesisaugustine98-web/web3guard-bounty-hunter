"""Tests for on-chain/fork support (Upgrade #3).

`--fork-url` was parsed by the CLI but never wired into the Foundry
sandbox, so PoCs ran against a blank local chain and the economic
analyzer could never surface real on-chain scale. These tests cover:

1. `--fork-url` forwarded to `forge test` when configured.
2. No fork flag when not configured (existing behavior preserved).
3. Scanner threads config `fork_url` through `create_sandbox`.
4. Exploit prompt gets a fork hint when a fork is configured.
5. A confirmed PoC on a fork may emit `vuln_tvl` (log_named_uint),
   which is parsed and fed into the economic analyzer.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest  # noqa: E402

from web3guard.scanner import Finding, Scanner  # noqa: E402
from web3guard.languages.base import TargetLanguage  # noqa: E402


# ---------------------------------------------------------------------------
# FoundrySandbox fork flag
# ---------------------------------------------------------------------------


class _TestRunner:
    name = "foundry"

    @staticmethod
    def has_impact_assertion(code: str) -> bool:
        return True


class _FakeAdapter:
    """Minimal stand-in for a Solidity LanguageAdapter."""

    language = TargetLanguage.SOLIDITY
    test_runner = _TestRunner()

    @staticmethod
    def analysis_system_prompt() -> str:
        return ""

    @staticmethod
    def vulnerability_catalog() -> dict:
        return {}

    @staticmethod
    def exploit_user_template() -> str:
        return (
            "Category: {category}\n"
            "Severity: {severity}\n"
            "Description: {description}\n"
            "Concept: {concept}\n"
            "Context: {context}\n"
            "CODE:\n{code}\n"
            "{fork_hint}\n"
            "{oracle_hint}\n"
        )


class _CaptureRun:
    """Replaces sandbox._run and records the forge test command."""

    def __init__(self):
        self.test_cmd: list[str] | None = None

    def __call__(self, cmd, *, cwd, timeout):
        if cmd and cmd[0] == "forge" and "test" in cmd:
            self.test_cmd = list(cmd)
        return True, "ok", ""


def _sandbox(fork_url=None):
    from web3guard.sandbox.foundry import FoundrySandbox
    return FoundrySandbox(
        adapter=_FakeAdapter(),
        target_path=Path("/tmp/nonexistent"),
        workdir=Path("/tmp"),
        fork_url=fork_url,
    )


def test_fork_url_adds_flag_to_forge_test():
    sb = _sandbox(fork_url="https://eth-mainnet.example.com/v2/abc")
    cap = _CaptureRun()
    sb._run = cap  # type: ignore[assignment]
    sb.run(Path("/tmp/sb"), Path("/tmp/poc.sol"))
    assert cap.test_cmd is not None
    assert "--fork-url" in cap.test_cmd
    assert cap.test_cmd[cap.test_cmd.index("--fork-url") + 1] == (
        "https://eth-mainnet.example.com/v2/abc"
    )


def test_no_fork_flag_when_unset():
    sb = _sandbox(fork_url=None)
    cap = _CaptureRun()
    sb._run = cap  # type: ignore[assignment]
    sb.run(Path("/tmp/sb"), Path("/tmp/poc.sol"))
    assert cap.test_cmd is not None
    assert "--fork-url" not in cap.test_cmd


def test_fork_url_redacted_from_output():
    from web3guard.sandbox.foundry import FoundrySandbox

    key_url = "https://eth-mainnet.g.alchemy.com/v2/supersecretkey"
    sb = FoundrySandbox(
        adapter=_FakeAdapter(), target_path=Path("/tmp/nonexistent"),
        workdir=Path("/tmp"), fork_url=key_url,
    )

    def fake_run(cmd, *, cwd, timeout):
        if cmd and cmd[0] == "forge" and "test" in cmd:
            return True, f"RPC failed: {key_url}\n", ""
        return True, "built ok", ""

    sb._run = fake_run  # type: ignore[assignment]
    result = sb.run(Path("/tmp/sb"), Path("/tmp/poc.sol"))
    assert key_url not in result.output
    assert "<redacted-fork-url>" in result.output


def test_create_sandbox_threads_fork_url():
    from web3guard.sandbox import create_sandbox
    sb = create_sandbox(
        _FakeAdapter(), Path("/tmp/t"), Path("/tmp/w"),
        fork_url="https://rpc.example/v1",
    )
    assert sb.fork_url == "https://rpc.example/v1"


# ---------------------------------------------------------------------------
# Differential fork parity
# ---------------------------------------------------------------------------


_FORK_DIFF_FIXTURE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send fail");
        balances[msg.sender] = 0;
    }
}
"""


def _run_differential_capture(tmp_path, monkeypatch, fork_url):
    from web3guard import sandbox as sandbox_mod
    from web3guard.languages.solidity import SolidityAdapter
    from web3guard.sandbox.differential import run_differential

    created: list[dict] = []

    class _SB:
        def __init__(self, kwargs):
            self.kwargs = kwargs

        def write_and_run(self, code, fingerprint, timeout=90):
            return True, "PASSED"

    def _fake_create(adapter, path, workdir, **kwargs):
        created.append(kwargs)
        return _SB(kwargs)

    monkeypatch.setattr(sandbox_mod, "create_sandbox", _fake_create)

    target = tmp_path / "t"
    target.mkdir()
    (target / "Vault.sol").write_text(_FORK_DIFF_FIXTURE)
    work = tmp_path / "w"
    work.mkdir()
    out = run_differential(
        SolidityAdapter(), target, work, "// poc", "fp", "reentrancy",
        fork_url=fork_url,
    )
    return out, created


def test_run_differential_threads_fork_url(tmp_path, monkeypatch):
    out, created = _run_differential_capture(
        tmp_path, monkeypatch, "https://rpc.example/v1"
    )
    assert len(created) == 2
    assert all(k.get("fork_url") == "https://rpc.example/v1" for k in created)
    assert out.status == "patched-still-passes"


def test_run_differential_omits_fork_url_when_unset(tmp_path, monkeypatch):
    out, created = _run_differential_capture(tmp_path, monkeypatch, None)
    assert len(created) == 2
    assert all(k.get("fork_url") is None for k in created)
    assert out.status == "patched-still-passes"


# ---------------------------------------------------------------------------
# Scanner wiring
# ---------------------------------------------------------------------------


class _CaptureSandbox:
    """Records kwargs passed to create_sandbox and runs a passing PoC."""

    def __init__(self):
        self.kwargs: dict = {}
        self.output = "PASSED\n  vuln_tvl: 5000000\n"

    def write_and_run(self, code, fingerprint, timeout=90):
        return True, self.output


class _FakeChat:
    def __init__(self, responses):
        self._responses = list(responses)
        self.user_messages: list[str] = []

    def chat(self, system, user, **kwargs):
        self.user_messages.append(user)
        return self._responses.pop(0)


def _valid_poc() -> str:
    return (
        "pragma solidity ^0.8.0;\n"
        'import "forge-std/Test.sol";\n'
        "contract ExploitTest is Test {\n"
        "    function test_exploit() public {\n"
        "        uint before = 100;\n"
        "        uint after = 0;\n"
        "        assertEq(after, 0);\n"
        "        assert(after < before);\n"
        "    }\n"
        "}\n"
    )


def test_scanner_passes_fork_url_to_sandbox(tmp_path, monkeypatch):
    from web3guard import sandbox as sandbox_mod
    from web3guard.ai.provider import ChatResponse

    cap = _CaptureSandbox()
    monkeypatch.setattr(sandbox_mod, "create_sandbox",
                        lambda *a, **k: (cap.__setattr__("kwargs", k) or cap))

    cfg = {"enable_ai_analysis": True, "enable_discovery": False,
           "enable_exploit": True, "max_exploit_attempts": 1,
           "fork_url": "https://rpc.example/v1"}
    ai = _FakeChat([ChatResponse(content=_valid_poc(), model="m")])
    scanner = Scanner(config=cfg, workdir=tmp_path, ai_client=ai)
    finding = Finding(target="x", language="solidity", file="Vault.sol")
    scanner._generate_poc(_FakeAdapter(), finding, _chunk(), tmp_path)
    assert cap.kwargs.get("fork_url") == "https://rpc.example/v1"


def test_fork_hint_populated_when_fork_configured(tmp_path):
    from web3guard.ai.provider import ChatResponse

    cfg = {"enable_ai_analysis": True, "enable_discovery": False,
           "enable_exploit": True, "max_exploit_attempts": 1,
           "fork_url": "https://rpc.example/v1"}
    ai = _FakeChat([ChatResponse(content=_valid_poc(), model="m")])
    scanner = Scanner(config=cfg, workdir=tmp_path, ai_client=ai)
    finding = Finding(target="x", language="solidity", file="Vault.sol")
    scanner._generate_poc(_FakeAdapter(), finding, _chunk(), tmp_path)
    assert ai.user_messages
    assert "live chain fork" in ai.user_messages[0]
    assert "vuln_tvl" in ai.user_messages[0]


def test_fork_hint_empty_when_no_fork(tmp_path):
    from web3guard.ai.provider import ChatResponse

    cfg = {"enable_ai_analysis": True, "enable_discovery": False,
           "enable_exploit": True, "max_exploit_attempts": 1}
    ai = _FakeChat([ChatResponse(content=_valid_poc(), model="m")])
    scanner = Scanner(config=cfg, workdir=tmp_path, ai_client=ai)
    finding = Finding(target="x", language="solidity", file="Vault.sol")
    scanner._generate_poc(_FakeAdapter(), finding, _chunk(), tmp_path)
    assert ai.user_messages
    assert "live chain fork" not in ai.user_messages[0]


def test_confirmed_poc_parses_vuln_tvl(tmp_path, monkeypatch):
    from web3guard import sandbox as sandbox_mod
    from web3guard.ai.provider import ChatResponse

    cap = _CaptureSandbox()
    monkeypatch.setattr(sandbox_mod, "create_sandbox", lambda *a, **k: cap)

    cfg = {"enable_ai_analysis": True, "enable_discovery": False,
           "enable_exploit": True, "max_exploit_attempts": 1,
           "fork_url": "https://rpc.example/v1"}
    ai = _FakeChat([ChatResponse(content=_valid_poc(), model="m")])
    scanner = Scanner(config=cfg, workdir=tmp_path, ai_client=ai)
    finding = Finding(target="x", language="solidity", file="Vault.sol")
    scanner._generate_poc(_FakeAdapter(), finding, _chunk(), tmp_path)
    assert finding.status == "CONFIRMED EXPLOIT"
    assert finding.metadata.get("on_chain_tvl") == 5000000


def test_scanner_forwards_fork_url_to_differential(tmp_path, monkeypatch):
    import web3guard.scanner as scanner_mod
    from web3guard import sandbox as sandbox_mod
    from web3guard.ai.provider import ChatResponse

    cap = _CaptureSandbox()
    monkeypatch.setattr(sandbox_mod, "create_sandbox", lambda *a, **k: cap)

    captured: dict = {}

    def _fake_diff(*args, **kwargs):
        captured.update(kwargs)
        return scanner_mod.DifferentialOutcome("confirmed")

    monkeypatch.setattr(scanner_mod, "run_differential", _fake_diff)

    cfg = {"enable_ai_analysis": True, "enable_discovery": False,
           "enable_exploit": True, "max_exploit_attempts": 1,
           "enable_differential": True,
           "fork_url": "https://rpc.example/v1"}
    ai = _FakeChat([ChatResponse(content=_valid_poc(), model="m")])
    scanner = Scanner(config=cfg, workdir=tmp_path, ai_client=ai)
    finding = Finding(target="x", language="solidity", file="Vault.sol")
    scanner._generate_poc(_FakeAdapter(), finding, _chunk(), tmp_path)
    assert captured.get("fork_url") == "https://rpc.example/v1"


def test_economic_analyzer_uses_on_chain_tvl():
    scanner = Scanner(config={"fork_url": "https://rpc.example/v1"},
                      ai_client=object())
    finding = Finding(target="x", language="solidity", file="Vault.sol")
    finding.metadata["on_chain_tvl"] = 7500000
    scanner._economic_analyzer(finding)
    econ = finding.metadata["economic"]
    assert econ.get("on_chain") is True
    assert finding.expected_profit_usd == 7500000


def test_economic_analyzer_offline_without_fork():
    scanner = Scanner(config={}, ai_client=object())
    finding = Finding(target="x", language="solidity", file="Vault.sol",
                      category="reentrancy")
    scanner._economic_analyzer(finding)
    econ = finding.metadata["economic"]
    assert econ.get("on_chain") is not True
    assert finding.expected_profit_usd > 0  # offline order-of-magnitude model


def test_economic_analyzer_fork_configured_without_tvl_is_offline():
    scanner = Scanner(config={"fork_url": "https://rpc.example/v1"},
                      ai_client=object())
    finding = Finding(target="x", language="solidity", file="Vault.sol",
                      category="reentrancy")
    scanner._economic_analyzer(finding)
    econ = finding.metadata["economic"]
    assert econ.get("on_chain") is False
    assert econ.get("fork_configured") is True
    assert finding.expected_profit_usd > 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _Chunk:
    file = "Vault.sol"
    content = "contract Vault { mapping(address=>uint) balances; }"
    context = "(none)"


def _chunk():
    return _Chunk()

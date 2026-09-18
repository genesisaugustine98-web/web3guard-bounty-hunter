# Fork-State Parity in Differential Confirmation (B1.5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make differential confirmation run the vulnerable and patched copies against the same fork state, and stop reporting an offline profit estimate as measured on-chain data.

**Architecture:** `run_differential` gains a `fork_url` parameter and forwards it to both `create_sandbox` calls; the scanner passes `config["fork_url"]` into that call; `_economic_analyzer` only sets `on_chain: True` when a real `vuln_tvl` was captured, otherwise `on_chain: False` plus a `fork_configured` flag.

**Tech Stack:** Python 3.11+, `pytest`, `unittest.mock`/`monkeypatch`; reuses the Foundry fork plumbing already in `FoundrySandbox` and `tests/test_fork_support.py`.

**Spec:** `docs/superpowers/specs/2026-09-18-fork-state-design.md`

## Global Constraints

- Python is `python3` (never `python`).
- Foundry-backed tests need `PATH="$HOME/.foundry/bin:$PATH"`.
- Repo root: `/tmp/opencode/web3guard-bounty-hunter`; always set the shell workdir there.
- TDD: failing test first, then implementation, then green.
- Do not add gratuitous inline comments; match the existing module-docstring style.
- Keep `ffi = false` and `fs_permissions = []` in generated Foundry configs (untouched here).
- Never print or commit secrets; the fork URL is already redacted by `FoundrySandbox.run`.
- Commit identity: `git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" commit -m "..."`.
- Push with `GIT_ASKPASS=/tmp/opencode/git-askpass.sh git -c credential.helper= push origin main`.
- A bad/unreachable RPC must degrade to `vulnerable-failed` (never `confirmed`); no new exceptions.
- All new tests are offline (fakes): no network, no RPC.

---

### Task 1: Thread `fork_url` through `run_differential`

**Files:**
- Modify: `web3guard/sandbox/differential.py:122-145`
- Test: `tests/test_fork_support.py` (append)

**Interfaces:**
- Consumes: `web3guard.sandbox.create_sandbox(adapter, target_path, workdir, policy=None, fork_url=None)`.
- Produces:
  - `run_differential(adapter, target_path, workdir, poc_code, fingerprint, category, fork_url=None) -> DifferentialOutcome`.
  - Both internal `create_sandbox` calls receive `fork_url=fork_url`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_fork_support.py` (after `test_create_sandbox_threads_fork_url`, before the scanner-wiring section):

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_fork_support.py -k "differential_threads or differential_omits" -v`
Expected: FAIL — `TypeError: run_differential() got an unexpected keyword argument 'fork_url'`.

- [ ] **Step 3: Write the minimal implementation**

In `web3guard/sandbox/differential.py`, change the signature (lines 122-129) to add `fork_url`:

```python
def run_differential(
    adapter: Any,
    target_path: Path,
    workdir: Path,
    poc_code: str,
    fingerprint: str,
    category: str,
    fork_url: str | None = None,
) -> DifferentialOutcome:
```

Change the vulnerable sandbox construction (line 132):

```python
    vuln = _sandbox.create_sandbox(adapter, target_path, workdir, fork_url=fork_url)
```

Change the patched sandbox construction (line 142):

```python
    patched = _sandbox.create_sandbox(adapter, patched_dir, workdir, fork_url=fork_url)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_fork_support.py tests/test_differential.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add web3guard/sandbox/differential.py tests/test_fork_support.py
git commit -m "fix(differential): run patched copy on the same fork state"
```

---

### Task 2: Scanner forwards `fork_url` into differential

**Files:**
- Modify: `web3guard/scanner.py:827-831`
- Test: `tests/test_fork_support.py` (append)

**Interfaces:**
- Consumes: `run_differential(..., fork_url=...)` from Task 1.
- Produces: the scanner's differential call carries `fork_url=self.config.get("fork_url")`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_fork_support.py` (after `test_confirmed_poc_parses_vuln_tvl`):

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_fork_support.py::test_scanner_forwards_fork_url_to_differential -v`
Expected: FAIL — `captured` has no `fork_url` key.

- [ ] **Step 3: Write the minimal implementation**

In `web3guard/scanner.py`, in `_generate_poc` (lines 827-831), add the keyword argument:

```python
                if self.config.get("enable_differential", True):
                    outcome: DifferentialOutcome = run_differential(
                        adapter, target_path, self.workdir, code,
                        finding.fingerprint or "exploit", finding.category,
                        fork_url=self.config.get("fork_url"),
                    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_fork_support.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add web3guard/scanner.py tests/test_fork_support.py
git commit -m "fix(scanner): pass fork url into differential confirmation"
```

---

### Task 3: Honest `on_chain` reporting in `_economic_analyzer`

**Files:**
- Modify: `web3guard/scanner.py:1231-1248`
- Test: `tests/test_fork_support.py` (append)

**Interfaces:**
- Consumes: `finding.metadata["on_chain_tvl"]` (set only from a captured `vuln_tvl` log).
- Produces: `metadata["economic"]` always contains `on_chain: bool`; when no `vuln_tvl` exists it also contains `fork_configured: bool`. `on_chain` is `True` only on the `vuln_tvl` path.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_fork_support.py` (after `test_economic_analyzer_offline_without_fork`):

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_fork_support.py::test_economic_analyzer_fork_configured_without_tvl_is_offline -v`
Expected: FAIL — `econ.get("on_chain")` is `True`.

- [ ] **Step 3: Write the minimal implementation**

In `web3guard/scanner.py`, in the per-category model branch (lines 1235-1240), replace the dict with:

```python
            finding.metadata["economic"] = {
                "note": "offline order-of-magnitude estimate; pass "
                        "--fork-url for on-chain TVL data",
                "scope": model["scope"],
                "on_chain": False,
                "fork_configured": fork_configured,
            }
```

In the unknown-category branch (lines 1244-1248), replace the dict with:

```python
        finding.metadata["economic"] = {
            "note": "offline estimate; pass --fork-url for on-chain TVL data",
            "scope": "unknown category; see description",
            "on_chain": False,
            "fork_configured": fork_configured,
        }
```

Leave the `on_chain_tvl is not None` branch unchanged (it keeps `"on_chain": True`, `"source": "fork-poc-log"`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_fork_support.py -q`
Expected: PASS, including the pre-existing `test_economic_analyzer_uses_on_chain_tvl` and `test_economic_analyzer_offline_without_fork`.

- [ ] **Step 5: Commit**

```bash
git add web3guard/scanner.py tests/test_fork_support.py
git commit -m "fix(economics): do not report offline estimates as on-chain"
```

---

### Task 4: Full verification, push, and CI

**Files:**
- Verify only (no source changes expected).

**Interfaces:**
- Consumes: Tasks 1-3.
- Produces: green local suites, a pushed `main`, and a successful CI run.

- [ ] **Step 1: Run the full suite without forge**

Run: `python3 -m pytest -q`
Expected: all pass (the pre-existing skipped count for forge-gated tests).

- [ ] **Step 2: Run the full suite with forge**

Run: `PATH="$HOME/.foundry/bin:$PATH" python3 -m pytest -q`
Expected: all pass, fewer skips than Step 1.

- [ ] **Step 3: Lint the changed files**

Run: `ruff check web3guard/sandbox/differential.py web3guard/scanner.py tests/test_fork_support.py`
Expected: `All checks passed!`

- [ ] **Step 4: Commit any lint fixes (only if Step 3 found issues)**

```bash
git add web3guard/sandbox/differential.py web3guard/scanner.py tests/test_fork_support.py
git commit -m "style(fork): sort imports and annotations"
```

- [ ] **Step 5: Push**

Run: `GIT_ASKPASS=/tmp/opencode/git-askpass.sh git -c credential.helper= push origin main`
Expected: `main -> main`.

- [ ] **Step 6: Poll CI**

Run:
```bash
GH_TOKEN="$(cat /tmp/opencode/gh_pat)" gh run list \
  --repo genesisaugustine98-web/web3guard-bounty-hunter --limit 1
```
Then: `python3 /tmp/opencode/poll_run.py <run_id> 1200`
Expected: `run completed success` for Test (Python 3.11/3.12), Toolchain sandbox smoke, Benchmark, and Devcontainer smoke.

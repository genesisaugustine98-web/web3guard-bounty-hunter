# EVM Finding Realism (Bar 1 Slice) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make EVM findings real — reproduce the target's actual build (remappings/solc/vendored deps), require runtime fund-movement evidence before `CONFIRMED EXPLOIT`, and reject exploits that also "work" against a patched copy of the contract.

**Architecture:** Add a `BuildProfile` detector and a harden-by-merge `foundry.toml` renderer; `FoundrySandbox` consumes the profile so remapped/vendored imports compile. Add `ImpactEvidence` parsed from Foundry `log_named_uint("impact_gain"|"impact_loss", ...)` output and make the scanner require it. Add a differential runner with per-category source mutators so confirmation needs vulnerable-pass **and** patched-fail.

**Tech Stack:** Python 3.11 (`tomllib`), pytest, Foundry (`forge`), the existing `web3guard.languages` / `web3guard.sandbox` seams.

## Global Constraints

- Python 3.11+ only; no new runtime dependencies (use stdlib `tomllib`).
- Every test that needs `forge` must `pytest.skip` when `shutil.which("forge") is None`.
- Sandbox hardening is non-negotiable: generated `foundry.toml` MUST keep `ffi = false` and `fs_permissions = []`. Never reuse the target's permissive values for these.
- Never expose API keys to subprocesses (existing `env.pop(...)` behavior must be preserved).
- Never delete repository files; only add/modify.
- Commit with pinned identity: `git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" commit ...`.
- Run tests with `python3 -m pytest` (the `python` binary is not present).
- The scanner workdir MUST stay a different directory from the target dir (see `tests/test_exploit_e2e_foundry.py`).

---

### Task 1: Build-system detection (`BuildProfile`)

**Files:**
- Create: `web3guard/sandbox/build_system.py`
- Test: `tests/test_build_profile.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `BuildProfile` frozen dataclass with fields `kind: str`, `src_dir: str`, `test_dir: str`, `libs: tuple[str, ...]`, `remappings: tuple[str, ...]`, `solc_version: str | None`, `via_ir: bool | None`.
  - `detect_build_profile(target_path: Path) -> BuildProfile`.

- [ ] **Step 1: Write the failing test**

```python
"""Unit tests for build-system detection."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from web3guard.sandbox.build_system import BuildProfile, detect_build_profile


def test_plain_project(tmp_path: Path) -> None:
    (tmp_path / "Foo.sol").write_text("contract Foo {}")
    p = detect_build_profile(tmp_path)
    assert p.kind == "plain"
    assert p.remappings == ()


def test_foundry_project_reads_remappings_and_solc(tmp_path: Path) -> None:
    (tmp_path / "foundry.toml").write_text(
        '[profile.default]\n'
        'src = "contracts"\n'
        'solc_version = "0.8.20"\n'
        'remappings = ["mylib/=lib/mylib/"]\n'
    )
    (tmp_path / "remappings.txt").write_text("other/=lib/other/\n")
    p = detect_build_profile(tmp_path)
    assert p.kind == "foundry"
    assert p.src_dir == "contracts"
    assert "mylib/=lib/mylib/" in p.remappings
    assert "other/=lib/other/" in p.remappings
    assert p.solc_version == "0.8.20"


def test_hardhat_project_derives_oz_remapping(tmp_path: Path) -> None:
    (tmp_path / "hardhat.config.js").write_text(
        "module.exports = { solidity: '0.8.19' };\n"
    )
    (tmp_path / "node_modules" / "@openzeppelin" / "contracts").mkdir(parents=True)
    p = detect_build_profile(tmp_path)
    assert p.kind == "hardhat"
    assert p.solc_version == "0.8.19"
    assert any(r.startswith("@openzeppelin/contracts/=") for r in p.remappings)


def test_truffle_and_brownie_kinds(tmp_path: Path) -> None:
    truffle = tmp_path / "truffle"
    truffle.mkdir()
    (truffle / "truffle-config.js").write_text("module.exports = {};")
    assert detect_build_profile(truffle).kind == "truffle"
    brownie = tmp_path / "brownie"
    brownie.mkdir()
    (brownie / "brownie-config.yaml").write_text("project_structure: {}")
    assert detect_build_profile(brownie).kind == "brownie"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_build_profile.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'web3guard.sandbox.build_system'`

- [ ] **Step 3: Write minimal implementation**

```python
"""Detect how a target repository builds, so the sandbox can reproduce it.

The sandbox runs `forge`, so the only thing that must survive the copy is
*import resolution*: remappings, the pinned solc version, `via_ir`, and the
vendored dependency trees. Native `src`/`contracts` layout does not matter
because user code is copied flat under `src/` preserving relative structure.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_REMAPPING_LINE = re.compile(r"^\s*(?P<prefix>[^=#\s]+)\s*=\s*(?P<target>[^#\s]+)\s*$")
_HARDHAT_SOLC = re.compile(r"solidity\s*:\s*[\"']([^\"']+)[\"']")
_SOLC_EXACT = re.compile(r"^\d+\.\d+\.\d+$")


@dataclass(frozen=True)
class BuildProfile:
    kind: str = "plain"                      # foundry | hardhat | truffle | brownie | plain
    src_dir: str = "src"
    test_dir: str = "test"
    libs: tuple[str, ...] = ("lib",)
    remappings: tuple[str, ...] = ()
    solc_version: str | None = None
    via_ir: bool = False


def detect_build_profile(target_path: Path) -> BuildProfile:
    if (target_path / "foundry.toml").is_file():
        return _from_foundry(target_path)
    if (target_path / "hardhat.config.js").is_file() or \
       (target_path / "hardhat.config.ts").is_file():
        return _from_hardhat(target_path)
    if (target_path / "truffle-config.js").is_file():
        return BuildProfile(kind="truffle", src_dir="contracts", test_dir="test")
    if (target_path / "brownie-config.yaml").is_file():
        return BuildProfile(kind="brownie", src_dir="contracts", test_dir="tests")
    return BuildProfile(kind="plain")


def _from_foundry(target_path: Path) -> BuildProfile:
    data: dict = {}
    try:
        import tomllib
        data = tomllib.loads((target_path / "foundry.toml").read_text(errors="ignore"))
    except Exception:  # noqa: BLE001 - malformed toml falls back to defaults
        data = {}
    prof = data.get("profile", {}).get("default", {}) if isinstance(data, dict) else {}
    remappings = list(prof.get("remappings", ()) or ())
    rt = target_path / "remappings.txt"
    if rt.is_file():
        for line in rt.read_text(errors="ignore").splitlines():
            m = _REMAPPING_LINE.match(line)
            if m:
                remappings.append(f"{m.group('prefix')}={m.group('target')}")
    solc = prof.get("solc_version") or prof.get("solc")
    solc = str(solc) if solc else None
    if solc and not _SOLC_EXACT.match(solc):
        solc = None  # ranges are not valid for foundry's solc_version
    return BuildProfile(
        kind="foundry",
        src_dir=str(prof.get("src", "src")),
        test_dir=str(prof.get("test", "test")),
        libs=tuple(prof.get("libs", ["lib"]) or ["lib"]),
        remappings=tuple(remappings),
        solc_version=solc,
        via_ir=bool(prof.get("via_ir", False)),
    )


def _from_hardhat(target_path: Path) -> BuildProfile:
    text = ""
    for name in ("hardhat.config.ts", "hardhat.config.js"):
        p = target_path / name
        if p.is_file():
            text = p.read_text(errors="ignore")
            break
    m = _HARDHAT_SOLC.search(text)
    solc = m.group(1) if m and _SOLC_EXACT.match(m.group(1)) else None
    remappings: list[str] = []
    oz = target_path / "node_modules" / "@openzeppelin" / "contracts"
    if oz.is_dir():
        remappings.append("@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/")
    return BuildProfile(
        kind="hardhat", src_dir="contracts", test_dir="test",
        libs=("lib", "node_modules"), remappings=tuple(remappings),
        solc_version=solc,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_build_profile.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add web3guard/sandbox/build_system.py tests/test_build_profile.py
git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" \
  commit -m "feat(sandbox): detect target build profile (foundry/hardhat/truffle/brownie)"
```

---

### Task 2: Harden-by-merge `foundry.toml` renderer

**Files:**
- Modify: `web3guard/sandbox/build_system.py`
- Test: `tests/test_build_profile.py`

**Interfaces:**
- Consumes: `BuildProfile` from Task 1.
- Produces: `render_foundry_toml(profile: BuildProfile) -> str`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_build_profile.py`:

```python
from web3guard.sandbox.build_system import render_foundry_toml


def test_render_keeps_remappings_and_pins_solc() -> None:
    p = BuildProfile(kind="foundry", solc_version="0.8.20",
                     remappings=("mylib/=lib/mylib/",), via_ir=True)
    out = render_foundry_toml(p)
    assert 'solc_version = "0.8.20"' in out
    assert 'remappings = ["mylib/=lib/mylib/"]' in out
    assert "via_ir = true" in out


def test_render_always_hardens_ffi_and_fs() -> None:
    out = render_foundry_toml(BuildProfile(kind="foundry", remappings=("a/=b/",)))
    assert "ffi = false" in out
    assert "fs_permissions = []" in out
    assert "solc_version" not in out  # no pin when unknown
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_build_profile.py -v`
Expected: FAIL with `ImportError: cannot import name 'render_foundry_toml'`

- [ ] **Step 3: Write minimal implementation**

Append to `web3guard/sandbox/build_system.py`:

```python
def render_foundry_toml(profile: BuildProfile) -> str:
    """Render a hardened foundry.toml that preserves import resolution."""
    lines = [
        "# Web3Guard-managed foundry.toml. Regenerated every run.",
        "[profile.default]",
        'src = "src"',
        'out = "out"',
        'libs = ["lib"]',
        'test = "test"',
        "optimizer = true",
        "optimizer_runs = 200",
    ]
    if profile.solc_version:
        lines.append(f'solc_version = "{profile.solc_version}"')
    if profile.via_ir:
        lines.append("via_ir = true")
    if profile.remappings:
        rendered = ", ".join(f'"{r}"' for r in profile.remappings)
        lines.append(f"remappings = [{rendered}]")
    lines += [
        "fs_permissions = []",
        "ffi = false",
        "verbosity = 1",
    ]
    return "\n".join(lines) + "\n"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_build_profile.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add web3guard/sandbox/build_system.py tests/test_build_profile.py
git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" \
  commit -m "feat(sandbox): render hardened foundry.toml preserving remappings/solc"
```

---

### Task 3: `FoundrySandbox` honors the build profile

**Files:**
- Modify: `web3guard/sandbox/foundry.py`
- Test: `tests/test_foundry_build_repro.py`

**Interfaces:**
- Consumes: `detect_build_profile`, `render_foundry_toml`, `BuildProfile` (Tasks 1–2).
- Produces: `FoundrySandbox(..., build_profile: BuildProfile | None = None)`; when `None`, the profile is detected from `target_path`.

- [ ] **Step 1: Write the failing test**

```python
"""The sandbox must preserve the target's remappings and solc pin."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.sandbox.build_system import detect_build_profile  # noqa: E402
from web3guard.sandbox.foundry import FoundrySandbox  # noqa: E402
from web3guard.languages.solidity import SolidityAdapter  # noqa: E402

_FIXTURE = PROJECT_ROOT / "test_contracts/remapping_project"


@pytest.mark.skipif(shutil.which("forge") is None, reason="forge not installed")
def test_sandbox_uses_target_remappings(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    target = tmp_path / "target"
    shutil.copytree(_FIXTURE, target)
    sb = FoundrySandbox(SolidityAdapter(), target, work)
    root = sb.setup(target)
    toml = (root / "foundry.toml").read_text()
    assert "mylib/=lib/mylib/" in toml
    assert 'solc_version = "0.8.20"' in toml
    assert "ffi = false" in toml

    poc = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.13;\n"
        'import "forge-std/Test.sol";\n'
        'import {Consumer} from "../src/Consumer.sol";\n'
        "contract ExploitTest is Test {\n"
        "    function test_autonomous_exploit() public {\n"
        "        Consumer c = new Consumer();\n"
        "        assertEq(c.sum(2, 3), 5);\n"
        "    }\n"
        "}\n"
    )
    ok, out = sb.write_and_run(poc, "remap")
    assert ok, out
    assert "1 passed" in out


def test_detect_profile_matches_fixture() -> None:
    p = detect_build_profile(_FIXTURE)
    assert p.kind == "foundry"
    assert "mylib/=lib/mylib/" in p.remappings
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_foundry_build_repro.py -v`
Expected: FAIL — `mylib/=lib/mylib/` is absent from the generated `foundry.toml` (the current sandbox writes a fixed template). The fixture does not exist yet, so create it in Step 3 first.

- [ ] **Step 3: Add the fixture and implementation**

Create `test_contracts/remapping_project/foundry.toml`:

```toml
[profile.default]
src = "src"
solc_version = "0.8.20"
remappings = ["mylib/=lib/mylib/"]
```

Create `test_contracts/remapping_project/lib/mylib/contracts/Helper.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library Helper {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
}
```

Create `test_contracts/remapping_project/src/Consumer.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "mylib/contracts/Helper.sol";

contract Consumer {
    function sum(uint256 a, uint256 b) external pure returns (uint256) {
        return Helper.add(a, b);
    }
}
```

Modify `web3guard/sandbox/foundry.py`:

1. Replace the imports block additions:

```python
from web3guard.sandbox.build_system import (
    BuildProfile,
    detect_build_profile,
    render_foundry_toml,
)
```

2. Delete the `_HARDENED_FOUNDRY_TOML` and `_HARDENED_FOUNDRY_TOML_VYPER` constants (lines 35–72). They are superseded by `render_foundry_toml`.

3. Change `__init__` to accept and store a profile:

```python
    def __init__(
        self,
        adapter: LanguageAdapter,
        target_path: Path,
        workdir: Path,
        policy: SandboxPolicy | None = None,
        fork_url: str | None = None,
        build_profile: BuildProfile | None = None,
    ) -> None:
        self.adapter = adapter
        self.target_path = target_path
        self.workdir = workdir
        self.fork_url = fork_url
        self.build_profile = build_profile
        self.guard = SandboxGuard(policy or SandboxPolicy())
        self._root: Path | None = None
```

4. In `setup`, after the `forge init` block and before copying user code, compute the profile and replace the final write:

```python
        profile = self.build_profile or detect_build_profile(target_path)
```

Replace the `(root / "foundry.toml").write_text(...)` block with:

```python
        # Regenerate foundry.toml from the detected profile, hardening
        # ffi/fs but preserving remappings + solc so imports resolve.
        (root / "foundry.toml").write_text(render_foundry_toml(profile))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_foundry_build_repro.py tests/test_build_profile.py -v`
Expected: PASS (or the forge test SKIPs if forge is absent; `test_detect_profile_matches_fixture` must always PASS)

- [ ] **Step 5: Commit**

```bash
git add web3guard/sandbox/foundry.py web3guard/sandbox/build_system.py \
  tests/test_foundry_build_repro.py test_contracts/remapping_project
git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" \
  commit -m "feat(sandbox): make FoundrySandbox reproduce target remappings and solc pin"
```

---

### Task 4: Vendor dependency trees into the sandbox

**Files:**
- Modify: `web3guard/sandbox/foundry.py`
- Test: `tests/test_foundry_build_repro.py`

**Interfaces:**
- Consumes: `BuildProfile.libs` (Tasks 1–3).
- Produces: `FoundrySandbox._vendor_dependencies(target_path: Path, root: Path, profile: BuildProfile) -> None`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_foundry_build_repro.py`:

```python
def test_vendored_lib_is_copied(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    target = tmp_path / "target"
    shutil.copytree(_FIXTURE, target)
    sb = FoundrySandbox(SolidityAdapter(), target, work)
    root = sb.setup(target)
    # lib/mylib was vendored from the target, not created by forge init.
    assert (root / "lib" / "mylib" / "contracts" / "Helper.sol").is_file()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_foundry_build_repro.py::test_vendored_lib_is_copied -v`
Expected: FAIL — `lib/mylib/contracts/Helper.sol` was never copied (only `.sol` files under `src/` are copied today).

- [ ] **Step 3: Write minimal implementation**

Add a method to `FoundrySandbox` and call it from `setup` immediately after the `foundry.toml` write:

```python
    def _vendor_dependencies(self, target_path: Path, root: Path, profile: BuildProfile) -> None:
        """Copy the target's dependency trees so remapped imports resolve.

        For each configured lib dir (e.g. ``lib``, ``node_modules``) copy its
        contents into the sandbox ``lib/`` without clobbering forge-std.
        OpenZeppelin under ``node_modules`` is remapped to
        ``lib/openzeppelin-contracts/contracts`` to match Task 1.
        """
        dest_root = root / "lib"
        dest_root.mkdir(parents=True, exist_ok=True)
        for lib_name in profile.libs:
            src_dir = target_path / lib_name
            if not src_dir.is_dir():
                continue
            if lib_name == "node_modules":
                oz = src_dir / "@openzeppelin" / "contracts"
                if oz.is_dir():
                    dest = dest_root / "openzeppelin-contracts" / "contracts"
                    shutil.copytree(oz, dest, dirs_exist_ok=True)
                continue
            for child in src_dir.iterdir():
                if not child.is_dir():
                    continue
                dest = dest_root / child.name
                shutil.copytree(child, dest, dirs_exist_ok=True)
```

Call it in `setup`:

```python
        (root / "foundry.toml").write_text(render_foundry_toml(profile))
        self._vendor_dependencies(target_path, root, profile)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_foundry_build_repro.py -v`
Expected: PASS (forge test may SKIP; the vendoring test must PASS)

- [ ] **Step 5: Commit**

```bash
git add web3guard/sandbox/foundry.py tests/test_foundry_build_repro.py
git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" \
  commit -m "feat(sandbox): vendor target libs/node_modules for remapped imports"
```

---

### Task 5: Hardhat-to-Foundry shim fixture + CI wiring

**Files:**
- Create: `test_contracts/hardhat_project/hardhat.config.js`
- Create: `test_contracts/hardhat_project/contracts/Consumer.sol`
- Create: `test_contracts/hardhat_project/node_modules/@openzeppelin/contracts/Ownable.sol`
- Modify: `tests/test_foundry_build_repro.py`
- Modify: `.github/workflows/bounty-hunter.yml` (toolchain-smoke run line)

**Interfaces:**
- Consumes: Tasks 1–4.
- Produces: an end-to-end proof that a Hardhat target with an OZ import compiles in the sandbox.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_foundry_build_repro.py`:

```python
_HARDHAT = PROJECT_ROOT / "test_contracts/hardhat_project"


@pytest.mark.skipif(shutil.which("forge") is None, reason="forge not installed")
def test_hardhat_oz_import_compiles(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    target = tmp_path / "target"
    shutil.copytree(_HARDHAT, target)
    sb = FoundrySandbox(SolidityAdapter(), target, work)
    root = sb.setup(target)
    toml = (root / "foundry.toml").read_text()
    assert "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/" in toml
    assert (root / "lib" / "openzeppelin-contracts" / "contracts" / "Ownable.sol").is_file()
    ok, out = sb.write_and_run(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.13;\n"
        'import "forge-std/Test.sol";\n'
        'import {Owned} from "../src/Consumer.sol";\n'
        "contract ExploitTest is Test {\n"
        "    function test_autonomous_exploit() public {\n"
        "        Owned o = new Owned();\n"
        "        assertEq(o.ownerOf(), address(this));\n"
        "    }\n"
        "}\n",
        "hardhat",
    )
    assert ok, out
    assert "1 passed" in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_foundry_build_repro.py::test_hardhat_oz_import_compiles -v`
Expected: FAIL — fixture files do not exist yet.

- [ ] **Step 3: Add the fixture and CI wiring**

Create `test_contracts/hardhat_project/hardhat.config.js`:

```javascript
module.exports = { solidity: "0.8.19" };
```

Create `test_contracts/hardhat_project/node_modules/@openzeppelin/contracts/Ownable.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Ownable {
    address public owner = msg.sender;
    function ownerOf() external view returns (address) { return owner; }
}
```

Create `test_contracts/hardhat_project/contracts/Consumer.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/Ownable.sol";

contract Owned is Ownable {}
```

Delete-and-recreate is not allowed, so do not add a duplicate `Lib.sol`; the single `Consumer.sol` + vendored `Ownable.sol` is enough.

Update the `toolchain-smoke` job's run line in `.github/workflows/bounty-hunter.yml`:

```yaml
      - name: Run sandbox smoke + real exploit-confirmation tests
        run: |
          python -m pytest tests/test_sandbox_smoke.py tests/test_exploit_e2e_foundry.py \
            tests/test_build_profile.py tests/test_foundry_build_repro.py -v
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_foundry_build_repro.py -v`
Expected: PASS (hardhat test may SKIP without forge)

- [ ] **Step 5: Commit**

```bash
git add test_contracts/hardhat_project tests/test_foundry_build_repro.py \
  .github/workflows/bounty-hunter.yml
git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" \
  commit -m "test(sandbox): prove Hardhat + OpenZeppelin imports compile via Foundry shim"
```

---

### Task 6: Runtime impact evidence (`ImpactEvidence`)

**Files:**
- Modify: `web3guard/languages/base.py`
- Modify: `web3guard/languages/solidity.py`
- Test: `tests/test_impact_extraction.py`

**Interfaces:**
- Consumes: existing `TestRunner` dataclass.
- Produces:
  - `ImpactEvidence` frozen dataclass (`gain: int = 0`, `loss: int = 0`, property `confirmed -> bool`).
  - `TestRunner.extract_impact: Callable[[str], ImpactEvidence | None] | None = None`.
  - `extract_impact_solidity(output: str) -> ImpactEvidence | None` and `_FOUNDRY_RUNNER.extract_impact = extract_impact_solidity`.

- [ ] **Step 1: Write the failing test**

```python
"""Impact evidence is parsed from Foundry log output."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from web3guard.languages.solidity import extract_impact_solidity


def test_no_logs_returns_none() -> None:
    assert extract_impact_solidity("1 passed; 0 failed") is None


def test_gain_confirms() -> None:
    out = "Ran 1 test ...\nimpact_gain: 2000000000000000000\n[PASS]"
    ev = extract_impact_solidity(out)
    assert ev is not None and ev.gain == 2 * 10**18 and ev.confirmed


def test_zero_gain_is_not_confirmed() -> None:
    ev = extract_impact_solidity("impact_gain: 0")
    assert ev is not None and not ev.confirmed


def test_loss_confirms() -> None:
    ev = extract_impact_solidity("impact_loss: 42")
    assert ev is not None and ev.loss == 42 and ev.confirmed
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_impact_extraction.py -v`
Expected: FAIL with `ImportError: cannot import name 'extract_impact_solidity'`

- [ ] **Step 3: Write minimal implementation**

In `web3guard/languages/base.py`, add after `TestRunner`:

```python
@dataclass(frozen=True)
class ImpactEvidence:
    """Machine-readable proof that a PoC moved value or broke an invariant."""
    gain: int = 0
    loss: int = 0

    @property
    def confirmed(self) -> bool:
        return self.gain > 0 or self.loss > 0
```

Add a field to `TestRunner`:

```python
    extract_impact: Callable[[str], "ImpactEvidence | None"] | None = None
```

In `web3guard/languages/solidity.py`, add:

```python
_IMPACT_LOG_RE = re.compile(r"impact_(gain|loss):\s*(\d+)")


def extract_impact_solidity(output: str) -> ImpactEvidence | None:
    """Parse ``log_named_uint("impact_gain"|"impact_loss", n)`` lines.

    Returns ``None`` when no impact log was emitted, which the scanner
    treats as "no evidence" (not as "zero impact").
    """
    gain = loss = 0
    found = False
    for kind, value in _IMPACT_LOG_RE.findall(output or ""):
        found = True
        if kind == "gain":
            gain += int(value)
        else:
            loss += int(value)
    return ImpactEvidence(gain=gain, loss=loss) if found else None
```

Import `ImpactEvidence` from `web3guard.languages.base` and set it on the runner:

```python
_FOUNDRY_RUNNER = TestRunner(
    ...
    has_impact_assertion=_has_impact_assertion_solidity,
    extract_impact=extract_impact_solidity,
    ...
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_impact_extraction.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add web3guard/languages/base.py web3guard/languages/solidity.py tests/test_impact_extraction.py
git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" \
  commit -m "feat(solidity): parse runtime impact evidence from Foundry logs"
```

---

### Task 7: Require an impact log in the syntactic pre-filter

**Files:**
- Modify: `web3guard/languages/solidity.py` (`_has_impact_assertion_solidity`)
- Test: `tests/test_impact_extraction.py`

**Interfaces:**
- Consumes: Task 6.
- Produces: `_has_impact_assertion_solidity` additionally requires an `impact_gain`/`impact_loss` log emit.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_impact_extraction.py`:

```python
from web3guard.languages.solidity import _has_impact_assertion_solidity


def test_rejects_bare_assert_true() -> None:
    assert not _has_impact_assertion_solidity("assert(true);")


def test_rejects_assert_without_impact_log() -> None:
    code = "function test_autonomous_exploit() public { assertEq(address(a).balance, 2 ether); }"
    assert not _has_impact_assertion_solidity(code)


def test_accepts_comparison_plus_impact_log() -> None:
    code = (
        "function test_autonomous_exploit() public {\n"
        "    assertGt(address(a).balance, 1 ether);\n"
        '    emit log_named_uint("impact_gain", 2 ether);\n'
        "}"
    )
    assert _has_impact_assertion_solidity(code)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_impact_extraction.py -v`
Expected: `test_rejects_assert_without_impact_log` FAILS (current regex accepts it).

- [ ] **Step 3: Write minimal implementation**

At the top of `_has_impact_assertion_solidity`, add the impact-log requirement:

```python
def _has_impact_assertion_solidity(code: str) -> bool:
    if not code:
        return False
    if not re.search(r'log_named_(?:uint|int)\s*\(\s*"impact_(?:gain|loss)"', code):
        return False
    # ... existing assertion + comparison checks unchanged below ...
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_impact_extraction.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add web3guard/languages/solidity.py tests/test_impact_extraction.py
git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" \
  commit -m "feat(solidity): require an impact log emit in the PoC pre-filter"
```

---

### Task 8: Scanner gates `CONFIRMED EXPLOIT` on runtime impact

**Files:**
- Modify: `web3guard/scanner.py` (`_generate_poc`)
- Modify: `web3guard/languages/solidity.py` (`_SOLIDITY_EXPLOIT_TEMPLATE`)
- Modify: `tests/test_exploit_e2e_foundry.py` (`_GOOD_POC`)
- Modify: every test fake whose sandbox returns a passing log with no impact line
- Test: `tests/test_exploit_confirmation.py`, `tests/test_exploit_e2e_foundry.py`

**Interfaces:**
- Consumes: `TestRunner.extract_impact` (Task 6).
- Produces: `_generate_poc` only sets `CONFIRMED EXPLOIT` when the run passed and, if an extractor exists, it reported `confirmed`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_exploit_confirmation.py`:

```python
class _NoEvidenceSandbox:
    def write_and_run(self, code: str, fingerprint: str, timeout: int = 90):
        return True, "1 passed; 0 failed"  # no impact_gain/log evidence


def test_pass_without_impact_evidence_is_not_confirmed(monkeypatch) -> None:
    import web3guard.sandbox as sandbox_mod

    fake = _NoEvidenceSandbox()
    monkeypatch.setattr(sandbox_mod, "create_sandbox", lambda *a, **k: fake)
    fc = ExploitAIClient("// SPDX-License-Identifier: MIT\nassertEq(1, 1);")
    cfg = {"enable_ai_analysis": True, "enable_discovery": False,
           "enable_exploit": True, "max_exploit_attempts": 1}
    s = Scanner(config=cfg, ai_client=fc)
    result = s.scan([str(_VULN_DIR) + "|max"])
    statuses = [f.status for f in result.targets[0].findings]
    assert all("CONFIRMED" not in st for st in statuses), statuses
```

Add `_VULN_DIR = Path(__file__).resolve().parent.parent / "test_contracts" / "vulnerable"` near the imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_exploit_confirmation.py::test_pass_without_impact_evidence_is_not_confirmed -v`
Expected: FAIL — the fake `PASSED` run currently yields `CONFIRMED EXPLOIT`.

- [ ] **Step 3: Write minimal implementation**

In `web3guard/scanner.py` `_generate_poc`, replace the `if ok:` block:

```python
            ok, out = sandbox.write_and_run(code, finding.fingerprint or "exploit")
            if ok:
                extractor = adapter.test_runner.extract_impact
                evidence = extractor(out) if extractor is not None else None
                if extractor is not None and evidence is None:
                    last_err = "PoC passed but emitted no impact_gain/impact_loss evidence"
                    continue
                if evidence is not None and not evidence.confirmed:
                    last_err = "PoC passed but impact evidence was zero"
                    continue
                finding.status = "CONFIRMED EXPLOIT"
                finding.poc_code = code
                finding.exploit_log = out
                if evidence is not None:
                    finding.metadata["impact_gain"] = evidence.gain
                    finding.metadata["impact_loss"] = evidence.loss
                self._capture_on_chain_tvl(finding, out)
                return
            last_err = out[-1500:]
```

In `web3guard/languages/solidity.py`, append to `_SOLIDITY_EXPLOIT_TEMPLATE` an instruction block:

```text
The test MUST emit a machine-readable impact log proving value moved:
    emit log_named_uint("impact_gain", <attackerGainWei>);
    emit log_named_uint("impact_loss", <victimLossWei>);
Use 0 for the side with no measurable delta. A passing test without this
log is rejected.
```

In `tests/test_exploit_e2e_foundry.py`, update `_GOOD_POC`'s test body:

```solidity
contract ExploitTest is Test {
    function test_autonomous_exploit() public {
        VulnerableBank bank = new VulnerableBank();
        vm.deal(address(this), 3 ether);
        Attack attacker = new Attack(bank);
        attacker.arm{value: 2 ether}();
        assertEq(address(bank).balance, 2 ether);

        uint256 before = address(attacker).balance;
        attacker.attack();
        uint256 gain = address(attacker).balance - before;

        assertEq(address(bank).balance, 0);
        assertEq(address(attacker).balance, 2 ether);
        emit log_named_uint("impact_gain", gain);
    }
}
```

Update every fake sandbox used by confirmation tests so its success output includes `"impact_gain: 1"` (grep: `grep -rn "return True, \"PASSED\"\|return True, .*passed" tests/`).

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_exploit_confirmation.py tests/test_exploit_e2e_foundry.py tests/test_impact_extraction.py -v`
Expected: PASS (forge test SKIPs without forge; the no-evidence test PASSES)

- [ ] **Step 5: Commit**

```bash
git add web3guard/scanner.py web3guard/languages/solidity.py \
  tests/test_exploit_confirmation.py tests/test_exploit_e2e_foundry.py
git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" \
  commit -m "feat(scanner): require runtime impact evidence before CONFIRMED EXPLOIT"
```

---

### Task 9: Per-category source mutators

**Files:**
- Create: `web3guard/sandbox/differential.py`
- Test: `tests/test_differential.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `MUTATORS: dict[str, Callable[[str], str | None]]`
  - `mutate_source(category: str, source: str) -> str | None`

- [ ] **Step 1: Write the failing test**

```python
"""Unit tests for vulnerability-patching mutators."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from web3guard.sandbox.differential import mutate_source

_VULN = """\
function withdraw(uint256 _amount) external {
    require(balances[msg.sender] >= _amount, "insufficient");
    (bool ok,) = msg.sender.call{value: _amount}("");
    require(ok, "send fail");
    balances[msg.sender] -= _amount;
}
"""


def test_reentrancy_mutator_reorders_state_update() -> None:
    out = mutate_source("reentrancy", _VULN)
    assert out is not None
    assert out.index("balances[msg.sender] -= _amount;") < out.index('call{value: _amount}("")')


def test_access_control_mutator_inserts_guard() -> None:
    src = "function setOwner(address n) external { owner = n; }"
    out = mutate_source("access-control", src)
    assert out is not None and "require(msg.sender == owner" in out


def test_unknown_category_returns_none() -> None:
    assert mutate_source("arithmetic", _VULN) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_differential.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'web3guard.sandbox.differential'`

- [ ] **Step 3: Write minimal implementation**

```python
"""Best-effort source mutators that patch one vulnerability category.

Used for differential confirmation: a real exploit must pass against the
vulnerable contract and FAIL against the patched copy. A mutator returns
``None`` when it cannot confidently patch the source, and the caller then
treats the finding as undifferentiated instead of confirmed.
"""
from __future__ import annotations

import re
from collections.abc import Callable

_REENTRANCY_CALL = re.compile(
    r'\(bool\s+ok,\)\s*=\s*msg\.sender\.call\{value:\s*_amount\}\(""\);\s*'
    r'require\(ok,\s*"send fail"\);\s*'
    r'balances\[msg\.sender\]\s*-=\s*_amount;',
    re.DOTALL,
)


def _mutate_reentrancy(source: str) -> str | None:
    def _fix(m: re.Match[str]) -> str:
        return (
            "balances[msg.sender] -= _amount;\n        "
            '(bool ok,) = msg.sender.call{value: _amount}("");\n        '
            'require(ok, "send fail");'
        )
    new, count = _REENTRANCY_CALL.subn(_fix, source)
    return new if count else None


def _mutate_access_control(source: str) -> str | None:
    pattern = re.compile(
        r"(\bfunction\s+\w+\s*\([^)]*\)\s*(?:external|public)[^{;]*)\{([^{}]*)\}",
        re.DOTALL,
    )

    def _fix(m: re.Match[str]) -> str:
        body = m.group(2)
        if "require(msg.sender" in body:
            return m.group(0)
        return (
            m.group(1) + "{\n        "
            'require(msg.sender == owner, "unauthorized");\n'
            + body + "\n    }"
        )

    new, count = pattern.subn(_fix, source)
    return new if count else None


MUTATORS: dict[str, Callable[[str], str | None]] = {
    "reentrancy": _mutate_reentrancy,
    "access-control": _mutate_access_control,
}


def mutate_source(category: str, source: str) -> str | None:
    mutator = MUTATORS.get(category)
    if mutator is None:
        return None
    return mutator(source)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_differential.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add web3guard/sandbox/differential.py tests/test_differential.py
git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" \
  commit -m "feat(sandbox): add reentrancy/access-control patch mutators"
```

---

### Task 10: Differential runner (vulnerable vs patched)

**Files:**
- Modify: `web3guard/sandbox/differential.py`
- Test: `tests/test_differential.py`

**Interfaces:**
- Consumes: `mutate_source`, `create_sandbox` from `web3guard.sandbox`.
- Produces:
  - `DifferentialOutcome` dataclass (`status: str`, `vulnerable_output: str`, `patched_output: str`).
  - `run_differential(adapter, target_path, workdir, poc_code, fingerprint, category) -> DifferentialOutcome` with `status` in `{"confirmed", "vulnerable-failed", "no-mutator", "patched-still-passes"}`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_differential.py`:

```python
def test_no_mutator_reports_unverified(tmp_path: Path) -> None:
    from web3guard.languages.solidity import SolidityAdapter
    from web3guard.sandbox.differential import run_differential

    target = tmp_path / "t"
    target.mkdir()
    (target / "X.sol").write_text("contract X {}")
    work = tmp_path / "w"
    work.mkdir()
    out = run_differential(SolidityAdapter(), target, work, "// noop", "fp", "arithmetic")
    assert out.status == "no-mutator"
```

(The full forge-backed differential is covered in Task 12.)

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_differential.py::test_no_mutator_reports_unverified -v`
Expected: FAIL with `ImportError: cannot import name 'run_differential'`

- [ ] **Step 3: Write minimal implementation**

Append to `web3guard/sandbox/differential.py`:

```python
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from web3guard.sandbox import create_sandbox


@dataclass
class DifferentialOutcome:
    status: str
    vulnerable_output: str = ""
    patched_output: str = ""


def _apply_mutation(category: str, root: Path) -> bool:
    changed = False
    for sol in root.rglob("*.sol"):
        text = sol.read_text(errors="ignore")
        new = mutate_source(category, text)
        if new is not None and new != text:
            sol.write_text(new)
            changed = True
    return changed


def run_differential(
    adapter: Any,
    target_path: Path,
    workdir: Path,
    poc_code: str,
    fingerprint: str,
    category: str,
) -> DifferentialOutcome:
    if category not in MUTATORS:
        return DifferentialOutcome("no-mutator")
    vuln = create_sandbox(adapter, target_path, workdir)
    if vuln is None:
        return DifferentialOutcome("vulnerable-failed", "sandbox init failed", "")
    ok_v, out_v = vuln.write_and_run(poc_code, f"{fingerprint}-vuln")
    if not ok_v:
        return DifferentialOutcome("vulnerable-failed", out_v, "")
    patched_dir = workdir / f"patched-{fingerprint[:12] or 'fp'}"
    shutil.copytree(target_path, patched_dir, dirs_exist_ok=True)
    if not _apply_mutation(category, patched_dir):
        return DifferentialOutcome("no-mutator", out_v, "")
    patched = create_sandbox(adapter, patched_dir, workdir)
    if patched is None:
        return DifferentialOutcome("no-mutator", out_v, "")
    ok_p, out_p = patched.write_and_run(poc_code, f"{fingerprint}-patched")
    if ok_p:
        return DifferentialOutcome("patched-still-passes", out_v, out_p)
    return DifferentialOutcome("confirmed", out_v, out_p)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_differential.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add web3guard/sandbox/differential.py tests/test_differential.py
git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" \
  commit -m "feat(sandbox): add vulnerable-vs-patched differential runner"
```

---

### Task 11: Scanner requires patched-fail when a mutator exists

**Files:**
- Modify: `web3guard/scanner.py` (`DEFAULT_CONFIG`, `_generate_poc`)
- Test: `tests/test_exploit_confirmation.py`

**Interfaces:**
- Consumes: `run_differential`, `DifferentialOutcome` (Task 10).
- Produces: config key `enable_differential` (default `True`); when true and the finding's category has a mutator, `CONFIRMED EXPLOIT` additionally requires `outcome.status == "confirmed"`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_exploit_confirmation.py`:

```python
class _ImpactButPatchedPasses:
    """Vulnerable run passes; patched run also passes -> not a real exploit."""

    def __init__(self) -> None:
        self.calls = 0

    def write_and_run(self, code: str, fingerprint: str, timeout: int = 90):
        self.calls += 1
        return True, "impact_gain: 100\n1 passed"


def test_patched_still_passing_is_not_confirmed(monkeypatch) -> None:
    import web3guard.scanner as scanner_mod
    import web3guard.sandbox as sandbox_mod

    fake = _ImpactButPatchedPasses()
    monkeypatch.setattr(sandbox_mod, "create_sandbox", lambda *a, **k: fake)
    monkeypatch.setattr(
        scanner_mod, "run_differential",
        lambda *a, **k: scanner_mod.DifferentialOutcome("patched-still-passes"),
    )
    fc = ExploitAIClient("// SPDX-License-Identifier: MIT\nassertEq(1, 1);")
    cfg = {"enable_ai_analysis": True, "enable_discovery": False,
           "enable_exploit": True, "max_exploit_attempts": 1,
           "enable_differential": True}
    s = Scanner(config=cfg, ai_client=fc)
    result = s.scan([str(_VULN_DIR) + "|max"])
    statuses = [f.status for f in result.targets[0].findings]
    assert all("CONFIRMED" not in st for st in statuses), statuses
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_exploit_confirmation.py::test_patched_still_passing_is_not_confirmed -v`
Expected: FAIL — `scanner_mod.DifferentialOutcome` and `scanner_mod.run_differential` are not imported yet, and the gate does not exist.

- [ ] **Step 3: Write minimal implementation**

In `web3guard/scanner.py`, add imports near the sandbox import site:

```python
from web3guard.sandbox.differential import (
    DifferentialOutcome,
    run_differential,
)
```

Add to `DEFAULT_CONFIG`:

```python
    "enable_differential": True,
```

In `_generate_poc`, after the runtime impact checks and before setting `CONFIRMED EXPLOIT`:

```python
                if self.config.get("enable_differential", True):
                    outcome = run_differential(
                        adapter, target_path, self.workdir, code,
                        finding.fingerprint or "exploit", finding.category,
                    )
                    finding.metadata["differential"] = outcome.status
                    if outcome.status == "patched-still-passes":
                        last_err = "differential: exploit also passes on patched copy"
                        continue
                    if outcome.status == "vulnerable-failed":
                        last_err = "differential: vulnerable run failed"
                        continue
                finding.status = "CONFIRMED EXPLOIT"
```

Keep the existing `finding.poc_code` / `exploit_log` / `_capture_on_chain_tvl` lines after this.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_exploit_confirmation.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add web3guard/scanner.py tests/test_exploit_confirmation.py
git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" \
  commit -m "feat(scanner): require patched-fail differential before CONFIRMED EXPLOIT"
```

---

### Task 12: Real-Forge differential end-to-end regression

**Files:**
- Create: `tests/test_differential_e2e_foundry.py`
- Modify: `.github/workflows/bounty-hunter.yml` (toolchain-smoke run line)
- Modify: `tests/test_exploit_e2e_foundry.py` only if the shared PoC needs reuse

**Interfaces:**
- Consumes: Tasks 1–11.
- Produces: a real-`forge` proof that reentrancy confirmation requires both the vulnerable pass and the patched fail.

- [ ] **Step 1: Write the failing test**

```python
"""Real-Forge differential regression: patched copy must reject the PoC."""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.scanner import Scanner  # noqa: E402
from tests.test_exploit_e2e_foundry import _GOOD_POC, ScriptedExploitAI, _REENTRANCY_FIXTURE  # noqa: E402


@pytest.mark.skipif(shutil.which("forge") is None, reason="forge not installed")
def test_real_differential_confirms_reentrancy(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    shutil.copy2(_REENTRANCY_FIXTURE, target / "ReentrancyVault.sol")
    work = tmp_path / "work"
    work.mkdir()
    cfg = {
        "enable_ai_analysis": True,
        "enable_discovery": False,
        "enable_exploit": True,
        "max_exploit_attempts": 2,
        "enable_differential": True,
    }
    s = Scanner(config=cfg, workdir=work, ai_client=ScriptedExploitAI(_GOOD_POC))
    result = s.scan([str(target) + "|max"])
    findings = result.targets[0].findings
    assert len(findings) == 1, [f.category for f in findings]
    f = findings[0]
    assert f.status == "CONFIRMED EXPLOIT", (f.status, f.exploit_log)
    assert f.metadata.get("differential") == "confirmed"
    assert f.metadata.get("impact_gain", 0) > 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_differential_e2e_foundry.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tests.test_exploit_e2e_foundry'` (the tests dir has no `__init__.py`).

- [ ] **Step 3: Fix the import and wire CI**

Create `tests/__init__.py` (empty file) so the cross-test import resolves.

Update the `toolchain-smoke` run line in `.github/workflows/bounty-hunter.yml`:

```yaml
      - name: Run sandbox smoke + real exploit-confirmation tests
        run: |
          python -m pytest tests/test_sandbox_smoke.py tests/test_exploit_e2e_foundry.py \
            tests/test_differential_e2e_foundry.py tests/test_build_profile.py \
            tests/test_foundry_build_repro.py tests/test_impact_extraction.py \
            tests/test_differential.py -v
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_differential_e2e_foundry.py -v`
Expected: PASS with forge installed; SKIP without forge. Also verify the metric: the patched copy (state update moved before the external call) makes the reentrant `attacker.attack()` revert or produce zero gain, so `run_differential` returns `confirmed`.

- [ ] **Step 5: Commit**

```bash
git add tests/__init__.py tests/test_differential_e2e_foundry.py .github/workflows/bounty-hunter.yml
git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" \
  commit -m "test(scanner): real-Forge differential confirmation regression"
```

---

## Self-Review

**Spec coverage**
- Faithful builds (B1.1): Tasks 1–5 cover detection, remappings, solc pins, vendoring, and a Hardhat/OZ shim.
- Real impact gate (B1.3): Tasks 6–8 cover `ImpactEvidence`, the syntactic pre-filter, the template, and the scanner gate. Non-EVM impact is explicitly out of this slice (follow-on plan).
- Negative controls (B1.4): Tasks 9–12 cover mutators, the differential runner, the scanner gate, and the real-Forge regression.

**Placeholder scan:** no TBD/TODO; every code step contains runnable code or a full file body.

**Type consistency:** `BuildProfile` fields match across Tasks 1–4; `ImpactEvidence.gain/loss/confirmed` match Tasks 6 and 8; `DifferentialOutcome.status` values match Tasks 10–12; `TestRunner.extract_impact` is the single field used by the scanner.

## Known follow-ons (not in this slice)
- Reachability/inheritance resolution (B1.2) to cut false positives.
- Non-EVM real impact harnesses (B1.3 remainder) and the Clarity `CONFIRMED` honesty fix.
- Fork-state execution (B1.5).
- Calibration on real exploit data (B2.2) to measure whether any of this actually improved precision/recall.

# External Reachability Pre-Filter (B1.2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Classify each finding as externally reachable / not reachable / unknown and reject only provable not-reachable findings before exploit generation, cutting false positives and wasted AI/sandbox budget.

**Architecture:** A new `web3guard/reachability/` package builds a per-target Solidity function index (visibility, inheritance, reverse call edges), resolves a verdict with a conservative custom parser, optionally corroborates with Slither, does a cheap visibility check for non-Solidity, and exposes a pure `ReachabilityAnalyzer.classify(finding)`. The scanner annotates every finding and rejects the definitive `not_reachable` ones.

**Tech Stack:** Python 3.11+, `re`, `dataclasses`, `pathlib`; reuses `web3guard.discovery.static_analyzer` primitives; optional `slither-analyzer` extra.

**Spec:** `docs/superpowers/specs/2026-09-16-reachability-design.md`

## Global Constraints

- Python is `python3` (never `python`).
- Foundry-backed tests need `PATH="$HOME/.foundry/bin:$PATH"`.
- Repo root: `/tmp/opencode/web3guard-bounty-hunter`; always set the shell workdir there.
- TDD: failing test first, then implementation, then green.
- Do not add gratuitous inline comments; match the existing module-docstring style.
- Keep `ffi = false` and `fs_permissions = []` in generated Foundry configs (untouched here).
- Never print or commit secrets.
- Commit identity: `git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" commit -m "..."`.
- Push with `GIT_ASKPASS=/tmp/opencode/git-askpass.sh git -c credential.helper= push origin main`.
- Reachability never gates `CONFIRMED EXPLOIT` and never suppresses under uncertainty: only `not_reachable` is rejected; `reachable`/`unknown` proceed.
- The analyzer must never raise into the scan loop; exceptions degrade to `unknown`.

---

### Task 1: Reachability types and Solidity function index

**Files:**
- Create: `web3guard/reachability/__init__.py`
- Create: `web3guard/reachability/types.py`
- Create: `web3guard/reachability/solidity_index.py`
- Test: `tests/test_reachability_index.py`

**Interfaces:**
- Consumes: `web3guard.discovery.static_analyzer._clean_code`, `._iter_braced_functions`, `._brace_body`.
- Produces:
  - `ReachabilityVerdict(StrEnum)` with `REACHABLE`, `NOT_REACHABLE`, `UNKNOWN`.
  - `ReachabilityEvidence(verdict, backend, function="", detail="", entrypoint="", path=(), gated=False)` with `.to_metadata() -> dict`.
  - `FunctionInfo(name, contract, file, visibility="", is_constructor=False, is_modifier=False, abstract=False, virtual=False, gated=False, body="", calls=frozenset(), parents=(), line_start=0, line_end=0)`.
  - `FunctionIndex.build(target_path) -> FunctionIndex`, `.functions`, `.by_name(name)`, `.references(name)`, `.enclosing(file, function, line)`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_reachability_index.py`:

```python
"""Tests for the Solidity reachability function index."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.reachability.solidity_index import FunctionIndex  # noqa: E402


SOURCE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

abstract contract Base {
    mapping(address => uint256) public balances;

    function _helper() internal virtual {
        balances[msg.sender] = 0;
    }
}

contract Derived is Base {
    function withdraw() external {
        _helper();
    }

    function _dead() internal {
        balances[msg.sender] = 1;
    }
}
"""


def _index(tmp_path: Path) -> FunctionIndex:
    (tmp_path / "Vault.sol").write_text(SOURCE, encoding="utf-8")
    return FunctionIndex.build(tmp_path)


def test_indexes_visibility_and_inheritance(tmp_path: Path) -> None:
    idx = _index(tmp_path)
    withdraw = idx.by_name("withdraw")[0]
    assert withdraw.visibility == "external"
    assert withdraw.contract == "Derived"
    assert withdraw.parents == ("Base",)


def test_helper_is_abstract_member(tmp_path: Path) -> None:
    helper = _index(tmp_path).by_name("_helper")[0]
    assert helper.visibility == "internal"
    assert helper.virtual is True
    assert helper.abstract is True


def test_references_finds_caller(tmp_path: Path) -> None:
    callers = [fn.name for fn in _index(tmp_path).references("_helper")]
    assert "withdraw" in callers


def test_references_empty_for_dead_code(tmp_path: Path) -> None:
    assert _index(tmp_path).references("_dead") == []


def test_enclosing_by_function_name(tmp_path: Path) -> None:
    fn = _index(tmp_path).enclosing("Vault.sol", "withdraw", 0)
    assert fn is not None and fn.name == "withdraw"


def test_enclosing_by_line(tmp_path: Path) -> None:
    fn = _index(tmp_path).enclosing("Vault.sol", "", 17)
    assert fn is not None and fn.name == "_dead"


def test_build_skips_vendored_and_tests(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "Dep.sol").write_text(
        "contract Dep { function f() public {} }", encoding="utf-8")
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "T.sol").write_text(
        "contract T { function g() public {} }", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "A.sol").write_text(
        "contract A { function h() public {} }", encoding="utf-8")
    names = {fn.name for fn in FunctionIndex.build(tmp_path).functions}
    assert "h" in names
    assert "f" not in names
    assert "g" not in names


def test_to_metadata_roundtrip() -> None:
    from web3guard.reachability.types import ReachabilityEvidence, ReachabilityVerdict

    ev = ReachabilityEvidence(
        ReachabilityVerdict.NOT_REACHABLE, "solidity-parser",
        function="_dead", detail="no path",
    )
    assert ev.to_metadata() == {
        "verdict": "not_reachable",
        "backend": "solidity-parser",
        "function": "_dead",
        "detail": "no path",
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_reachability_index.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'web3guard.reachability'`.

- [ ] **Step 3: Create the package types**

Create `web3guard/reachability/types.py`:

```python
"""Verdict and evidence types for external reachability analysis."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ReachabilityVerdict(StrEnum):
    REACHABLE = "reachable"
    NOT_REACHABLE = "not_reachable"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ReachabilityEvidence:
    verdict: ReachabilityVerdict
    backend: str
    function: str = ""
    detail: str = ""
    entrypoint: str = ""
    path: tuple[str, ...] = ()
    gated: bool = False

    def to_metadata(self) -> dict[str, object]:
        out: dict[str, object] = {
            "verdict": self.verdict.value,
            "backend": self.backend,
            "function": self.function,
            "detail": self.detail,
        }
        if self.entrypoint:
            out["entrypoint"] = self.entrypoint
        if self.path:
            out["path"] = list(self.path)
        if self.gated:
            out["gated"] = True
        return out
```

Create `web3guard/reachability/__init__.py`:

```python
"""External-reachability pre-filter (B1.2)."""

from web3guard.reachability.types import ReachabilityEvidence, ReachabilityVerdict

__all__ = ["ReachabilityEvidence", "ReachabilityVerdict"]
```

- [ ] **Step 4: Create the Solidity function index**

Create `web3guard/reachability/solidity_index.py`:

```python
"""Solidity function index used by reachability analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from web3guard.discovery.static_analyzer import (
    _brace_body,
    _clean_code,
    _iter_braced_functions,
)

_CONTRACT_RE = re.compile(
    r"\b(?P<kind>abstract\s+contract|contract|interface|library)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s+is\s+(?P<parents>[^{]+))?\s*\{"
)
_CONSTRUCTOR_RE = re.compile(r"\bconstructor\s*\([^)]*\)[^{;]*\{")
_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_VISIBILITY_RE = re.compile(r"\b(public|external|internal|private)\b")
_GATE_RE = re.compile(r"only[A-Za-z][A-Za-z0-9_]*\b")
_VIRTUAL_RE = re.compile(r"\bvirtual\b")

_SKIP_DIRS = {
    "test", "tests", "script", "scripts", "lib", "libs", "node_modules",
    "build", "dist", "out", ".git", "mock", "mocks", "stub", "stubs",
}


@dataclass
class FunctionInfo:
    name: str
    contract: str
    file: str
    visibility: str = ""
    is_constructor: bool = False
    is_modifier: bool = False
    abstract: bool = False
    virtual: bool = False
    gated: bool = False
    body: str = ""
    calls: frozenset[str] = frozenset()
    parents: tuple[str, ...] = ()
    line_start: int = 0
    line_end: int = 0


@dataclass
class FunctionIndex:
    functions: list[FunctionInfo] = field(default_factory=list)
    root: Path = Path(".")
    _by_name: dict[str, list[FunctionInfo]] = field(
        init=False, default_factory=dict, repr=False
    )

    def __post_init__(self) -> None:
        for fn in self.functions:
            self._by_name.setdefault(fn.name, []).append(fn)

    @classmethod
    def build(cls, target_path: Path) -> "FunctionIndex":
        root = Path(target_path)
        funcs: list[FunctionInfo] = []
        for path in sorted(root.rglob("*.sol")):
            if _is_skipped(path, root):
                continue
            try:
                raw = path.read_text(errors="ignore")
            except OSError:
                continue
            try:
                rel = str(path.relative_to(root))
            except ValueError:
                rel = str(path)
            funcs.extend(_parse_file(raw, rel))
        return cls(functions=funcs, root=root)

    def by_name(self, name: str) -> list[FunctionInfo]:
        return list(self._by_name.get(name, ()))

    def references(self, name: str) -> list[FunctionInfo]:
        pattern = re.compile(rf"\b{re.escape(name)}\b")
        out: list[FunctionInfo] = []
        for fn in self.functions:
            if name in fn.calls or pattern.search(fn.body):
                out.append(fn)
        return out

    def enclosing(self, file: str, function: str, line: int) -> FunctionInfo | None:
        base = Path(file).name
        candidates = [fn for fn in self.functions if Path(fn.file).name == base]
        if function:
            named = [fn for fn in candidates if fn.name == function]
            if named:
                return named[0]
            inherited = self.by_name(function)
            if inherited:
                return inherited[0]
        if line:
            for fn in candidates:
                if fn.line_start and fn.line_start <= line <= fn.line_end:
                    return fn
        return None


def _is_skipped(path: Path, root: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    if {part.lower() for part in rel.parts[:-1]} & _SKIP_DIRS:
        return True
    stem = path.stem.lower()
    return stem.endswith(("test", "mock", "stub", "fake", "spec"))


def _visibility(decl: str) -> str:
    m = _VISIBILITY_RE.search(decl)
    return m.group(1) if m else ""


def _parse_file(raw: str, rel: str) -> list[FunctionInfo]:
    text = _clean_code(raw, "solidity")
    funcs: list[FunctionInfo] = []
    for m in _CONTRACT_RE.finditer(text):
        kind = m.group("kind")
        cname = m.group("name")
        parents = tuple(
            p.strip().split("(")[0].split(" ")[0]
            for p in (m.group("parents") or "").split(",")
            if p.strip()
        )
        brace = text.find("{", m.end() - 1)
        if brace == -1:
            continue
        body = text[brace:_brace_body(text, brace)]
        base_line = text[:brace].count("\n") + 1
        abstract = kind.startswith("abstract") or kind == "interface"
        for name, fbody, start_line, _off, decl in _iter_braced_functions(body, "solidity"):
            if not name:
                continue
            gstart = base_line + start_line - 1
            funcs.append(FunctionInfo(
                name=name,
                contract=cname,
                file=rel,
                visibility=_visibility(decl),
                abstract=abstract,
                virtual=bool(_VIRTUAL_RE.search(decl)),
                gated=bool(_GATE_RE.search(decl + fbody)),
                body=fbody,
                calls=frozenset(_CALL_RE.findall(fbody)),
                parents=parents,
                line_start=gstart,
                line_end=gstart + fbody.count("\n"),
            ))
        for cm in _CONSTRUCTOR_RE.finditer(body):
            cstart = base_line + body[:cm.start()].count("\n")
            tail = body[cm.start():]
            funcs.append(FunctionInfo(
                name="constructor",
                contract=cname,
                file=rel,
                visibility="public",
                is_constructor=True,
                abstract=abstract,
                body=tail,
                parents=parents,
                line_start=cstart,
                line_end=cstart + tail.count("\n"),
            ))
    return funcs
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python3 -m pytest tests/test_reachability_index.py -v`
Expected: PASS (8 passed).

- [ ] **Step 6: Commit**

```bash
git add web3guard/reachability/__init__.py web3guard/reachability/types.py \
  web3guard/reachability/solidity_index.py tests/test_reachability_index.py
git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" \
  commit -m "feat(reachability): Solidity function index and verdict types"
```

---

### Task 2: Solidity verdict resolver

**Files:**
- Create: `web3guard/reachability/solidity.py`
- Test: `tests/test_reachability_solidity.py`

**Interfaces:**
- Consumes: `FunctionIndex`, `FunctionInfo`, `ReachabilityEvidence`, `ReachabilityVerdict`.
- Produces: `resolve_solidity(index: FunctionIndex, fn: FunctionInfo | None) -> ReachabilityEvidence`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_reachability_solidity.py`:

```python
"""Tests for custom Solidity reachability verdicts."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.reachability.solidity import resolve_solidity  # noqa: E402
from web3guard.reachability.solidity_index import FunctionIndex  # noqa: E402
from web3guard.reachability.types import ReachabilityVerdict  # noqa: E402


SOURCE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

abstract contract Base {
    mapping(address => uint256) public balances;

    function _helper() internal virtual {
        balances[msg.sender] = 0;
    }
}

contract Vault is Base {
    function withdraw() external {
        _helper();
    }

    function _dead() internal {
        balances[msg.sender] = 1;
    }

    function _mid() internal {
        _leaf();
    }

    function _leaf() internal {
        balances[msg.sender] = 2;
    }

    function lockedWithdraw() external onlyOwner {
        balances[msg.sender] = 0;
    }
}
"""


def _index(tmp_path: Path) -> FunctionIndex:
    (tmp_path / "Vault.sol").write_text(SOURCE, encoding="utf-8")
    return FunctionIndex.build(tmp_path)


def _verdict(tmp_path: Path, name: str) -> object:
    idx = _index(tmp_path)
    return resolve_solidity(idx, idx.by_name(name)[0])


def test_public_function_is_reachable(tmp_path: Path) -> None:
    ev = _verdict(tmp_path, "withdraw")
    assert ev.verdict == ReachabilityVerdict.REACHABLE
    assert ev.entrypoint == "withdraw"


def test_inherited_internal_helper_is_reachable(tmp_path: Path) -> None:
    ev = _verdict(tmp_path, "_helper")
    assert ev.verdict == ReachabilityVerdict.REACHABLE
    assert ev.entrypoint == "withdraw"
    assert "_helper" in ev.path


def test_dead_internal_is_not_reachable(tmp_path: Path) -> None:
    assert _verdict(tmp_path, "_dead").verdict == ReachabilityVerdict.NOT_REACHABLE


def test_internal_called_only_by_uncalled_internal_is_not_reachable(tmp_path: Path) -> None:
    assert _verdict(tmp_path, "_leaf").verdict == ReachabilityVerdict.NOT_REACHABLE


def test_abstract_virtual_member_is_unknown(tmp_path: Path) -> None:
    src = """\
pragma solidity ^0.8.0;

abstract contract A {
    function _hook() internal virtual {
        uint x = 1;
    }

    function _unreferenced() internal virtual {
        uint y = 2;
    }
}
"""
    tmp = tmp_path / "A.sol"
    tmp.write_text(src, encoding="utf-8")
    idx = FunctionIndex.build(tmp_path)
    ev = resolve_solidity(idx, idx.by_name("_unreferenced")[0])
    assert ev.verdict == ReachabilityVerdict.UNKNOWN


def test_unknown_function_is_unknown(tmp_path: Path) -> None:
    idx = _index(tmp_path)
    assert resolve_solidity(idx, None).verdict == ReachabilityVerdict.UNKNOWN


def test_gated_public_is_reachable_and_marked_gated(tmp_path: Path) -> None:
    idx = _index(tmp_path)
    fn = idx.by_name("lockedWithdraw")[0]
    ev = resolve_solidity(idx, fn)
    assert ev.verdict == ReachabilityVerdict.REACHABLE
    assert ev.gated is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_reachability_solidity.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'web3guard.reachability.solidity'`.

- [ ] **Step 3: Implement the resolver**

Create `web3guard/reachability/solidity.py`:

```python
"""Custom Solidity reachability verdicts."""

from __future__ import annotations

from web3guard.reachability.solidity_index import FunctionIndex, FunctionInfo
from web3guard.reachability.types import ReachabilityEvidence, ReachabilityVerdict

_ENTRY_VISIBILITIES = {"public", "external"}
_SPECIAL_ENTRY_NAMES = {"fallback", "receive"}
_MAX_HOPS = 64


def resolve_solidity(
    index: FunctionIndex, fn: FunctionInfo | None
) -> ReachabilityEvidence:
    if fn is None:
        return ReachabilityEvidence(
            ReachabilityVerdict.UNKNOWN, "solidity-parser",
            detail="function not found in index",
        )
    if fn.is_constructor or fn.name in _SPECIAL_ENTRY_NAMES \
            or fn.visibility in _ENTRY_VISIBILITIES:
        label = fn.visibility or ("constructor" if fn.is_constructor else fn.name)
        return ReachabilityEvidence(
            ReachabilityVerdict.REACHABLE, "solidity-parser",
            function=fn.name, entrypoint=fn.name, gated=fn.gated,
            detail=f"external entrypoint ({label})",
        )
    if fn.visibility not in ("internal", "private"):
        return ReachabilityEvidence(
            ReachabilityVerdict.UNKNOWN, "solidity-parser",
            function=fn.name, detail="unknown visibility",
        )
    found = _bfs(index, fn)
    if found is not None:
        entry, path = found
        return ReachabilityEvidence(
            ReachabilityVerdict.REACHABLE, "solidity-parser",
            function=fn.name, entrypoint=entry, path=path, gated=fn.gated,
            detail="reverse call path reaches an external entrypoint",
        )
    if fn.virtual or fn.abstract:
        return ReachabilityEvidence(
            ReachabilityVerdict.UNKNOWN, "solidity-parser",
            function=fn.name,
            detail="virtual or abstract member; a derived contract may expose it",
        )
    if not index.references(fn.name):
        return ReachabilityEvidence(
            ReachabilityVerdict.NOT_REACHABLE, "solidity-parser",
            function=fn.name,
            detail="identifier referenced nowhere in user code",
        )
    return ReachabilityEvidence(
        ReachabilityVerdict.NOT_REACHABLE, "solidity-parser",
        function=fn.name,
        detail="no reverse call path reaches an external entrypoint",
    )


def _bfs(index: FunctionIndex, fn: FunctionInfo) -> tuple[str, tuple[str, ...]] | None:
    frontier: list[tuple[FunctionInfo, tuple[str, ...]]] = [
        (start, (start.name,)) for start in index.by_name(fn.name)
    ]
    visited: set[tuple[str, str, str]] = set()
    for _ in range(_MAX_HOPS):
        if not frontier:
            return None
        nxt: list[tuple[FunctionInfo, tuple[str, ...]]] = []
        for current, path in frontier:
            key = (current.file, current.contract, current.name)
            if key in visited:
                continue
            visited.add(key)
            if current.is_constructor \
                    or current.name in _SPECIAL_ENTRY_NAMES \
                    or current.visibility in _ENTRY_VISIBILITIES:
                return current.name, path
            for caller in index.references(current.name):
                nxt.append((caller, path + (caller.name,)))
        frontier = nxt
    return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_reachability_solidity.py -v`
Expected: PASS (7 passed).

- [ ] **Step 5: Commit**

```bash
git add web3guard/reachability/solidity.py tests/test_reachability_solidity.py
git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" \
  commit -m "feat(reachability): custom Solidity verdict resolver"
```

---

### Task 3: Visibility resolvers and analyzer router

**Files:**
- Create: `web3guard/reachability/visibility.py`
- Create: `web3guard/reachability/analyzer.py`
- Modify: `web3guard/reachability/__init__.py`
- Test: `tests/test_reachability_analyzer.py`

**Interfaces:**
- Consumes: Task 1 and Task 2 exports, plus `web3guard.scanner.Finding`.
- Produces:
  - `resolve_visibility(language: str, source: str, function: str) -> ReachabilityEvidence`.
  - `ReachabilityAnalyzer(target_path, *, use_slither=False, slither_backend=None)` with `.classify(finding) -> ReachabilityEvidence`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_reachability_analyzer.py`:

```python
"""Tests for the reachability analyzer router and visibility checks."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.reachability.analyzer import ReachabilityAnalyzer  # noqa: E402
from web3guard.reachability.types import ReachabilityVerdict  # noqa: E402
from web3guard.reachability.visibility import resolve_visibility  # noqa: E402
from web3guard.scanner import Finding  # noqa: E402


def test_vyper_external_is_reachable() -> None:
    src = "@external\ndef withdraw():\n    pass\n"
    ev = resolve_visibility("vyper", src, "withdraw")
    assert ev.verdict == ReachabilityVerdict.REACHABLE


def test_vyper_internal_without_caller_is_unknown() -> None:
    src = "@internal\ndef helper():\n    pass\n"
    ev = resolve_visibility("vyper", src, "helper")
    assert ev.verdict == ReachabilityVerdict.UNKNOWN


def test_vyper_internal_with_self_call_is_reachable() -> None:
    src = "@external\ndef withdraw():\n    self.helper()\n\n@internal\ndef helper():\n    pass\n"
    ev = resolve_visibility("vyper", src, "helper")
    assert ev.verdict == ReachabilityVerdict.REACHABLE


def test_move_entry_is_reachable() -> None:
    src = "module m { entry fun withdraw() { } }"
    ev = resolve_visibility("move", src, "withdraw")
    assert ev.verdict == ReachabilityVerdict.REACHABLE


def test_move_private_is_unknown() -> None:
    src = "module m { fun helper() { } }"
    ev = resolve_visibility("move", src, "helper")
    assert ev.verdict == ReachabilityVerdict.UNKNOWN


def test_cairo_external_is_reachable() -> None:
    src = "#[external]\nfn withdraw() {\n}\n"
    ev = resolve_visibility("cairo", src, "withdraw")
    assert ev.verdict == ReachabilityVerdict.REACHABLE


def test_cairo_plain_fn_is_unknown() -> None:
    src = "fn helper() {\n}\n"
    ev = resolve_visibility("cairo", src, "helper")
    assert ev.verdict == ReachabilityVerdict.UNKNOWN


def test_clarity_public_is_reachable() -> None:
    src = "(define-public (withdraw) (ok true))"
    ev = resolve_visibility("clarity", src, "withdraw")
    assert ev.verdict == ReachabilityVerdict.REACHABLE


def test_non_solidity_never_rejects() -> None:
    for lang, src, name in (
        ("vyper", "@internal\ndef helper():\n    pass\n", "helper"),
        ("move", "module m { fun helper() { } }", "helper"),
        ("cairo", "fn helper() {\n}\n", "helper"),
        ("clarity", "(define-private (helper) (ok true))", "helper"),
    ):
        assert resolve_visibility(lang, src, name).verdict != ReachabilityVerdict.NOT_REACHABLE


def test_analyzer_routes_solidity(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Vault {\n"
        "    mapping(address => uint) public balances;\n"
        "    function _dead() internal { balances[msg.sender] = 1; }\n"
        "    function deposit() external payable { balances[msg.sender] += msg.value; }\n"
        "}\n",
        encoding="utf-8",
    )
    analyzer = ReachabilityAnalyzer(tmp_path)
    finding = Finding(target="x", language="solidity", file="Vault.sol",
                      function="_dead", line_hint="4")
    assert analyzer.classify(finding).verdict == ReachabilityVerdict.NOT_REACHABLE


def test_analyzer_unknown_language_is_unknown(tmp_path: Path) -> None:
    analyzer = ReachabilityAnalyzer(tmp_path)
    finding = Finding(target="x", language="func", file="vault.fc", function="f")
    assert analyzer.classify(finding).verdict == ReachabilityVerdict.UNKNOWN


def test_analyzer_never_raises_on_bad_file(tmp_path: Path) -> None:
    analyzer = ReachabilityAnalyzer(tmp_path)
    finding = Finding(target="x", language="solidity", file="missing.sol",
                      function="whatever")
    assert analyzer.classify(finding).verdict == ReachabilityVerdict.UNKNOWN


class _FakeSlither:
    def __init__(self, verdict) -> None:
        self._verdict = verdict

    def verdict(self, fn):  # noqa: ANN001
        return self._verdict


def test_corroboration_rescues_not_reachable(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Vault {\n"
        "    function _dead() internal { uint x = 1; }\n"
        "}\n",
        encoding="utf-8",
    )
    analyzer = ReachabilityAnalyzer(
        tmp_path, use_slither=False, slither_backend=_FakeSlither(ReachabilityVerdict.REACHABLE)
    )
    finding = Finding(target="x", language="solidity", file="Vault.sol",
                      function="_dead", line_hint="3")
    ev = analyzer.classify(finding)
    assert ev.verdict == ReachabilityVerdict.REACHABLE
    assert ev.backend == "slither"


def test_corroboration_strengthens_not_reachable(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Vault {\n"
        "    function _dead() internal { uint x = 1; }\n"
        "}\n",
        encoding="utf-8",
    )
    analyzer = ReachabilityAnalyzer(
        tmp_path, use_slither=False,
        slither_backend=_FakeSlither(ReachabilityVerdict.NOT_REACHABLE),
    )
    finding = Finding(target="x", language="solidity", file="Vault.sol",
                      function="_dead", line_hint="3")
    ev = analyzer.classify(finding)
    assert ev.verdict == ReachabilityVerdict.NOT_REACHABLE
    assert ev.backend == "slither"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_reachability_analyzer.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'web3guard.reachability.analyzer'`.

- [ ] **Step 3: Implement the visibility resolver**

Create `web3guard/reachability/visibility.py`:

```python
"""Cheap visibility-based reachability for non-Solidity languages."""

from __future__ import annotations

import re

from web3guard.reachability.types import ReachabilityEvidence, ReachabilityVerdict


def resolve_visibility(
    language: str, source: str, function: str
) -> ReachabilityEvidence:
    lang = language.lower()
    if lang == "vyper":
        return _resolve_vyper(source, function)
    if lang == "move":
        return _resolve_move(source, function)
    if lang == "cairo":
        return _resolve_cairo(source, function)
    if lang == "clarity":
        return _resolve_clarity(source, function)
    return _unknown(f"no visibility check for {language}")


def _reachable(detail: str) -> ReachabilityEvidence:
    return ReachabilityEvidence(
        ReachabilityVerdict.REACHABLE, "visibility", detail=detail
    )


def _unknown(detail: str) -> ReachabilityEvidence:
    return ReachabilityEvidence(
        ReachabilityVerdict.UNKNOWN, "visibility", detail=detail
    )


def _preceding_decorators(lines: list[str], idx: int) -> list[str]:
    out: list[str] = []
    j = idx - 1
    while j >= 0:
        stripped = lines[j].strip()
        if stripped.startswith("@"):
            out.append(stripped[1:].split("(")[0].strip())
            j -= 1
        elif stripped == "":
            j -= 1
        else:
            break
    return out


def _resolve_vyper(source: str, function: str) -> ReachabilityEvidence:
    if not function:
        return _unknown("no function name")
    lines = source.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^\s*def\s+([a-z_][a-z0-9_]*)\s*\(", line)
        if not m or m.group(1) != function:
            continue
        decorators = _preceding_decorators(lines, i)
        if any(d in ("external", "public") for d in decorators):
            return _reachable(f"@{decorators[0]} {function}")
        if any(d in ("internal", "private") for d in decorators):
            if re.search(rf"self\.{re.escape(function)}\s*\(", source):
                return _reachable(f"internal {function} reached via self-call")
            return _unknown(f"internal {function} with no visible caller")
        return _unknown("no visibility decorator")
    return _unknown("function not found")


def _resolve_move(source: str, function: str) -> ReachabilityEvidence:
    if not function:
        return _unknown("no function name")
    if re.search(rf"\b(?:public\s+)?entry\s+fun\s+{re.escape(function)}\b", source):
        return _reachable(f"entry fun {function}")
    if re.search(rf"\bpublic\s+fun\s+{re.escape(function)}\b", source):
        return _reachable(f"public fun {function}")
    return _unknown(f"non-public fun {function}")


def _resolve_cairo(source: str, function: str) -> ReachabilityEvidence:
    if not function:
        return _unknown("no function name")
    for m in re.finditer(rf"\bfn\s+{re.escape(function)}\b", source):
        window = source[max(0, m.start() - 200):m.start()]
        if "#[external]" in window or "#[abi" in window:
            return _reachable(f"external fn {function}")
    return _unknown(f"non-external fn {function}")


def _resolve_clarity(source: str, function: str) -> ReachabilityEvidence:
    if not function:
        return _unknown("no function name")
    if re.search(rf"\(define-public\s*\(\s*{re.escape(function)}\b", source):
        return _reachable(f"define-public {function}")
    return _unknown(f"non-public define {function}")
```

- [ ] **Step 4: Implement the analyzer router**

Create `web3guard/reachability/analyzer.py`:

```python
"""Route findings to the right reachability backend."""

from __future__ import annotations

import re
from pathlib import Path

from web3guard.reachability.solidity import resolve_solidity
from web3guard.reachability.types import ReachabilityEvidence, ReachabilityVerdict
from web3guard.reachability.visibility import resolve_visibility

_VISIBILITY_LANGS = {"vyper", "move", "cairo", "clarity"}


def _first_line(hint: str) -> int:
    m = re.search(r"\d+", hint or "")
    return int(m.group()) if m else 0


class ReachabilityAnalyzer:
    def __init__(
        self,
        target_path: Path,
        *,
        use_slither: bool = False,
        slither_backend: object | None = None,
    ) -> None:
        self._target = Path(target_path)
        self._use_slither = use_slither
        self._slither = slither_backend
        self._index = None
        self._index_failed = False

    def classify(self, finding: object) -> ReachabilityEvidence:
        language = str(getattr(finding, "language", "") or "").lower()
        try:
            if language == "solidity":
                return self._classify_solidity(finding)
            if language in _VISIBILITY_LANGS:
                return self._classify_visibility(language, finding)
        except Exception:  # noqa: BLE001
            pass
        return ReachabilityEvidence(
            ReachabilityVerdict.UNKNOWN, "analyzer",
            detail=f"no reachability backend for {language or 'unknown'}",
        )

    def _get_index(self):  # noqa: ANN202
        if self._index is None and not self._index_failed:
            try:
                from web3guard.reachability.solidity_index import FunctionIndex

                self._index = FunctionIndex.build(self._target)
            except Exception:  # noqa: BLE001
                self._index_failed = True
        return self._index

    def _get_slither(self):  # noqa: ANN202
        if self._slither is not None:
            return self._slither
        if not self._use_slither:
            return None
        from web3guard.reachability.slither_backend import SlitherBackend

        self._slither = SlitherBackend(self._target)
        return self._slither

    def _classify_solidity(self, finding: object) -> ReachabilityEvidence:
        index = self._get_index()
        if index is None:
            return ReachabilityEvidence(
                ReachabilityVerdict.UNKNOWN, "solidity-parser",
                detail="function index build failed",
            )
        fn = index.enclosing(
            str(getattr(finding, "file", "") or ""),
            str(getattr(finding, "function", "") or ""),
            _first_line(str(getattr(finding, "line_hint", "") or "")),
        )
        evidence = resolve_solidity(index, fn)
        if fn is None:
            return evidence
        slither = self._get_slither()
        if slither is None:
            return evidence
        return _corroborate(evidence, slither, fn)

    def _classify_visibility(
        self, language: str, finding: object
    ) -> ReachabilityEvidence:
        source = self._read_source(str(getattr(finding, "file", "") or ""))
        if source is None:
            return ReachabilityEvidence(
                ReachabilityVerdict.UNKNOWN, "visibility",
                detail="source file not found",
            )
        return resolve_visibility(
            language, source, str(getattr(finding, "function", "") or "")
        )

    def _read_source(self, rel: str) -> str | None:
        if not rel:
            return None
        candidate = self._target / rel
        if candidate.is_file():
            try:
                return candidate.read_text(errors="ignore")
            except OSError:
                return None
        base = Path(rel).name
        for path in self._target.rglob(base):
            if path.is_file():
                try:
                    return path.read_text(errors="ignore")
                except OSError:
                    return None
        return None


def _corroborate(evidence: ReachabilityEvidence, slither: object, fn: object) -> ReachabilityEvidence:
    try:
        verdict = slither.verdict(fn)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return evidence
    if verdict is None:
        return evidence
    if verdict == ReachabilityVerdict.REACHABLE:
        return ReachabilityEvidence(
            ReachabilityVerdict.REACHABLE, "slither",
            function=evidence.function, entrypoint=evidence.entrypoint or evidence.function,
            gated=evidence.gated, detail="Slither sees an external caller",
        )
    if verdict == ReachabilityVerdict.NOT_REACHABLE \
            and evidence.verdict == ReachabilityVerdict.NOT_REACHABLE:
        return ReachabilityEvidence(
            ReachabilityVerdict.NOT_REACHABLE, "slither",
            function=evidence.function, detail="custom parser and Slither agree",
        )
    return evidence
```

- [ ] **Step 5: Export the analyzer**

Modify `web3guard/reachability/__init__.py` to:

```python
"""External-reachability pre-filter (B1.2)."""

from web3guard.reachability.analyzer import ReachabilityAnalyzer
from web3guard.reachability.types import ReachabilityEvidence, ReachabilityVerdict

__all__ = ["ReachabilityAnalyzer", "ReachabilityEvidence", "ReachabilityVerdict"]
```

- [ ] **Step 6: Run test to verify it passes**

Run: `python3 -m pytest tests/test_reachability_analyzer.py -v`
Expected: PASS (14 passed).

- [ ] **Step 7: Commit**

```bash
git add web3guard/reachability/visibility.py web3guard/reachability/analyzer.py \
  web3guard/reachability/__init__.py tests/test_reachability_analyzer.py
git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" \
  commit -m "feat(reachability): analyzer router and visibility checks"
```

---

### Task 4: Optional Slither backend

**Files:**
- Create: `web3guard/reachability/slither_backend.py`
- Test: `tests/test_reachability_slither.py`

**Interfaces:**
- Consumes: `FunctionInfo`, `ReachabilityVerdict`.
- Produces: `SlitherBackend(target_path)` with `.verdict(fn) -> ReachabilityVerdict | None`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_reachability_slither.py`:

```python
"""Tests for the optional Slither reachability backend."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.reachability.analyzer import ReachabilityAnalyzer  # noqa: E402
from web3guard.reachability.slither_backend import SlitherBackend  # noqa: E402
from web3guard.reachability.solidity_index import FunctionInfo  # noqa: E402


def test_backend_returns_none_without_slither(tmp_path: Path) -> None:
    backend = SlitherBackend(tmp_path)
    fn = FunctionInfo(name="f", contract="C", file="C.sol", visibility="internal")
    assert backend.verdict(fn) in (None,)


def test_analyzer_does_not_construct_backend_when_disabled(tmp_path: Path) -> None:
    analyzer = ReachabilityAnalyzer(tmp_path, use_slither=False)
    assert analyzer._get_slither() is None


def test_analyzer_constructs_backend_when_enabled(tmp_path: Path) -> None:
    analyzer = ReachabilityAnalyzer(tmp_path, use_slither=True)
    backend = analyzer._get_slither()
    assert isinstance(backend, SlitherBackend)
    assert analyzer._get_slither() is backend
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_reachability_slither.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'web3guard.reachability.slither_backend'`.

- [ ] **Step 3: Implement the backend**

Create `web3guard/reachability/slither_backend.py`:

```python
"""Optional Slither corroboration for Solidity reachability."""

from __future__ import annotations

from pathlib import Path

from web3guard.reachability.solidity_index import FunctionInfo
from web3guard.reachability.types import ReachabilityVerdict


def _full_name(function: object) -> str:
    return getattr(function, "full_name", None) or getattr(function, "name", "")


class SlitherBackend:
    def __init__(self, target_path: Path) -> None:
        self._target = Path(target_path)
        self._result = None
        self._loaded = False

    def _load(self):  # noqa: ANN202
        if self._loaded:
            return self._result
        self._loaded = True
        try:
            from slither import Slither

            self._result = Slither(str(self._target))
        except Exception:  # noqa: BLE001
            self._result = None
        return self._result

    def verdict(self, fn: FunctionInfo) -> ReachabilityVerdict | None:
        instance = self._load()
        if instance is None:
            return None
        try:
            reachable = self._reachable(instance)
            matches = [
                f for c in instance.contracts for f in c.functions if f.name == fn.name
            ]
            if not matches:
                return None
            if any(_full_name(f) in reachable for f in matches):
                return ReachabilityVerdict.REACHABLE
            if all(not c.is_abstract for c in instance.contracts):
                return ReachabilityVerdict.NOT_REACHABLE
            return None
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _reachable(instance: object) -> set[str]:
        stack = [
            f for c in instance.contracts for f in c.functions_entry_points  # type: ignore[attr-defined]
        ]
        seen: set[str] = set()
        while stack:
            function = stack.pop()
            name = _full_name(function)
            if name in seen:
                continue
            seen.add(name)
            try:
                stack.extend(function.all_internal_calls())
            except Exception:  # noqa: BLE001
                continue
        return seen
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_reachability_slither.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add web3guard/reachability/slither_backend.py tests/test_reachability_slither.py
git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" \
  commit -m "feat(reachability): optional Slither corroboration backend"
```

---

### Task 5: Scanner gating

**Files:**
- Modify: `web3guard/scanner.py`
- Test: `tests/test_reachability_scanner.py`

**Interfaces:**
- Consumes: `ReachabilityAnalyzer`, `ReachabilityVerdict`.
- Produces: `Scanner._apply_reachability(reachability, finding) -> bool` (True = proceed, False = rejected); `_analyze_chunk(..., reachability=None)`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_reachability_scanner.py`:

```python
"""Scanner integration tests for the reachability pre-filter."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.scanner import Finding, Scanner  # noqa: E402


class _Resp:
    def __init__(self, content: str) -> None:
        self.content = content


class _Cost:
    def summary(self) -> dict[str, object]:
        return {"total_cost_usd": 0.0}


class _NamedFunctionAI:
    def __init__(self, function: str, poc: str) -> None:
        self._function = function
        self._poc = poc
        self.chat_calls: list[dict] = []

    def chat(self, system: str, user: str, **kwargs):
        self.chat_calls.append({"system": system, "user": user, "kwargs": kwargs})
        if kwargs.get("role", "analysis") == "exploit":
            return _Resp(f"```solidity\n{self._poc}\n```")
        return _Resp(json.dumps({
            "status": "vulnerable",
            "category": "reentrancy",
            "severity": "HIGH",
            "confidence": 0.9,
            "function": self._function,
            "description": "reentrancy via external call",
            "reasoning": "call before state update",
            "line_hint": "7-9",
        }))

    def cost_tracker(self) -> _Cost:
        return _Cost()


class _FakeSandbox:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def write_and_run(self, code: str, fingerprint: str, timeout: int = 90):
        self.calls.append((code, fingerprint))
        return True, "impact_gain: 100\nPASSED"


def _poc() -> str:
    return (
        "pragma solidity ^0.8.0;\n"
        'import "forge-std/Test.sol";\n'
        "contract ExploitTest is Test {\n"
        "    function test_exploit() public {\n"
        "        uint before = 100;\n"
        "        uint after = 0;\n"
        "        assert(after < before);\n"
        '        emit log_named_uint("impact_gain", before - after);\n'
        "    }\n"
        "}\n"
    )


_UNREACHABLE = """\
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint) public balances;

    function _helper() internal {
        balances[msg.sender] = 0;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
"""


def _write(tmp_path: Path) -> Path:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "Vault.sol").write_text(_UNREACHABLE, encoding="utf-8")
    return project


def test_unreachable_finding_skips_poc_and_is_rejected(tmp_path: Path, monkeypatch):
    from web3guard import sandbox as sandbox_mod

    fake = _FakeSandbox()
    monkeypatch.setattr(sandbox_mod, "create_sandbox", lambda *a, **k: fake)
    project = _write(tmp_path)
    scanner = Scanner(
        config={"enable_ai_analysis": True, "enable_discovery": False,
                "enable_exploit": True, "max_exploit_attempts": 2,
                "enable_reachability": True},
        workdir=tmp_path / "work",
        ai_client=_NamedFunctionAI("_helper", _poc()),
    )
    result = scanner.scan([str(project) + "|max"])
    findings = result.targets[0].findings
    rejected = [f for f in findings if f.status == "REJECTED"]
    assert rejected, [f.status for f in findings]
    assert fake.calls == []
    assert rejected[0].metadata["reachability"]["verdict"] == "not_reachable"
    assert rejected[0].metadata["rejection_reason"] == "not externally reachable"


def test_reachable_finding_still_runs_poc(tmp_path: Path, monkeypatch):
    from web3guard import sandbox as sandbox_mod

    fake = _FakeSandbox()
    monkeypatch.setattr(sandbox_mod, "create_sandbox", lambda *a, **k: fake)
    project = _write(tmp_path)
    scanner = Scanner(
        config={"enable_ai_analysis": True, "enable_discovery": False,
                "enable_exploit": True, "max_exploit_attempts": 2,
                "enable_reachability": True, "enable_differential": False},
        workdir=tmp_path / "work",
        ai_client=_NamedFunctionAI("deposit", _poc()),
    )
    result = scanner.scan([str(project) + "|max"])
    findings = result.targets[0].findings
    assert findings and fake.calls != []
    assert findings[0].metadata["reachability"]["verdict"] == "reachable"


def test_discovery_unreachable_finding_is_rejected(tmp_path: Path, monkeypatch):
    project = _write(tmp_path)
    scanner = Scanner(
        config={"enable_discovery": True, "enable_ai_analysis": False,
                "enable_exploit": False, "enable_reachability": True,
                "use_ai_planning": False, "enable_attack_sequence_brainstorm": False,
                "enable_role_map": False, "enable_secret_scan": False},
        workdir=tmp_path / "work",
    )
    fake = Finding(target="x", language="solidity", file="Vault.sol",
                   function="_helper", category="reentrancy", severity="HIGH",
                   description="reentrancy", line_hint="7-9")
    monkeypatch.setattr(scanner, "_run_discovery", lambda *a, **k: [fake])
    result = scanner._scan_one(str(project), 100000, min_severity="LOW")
    rejected = [f for f in result.findings if f.status == "REJECTED"]
    assert rejected
    assert rejected[0].metadata["reachability"]["verdict"] == "not_reachable"


def test_reachability_disabled_leaves_finding_untouched(tmp_path: Path, monkeypatch):
    from web3guard import sandbox as sandbox_mod

    fake = _FakeSandbox()
    monkeypatch.setattr(sandbox_mod, "create_sandbox", lambda *a, **k: fake)
    project = _write(tmp_path)
    scanner = Scanner(
        config={"enable_ai_analysis": True, "enable_discovery": False,
                "enable_exploit": True, "max_exploit_attempts": 1,
                "enable_reachability": False},
        workdir=tmp_path / "work",
        ai_client=_NamedFunctionAI("_helper", _poc()),
    )
    result = scanner.scan([str(project) + "|max"])
    findings = result.targets[0].findings
    assert findings and fake.calls != []
    assert "reachability" not in findings[0].metadata
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_reachability_scanner.py -v`
Expected: FAIL — the unreachable finding is not rejected (no `reachability` metadata, sandbox is called).

- [ ] **Step 3: Add config flags and the import**

In `web3guard/scanner.py`, add to `DEFAULT_CONFIG` immediately after `"enable_differential": True,`:

```python
    "enable_reachability": True,
    "reachability_use_slither": True,
```

Add near the other `web3guard` imports (after `from web3guard.utils.vuln_catalog import get_catalog`):

```python
from web3guard.reachability import ReachabilityAnalyzer, ReachabilityVerdict
```

- [ ] **Step 4: Build the analyzer in `_scan_one`**

In `web3guard/scanner.py`, immediately after the line `tr.attack_sequences = {}` (inside `_scan_one`), add:

```python
        reachability = None
        if self.config.get("enable_reachability", True):
            reachability = ReachabilityAnalyzer(
                target_path,
                use_slither=bool(self.config.get("reachability_use_slither", True)),
            )
```

- [ ] **Step 5: Gate discovery findings**

In `_scan_one`, change the discovery loop body so the classification runs before the finding is kept:

```python
            if self.config.get("enable_discovery", True):
                for finding in self._run_discovery(target_path, target, adapter.language):
                    if finding.fingerprint in seen_fps:
                        continue
                    if not self._severity_at_least(finding.severity, min_severity):
                        continue
                    if reachability is not None:
                        self._apply_reachability(reachability, finding)
                    seen_fps.add(finding.fingerprint)
                    tr.findings.append(finding)
```

- [ ] **Step 6: Gate AI findings before exploit generation**

Change the `_analyze_chunk` call in `_scan_one` to pass the analyzer:

```python
                    finding = self._analyze_chunk(
                        adapter, ch, target_path, target, reachability=reachability
                    )
```

Change the `_analyze_chunk` signature:

```python
    def _analyze_chunk(
        self,
        adapter: LanguageAdapter,
        chunk: Any,
        target_path: Path,
        target_url: str,
        *,
        reachability: ReachabilityAnalyzer | None = None,
    ) -> Finding | None:
```

After `finding.fingerprint = self._fingerprint(finding)` and before `# 5. Generate a PoC if enabled`, insert:

```python
        if reachability is not None and not self._apply_reachability(reachability, finding):
            return finding
```

- [ ] **Step 7: Add the `_apply_reachability` helper**

Add this method to `Scanner` (place it directly above `_generate_poc`):

```python
    def _apply_reachability(
        self, reachability: ReachabilityAnalyzer, finding: Finding
    ) -> bool:
        """Annotate ``finding`` with its reachability verdict.

        Returns True when the finding should proceed (reachable or
        unknown) and False when it was definitively not reachable and has
        been rejected.
        """
        try:
            evidence = reachability.classify(finding)
        except Exception as e:  # noqa: BLE001
            LOGGER.warning("reachability classification failed: %s", e)
            return True
        finding.metadata["reachability"] = evidence.to_metadata()
        if evidence.verdict != ReachabilityVerdict.NOT_REACHABLE:
            return True
        finding.status = "REJECTED"
        finding.metadata["rejection_reason"] = "not externally reachable"
        return False
```

- [ ] **Step 8: Run the new tests to verify they pass**

Run: `python3 -m pytest tests/test_reachability_scanner.py -v`
Expected: PASS (4 passed).

- [ ] **Step 9: Run the existing confirmation tests for regressions**

Run: `python3 -m pytest tests/test_exploit_confirmation.py tests/test_exploit_system_prompt.py tests/test_fork_support.py -v`
Expected: PASS (all previously-passing tests still pass).

- [ ] **Step 10: Commit**

```bash
git add web3guard/scanner.py tests/test_reachability_scanner.py
git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" \
  commit -m "feat(scanner): gate findings on external reachability"
```

---

### Task 6: Fixtures, end-to-end test, and full verification

**Files:**
- Create: `test_contracts/reachability/UnreachableReentrancy.sol`
- Create: `test_contracts/reachability/InheritedReentrancy.sol`
- Test: `tests/test_reachability_e2e.py`

**Interfaces:**
- Consumes: `ReachabilityAnalyzer`, `_detect_solidity`, `Finding`.
- Produces: a regression proving a *present* unreachable pattern is rejected while an inherited reachable one is kept.

- [ ] **Step 1: Write the failing test**

Create `tests/test_reachability_e2e.py`:

```python
"""End-to-end reachability: present vs externally reachable."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.discovery.static_analyzer import _detect_solidity  # noqa: E402
from web3guard.reachability.analyzer import ReachabilityAnalyzer  # noqa: E402
from web3guard.reachability.types import ReachabilityVerdict  # noqa: E402
from web3guard.scanner import Finding  # noqa: E402

_FIXTURES = PROJECT_ROOT / "test_contracts" / "reachability"


def test_static_analyzer_flags_both_patterns() -> None:
    for name in ("UnreachableReentrancy.sol", "InheritedReentrancy.sol"):
        text = (_FIXTURES / name).read_text(encoding="utf-8")
        issues = _detect_solidity(text, name)
        assert any(i.category == "reentrancy" for i in issues), name


def test_unreachable_fixture_is_not_reachable() -> None:
    analyzer = ReachabilityAnalyzer(_FIXTURES)
    finding = Finding(target="x", language="solidity",
                      file="UnreachableReentrancy.sol",
                      function="_withdrawInternal", line_hint="6-11")
    assert analyzer.classify(finding).verdict == ReachabilityVerdict.NOT_REACHABLE


def test_inherited_fixture_is_reachable() -> None:
    analyzer = ReachabilityAnalyzer(_FIXTURES)
    finding = Finding(target="x", language="solidity",
                      file="InheritedReentrancy.sol",
                      function="_withdraw", line_hint="5-10")
    ev = analyzer.classify(finding)
    assert ev.verdict == ReachabilityVerdict.REACHABLE
    assert ev.entrypoint == "withdraw"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_reachability_e2e.py -v`
Expected: FAIL — the fixture files do not exist yet.

- [ ] **Step 3: Create the fixtures**

Create `test_contracts/reachability/UnreachableReentrancy.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UnreachableReentrancy {
    mapping(address => uint256) public balances;

    function _withdrawInternal() internal {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        balances[msg.sender] = 0;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
```

Create `test_contracts/reachability/InheritedReentrancy.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BaseVault {
    mapping(address => uint256) public balances;

    function _withdraw() internal {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        balances[msg.sender] = 0;
    }
}

contract InheritedReentrancy is BaseVault {
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        _withdraw();
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_reachability_e2e.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Run the full suite without forge**

Run: `python3 -m pytest -q`
Expected: all previously-passing tests pass plus the new reachability tests; skips unchanged.

- [ ] **Step 6: Run the full suite with forge**

Run: `PATH="$HOME/.foundry/bin:$PATH" python3 -m pytest -q`
Expected: all pass (forge-backed tests now run); no new failures.

- [ ] **Step 7: Lint the new and changed files**

Run: `ruff check web3guard/reachability web3guard/scanner.py tests/test_reachability_*.py`
Expected: `All checks passed!`

- [ ] **Step 8: Commit**

```bash
git add test_contracts/reachability tests/test_reachability_e2e.py
git -c user.name="genesisaugustine98-web" -c user.email="genesisaugustine98@gmail.com" \
  commit -m "test(reachability): end-to-end present-vs-reachable fixtures"
```

- [ ] **Step 9: Push and verify CI**

```bash
GIT_ASKPASS=/tmp/opencode/git-askpass.sh git -c credential.helper= push origin main
GH_TOKEN="$(cat /tmp/opencode/gh_pat)" gh run list --repo genesisaugustine98-web/web3guard-bounty-hunter --limit 1
python3 /tmp/opencode/poll_run.py <run_id> 900
```

Expected: the run reports `completed success`.

---

## Self-Review

**Spec coverage:**
- Role = static pre-filter, annotate + definitive reject: Task 5 (`_apply_reachability`).
- Solidity-first scope with generic fallback: Tasks 1–3, 5.
- Behavior (reject only `not_reachable`; unknown untouched): Task 5.
- Hybrid custom parser + optional Slither: Tasks 1–4.
- `types.py`, `solidity_index.py`, `solidity.py`, `slither_backend.py`, `analyzer.py`: Tasks 1, 2, 4, 3.
- Verdict rules incl. dead code, uncalled-closure, virtual/abstract, gated, inheritance: Task 2 tests.
- Non-Solidity never rejects: Task 3 tests.
- Config flags, AI path skip, discovery path, reports stay traceable: Task 5.
- Fixtures + e2e + full verification: Task 6.

**Placeholder scan:** no TBD/TODO; every code step carries a complete body or exact edit.

**Type consistency:** `ReachabilityVerdict`/`ReachabilityEvidence` (Task 1) are used verbatim in Tasks 2–5. `FunctionIndex.enclosing`/`references`/`by_name` signatures match their callers. `resolve_solidity(index, fn)` matches. `ReachabilityAnalyzer.classify(finding)` matches `_apply_reachability`. `SlitherBackend.verdict(fn)` matches `_corroborate`.

**Known limitation carried from the spec:** the custom parser errs to `unknown`; Slither never alone yields `not_reachable`.

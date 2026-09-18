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
    def build(cls, target_path: Path) -> FunctionIndex:
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

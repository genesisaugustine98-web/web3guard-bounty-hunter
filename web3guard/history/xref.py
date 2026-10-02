"""Cross-file reference map for the history engine.

The old verdict layer only scanned files named by the audit report, so a
vulnerability that moved to a different file was declared FIXED without
the new file ever being examined. This module builds a lightweight
reference map per version:

- **imports**: which files each Solidity file pulls in (resolved to
  repo-relative paths where possible);
- **inheritance**: ``contract X is Y, Z`` edges;
- **calls**: dotted external-call targets (``Vault.withdraw(``,
  ``token.transfer(``) so callers of a moved function can be found;
- **definitions**: which file defines each contract and each function.

:func:`XRefMap.locate_function` is the key entry point: given a function
name, hint paths from the audit report, and (when available) the
rename-resistant fingerprint of the function's body from the previous
version, it finds where that function actually lives *in this version* —
following renames, moves between files, and file renames. Verdicts are
then computed against the code's real location, not its old address.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from web3guard.history.diff import (
    extract_solidity_functions,
    file_content_at,
    list_files_at,
)
from web3guard.history.normalize import (
    canonicalize_function,
    similarity,
    statement_multiset,
)

_IMPORT_RE = re.compile(
    r"""(?mx)
    ^\s*import\s+
    (?:
        "(?P<path1>[^"]+)"\s*;                        # import "./Vault.sol";
      | \{(?P<names>[^}]*)\}\s*from\s*"(?P<path2>[^"]+)"\s*;  # import {A} from "...";
      | \*\s*as\s+[A-Za-z_][A-Za-z0-9_]*\s*from\s*"(?P<path3>[^"]+)"\s*;  # import * as NS from "...";
    )
    """
)
_CONTRACT_RE = re.compile(
    r"(?m)^\s*(?:abstract\s+)?contract\s+([A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?:is\s+([A-Za-z_][A-Za-z0-9_,\s]+?))?\s*\{"
)
_DOTTED_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\.([a-z_][A-Za-z0-9_]*)\s*\(")
_NEW_RE = re.compile(r"\bnew\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")

#: Minimum canonical similarity for a fingerprint match to count as "the
#: same function under a new name". Deliberately high: a false relocation
#: is worse than admitting we lost track (which yields low confidence,
#: never a confident FIXED).
FINGERPRINT_THRESHOLD = 0.8


@dataclass
class FileRefs:
    """What one Solidity file references and defines."""

    path: str
    imports: list[str] = field(default_factory=list)  # resolved repo-relative paths
    raw_imports: list[str] = field(default_factory=list)  # as written in source
    contracts: dict[str, list[str]] = field(default_factory=dict)  # name -> bases
    functions: list[str] = field(default_factory=list)  # defined function names
    external_calls: list[str] = field(default_factory=list)  # "Target.fn" dotted calls


def _resolve_import(from_path: str, raw: str) -> str | None:
    """Resolve a relative import to a repo-relative path; None if external."""
    if not raw.startswith("."):
        return None  # bare specifier (@openzeppelin/..., URLs): not a repo file
    base = os.path.dirname(from_path)
    resolved = os.path.normpath(os.path.join(base, raw))
    return resolved.replace(os.sep, "/")


def _file_refs(path: str, source: str) -> FileRefs:
    refs = FileRefs(path=path)
    for m in _IMPORT_RE.finditer(source):
        raw = m.group("path1") or m.group("path2") or m.group("path3")
        if not raw:
            continue
        refs.raw_imports.append(raw)
        resolved = _resolve_import(path, raw)
        if resolved:
            refs.imports.append(resolved)
    for m in _CONTRACT_RE.finditer(source):
        name = m.group(1)
        bases = (
            [b.strip() for b in m.group(2).split(",") if b.strip()]
            if m.group(2)
            else []
        )
        refs.contracts[name] = bases
    functions = extract_solidity_functions(source)
    refs.functions = sorted(functions)
    calls: list[str] = []
    for m in _DOTTED_CALL_RE.finditer(source):
        target = f"{m.group(1)}.{m.group(2)}"
        if target not in calls:
            calls.append(target)
    for m in _NEW_RE.finditer(source):
        target = f"new {m.group(1)}"
        if target not in calls:
            calls.append(target)
    refs.external_calls = calls
    return refs


class XRefMap:
    """Cross-file reference map for one repo at one ref."""

    def __init__(self, files: dict[str, FileRefs]) -> None:
        self.files = files
        # (path, fn) -> raw body text. Attached after construction so the
        # map itself stays a cheap structural summary.
        self._bodies: dict[tuple[str, str], str] = {}
        self.contract_to_file: dict[str, str] = {}
        self.function_to_files: dict[str, list[str]] = {}
        for path, refs in files.items():
            for contract in refs.contracts:
                self.contract_to_file.setdefault(contract, path)
            for fn in refs.functions:
                self.function_to_files.setdefault(fn, []).append(path)

    def neighbors(self, path: str) -> dict[str, list[str]]:
        """Files related to ``path``: importers, imports, inheritance kin."""
        refs = self.files.get(path)
        if refs is None:
            return {"importers": [], "imports": [], "inheritance": []}
        importers = sorted(
            p for p, r in self.files.items() if path in r.imports
        )
        inheritance: list[str] = []
        own_contracts = set(refs.contracts)
        for _contract, bases in refs.contracts.items():
            for base in bases:  # parents: files defining our base contracts
                holder = self.contract_to_file.get(base)
                if holder and holder != path and holder not in inheritance:
                    inheritance.append(holder)
        for other_path, other_refs in self.files.items():  # children
            if other_path == path:
                continue
            for bases in other_refs.contracts.values():
                if own_contracts & set(bases) and other_path not in inheritance:
                    inheritance.append(other_path)
        return {
            "importers": importers,
            "imports": sorted(set(refs.imports)),
            "inheritance": sorted(inheritance),
        }

    def locate_function(
        self,
        name: str,
        hint_paths: list[str] | None = None,
        prev_body: str | None = None,
        prev_name: str | None = None,
        known_vuln_canonicals: set[str] | None = None,
    ) -> tuple[str | None, str | None, str]:
        """Find where a function lives in this version.

        Returns ``(path, name_at_version, how)`` where ``how`` is one of
        ``"hint"`` (found by name in a report-named file),
        ``"name-elsewhere"`` (found by name in another file),
        ``"fingerprint"`` (found by rename-resistant body match), or
        ``"missing"`` (not found anywhere).

        Search order is deliberate: the report's hint files first (a name
        match where the audit said the code was is the strongest signal),
        then any file by name, then an exact match against historically
        vulnerable canonical shapes (catches revert-to-old-shape), then
        the rename-resistant fingerprint across every file. A fingerprint
        match requires similarity >= :data:`FINGERPRINT_THRESHOLD` or
        statement-multiset equality.
        """
        hint_paths = hint_paths or []
        known_vuln_canonicals = known_vuln_canonicals or set()

        def _body_of(path: str, fname: str) -> str | None:
            refs = self.files.get(path)
            if refs is None or fname not in refs.functions:
                return None
            return self._bodies.get((path, fname))

        # 1. By name in the hinted files.
        for hint in hint_paths:
            if _body_of(hint, name) is not None:
                return hint, name, "hint"
        # 2. By name anywhere else.
        for path in self.function_to_files.get(name, []):
            if path not in hint_paths:
                return path, name, "name-elsewhere"
        # 3. Exact match against historically vulnerable shapes (reverts).
        if known_vuln_canonicals:
            for (path, fname), body in self._bodies.items():
                if prev_name and fname == prev_name:
                    continue
                if canonicalize_function(fname, body) in known_vuln_canonicals:
                    return path, fname, "fingerprint"
        # 4. Rename-resistant fingerprint across every file.
        if prev_body is not None:
            prev_canon = canonicalize_function(prev_name or name, prev_body)
            prev_ms = statement_multiset(prev_body, prev_name or name)
            best: tuple[float, str, str] | None = None
            for (path, fname), body in self._bodies.items():
                if prev_name and fname == prev_name:
                    continue  # name matches were handled above
                same_statements = (
                    len(prev_ms) >= 3
                    and statement_multiset(body, fname) == prev_ms
                )
                if same_statements:
                    # Same statements modulo renames/reorder: the classic
                    # "disguised by reshuffling" shape. Strongest
                    # relocation signal — order is checked separately by
                    # the verdict layer (it can be security-relevant).
                    score = 1.0
                else:
                    cand_canon = canonicalize_function(fname, body)
                    score = similarity(prev_canon, cand_canon)
                    if score < FINGERPRINT_THRESHOLD:
                        continue
                if best is None or score > best[0]:
                    best = (score, path, fname)
            if best is not None:
                return best[1], best[2], "fingerprint"
        return None, None, "missing"


@lru_cache(maxsize=32)
def build_xref(repo: str, ref: str) -> XRefMap:
    """Build (and cache) the cross-file reference map for ``repo`` at ``ref``."""
    repo_path = Path(repo)
    xref = XRefMap({})
    bodies: dict[tuple[str, str], str] = {}
    for path in list_files_at(repo_path, ref, (".sol",)):
        src = file_content_at(repo_path, ref, path)
        if src is None:
            continue
        refs = _file_refs(path, src)
        xref.files[path] = refs
        for contract in refs.contracts:
            xref.contract_to_file.setdefault(contract, path)
        for fn in refs.functions:
            xref.function_to_files.setdefault(fn, []).append(path)
        for fn, body in extract_solidity_functions(src).items():
            bodies[(path, fn)] = body
    xref._bodies = bodies
    return xref

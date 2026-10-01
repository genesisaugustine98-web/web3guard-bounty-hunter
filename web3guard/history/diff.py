"""Version diffing between two git refs.

Uses the git CLI via subprocess — no new dependencies. Produces a
structured :class:`VersionDiff`: changed files, added/removed/changed
functions, and changed line ranges per file.

Function extraction is Solidity-focused and deliberately simple (regex +
brace matching, not a full parser). It is robust enough to answer "did
function X change between these two versions?" which is all the verdict
layer needs.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

_FUNC_RE = re.compile(
    r"(?m)^[ \t]*(?:function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(|"
    r"constructor\s*\(|"
    r"(?:fallback|receive)\s*\(\s*\))"
)
_NAMED_FUNC_RE = re.compile(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_COMMENT_LINE_RE = re.compile(r"//.*")
_COMMENT_BLOCK_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class GitError(RuntimeError):
    """Raised when a git operation fails (not a repo, bad ref, ...)."""


@dataclass
class FileChange:
    """One file's change status between two refs."""

    path: str
    status: str  # added | deleted | modified | renamed | typechange
    old_path: str | None = None


@dataclass
class VersionDiff:
    """Structured diff between ref_a and ref_b."""

    ref_a: str
    ref_b: str
    files: list[FileChange] = field(default_factory=list)
    added_functions: dict[str, list[str]] = field(default_factory=dict)
    removed_functions: dict[str, list[str]] = field(default_factory=dict)
    changed_functions: dict[str, list[str]] = field(default_factory=dict)
    changed_line_ranges: dict[str, list[tuple[int, int]]] = field(default_factory=dict)

    def touched_functions(self) -> dict[str, list[str]]:
        """All functions that were added, removed or changed, per file."""
        out: dict[str, list[str]] = {}
        for src in (self.added_functions, self.removed_functions, self.changed_functions):
            for path, names in src.items():
                out.setdefault(path, [])
                for name in names:
                    if name not in out[path]:
                        out[path].append(name)
        return out


def _git(repo: Path, *args: str, timeout: int = 60) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitError("git executable not found on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git command timed out: {' '.join(args)}") from exc
    if proc.returncode != 0:
        raise GitError(
            f"git {' '.join(args)} failed: {proc.stderr.strip()[:300]}"
        )
    return proc.stdout


def file_content_at(repo: str | Path, ref: str, path: str) -> str | None:
    """Return a file's content at a ref, or None if it doesn't exist there."""
    repo = Path(repo)
    try:
        return _git(repo, "show", f"{ref}:{path}")
    except GitError:
        return None


def list_files_at(repo: str | Path, ref: str, suffixes: tuple[str, ...] = (".sol",)) -> list[str]:
    """List tracked files at a ref, optionally filtered by suffix."""
    repo = Path(repo)
    out = _git(repo, "ls-tree", "-r", "--name-only", ref)
    files = [line for line in out.splitlines() if line]
    if suffixes:
        files = [f for f in files if f.endswith(suffixes)]
    return files


def extract_solidity_functions(source: str) -> dict[str, str]:
    """Map function name -> normalised signature+body for Solidity source.

    Brace-matched so multi-line bodies compare correctly. Comments are
    stripped before matching to avoid false hits. The signature line is
    included so modifiers (``nonReentrant``, ``onlyOwner``, ...) are part
    of the compared text.
    """
    cleaned = _COMMENT_BLOCK_RE.sub("", source)
    cleaned = _COMMENT_LINE_RE.sub("", cleaned)
    functions: dict[str, str] = {}
    for match in _NAMED_FUNC_RE.finditer(cleaned):
        name = match.group(1)
        # Find the opening brace of the body after the signature.
        idx = cleaned.find("{", match.end())
        if idx == -1:
            continue
        depth = 0
        end = idx
        for pos in range(idx, len(cleaned)):
            ch = cleaned[pos]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = pos
                    break
        text = cleaned[match.start() : end + 1]
        # Abstract/interface declarations have no body; skip them.
        if text.rstrip().endswith(";"):
            continue
        functions.setdefault(name, _normalise(text))
    return functions


def _normalise(body: str) -> str:
    """Collapse whitespace so formatting-only diffs don't count as changes."""
    return re.sub(r"\s+", " ", body).strip()


def diff_refs(repo: str | Path, ref_a: str, ref_b: str) -> VersionDiff:
    """Build a structured diff between two git refs (tags or commits)."""
    repo = Path(repo)
    diff = VersionDiff(ref_a=ref_a, ref_b=ref_b)

    # File-level changes.
    name_status = _git(repo, "diff", "--name-status", "-z", ref_a, ref_b, "--")
    parts = [p for p in name_status.split("\0") if p]
    i = 0
    while i < len(parts):
        status = parts[i]
        code = status[0]
        if code == "R":
            old, new = parts[i + 1], parts[i + 2]
            diff.files.append(FileChange(path=new, status="renamed", old_path=old))
            i += 3
        else:
            path = parts[i + 1]
            label = {"A": "added", "D": "deleted", "M": "modified"}.get(code, "typechange")
            diff.files.append(FileChange(path=path, status=label))
            i += 2

    # Per-file line ranges (new-file side).
    patch = _git(repo, "diff", "-U0", "--no-color", ref_a, ref_b, "--")
    current: str | None = None
    for line in patch.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
            diff.changed_line_ranges.setdefault(current, [])
        elif line.startswith("@@") and current is not None:
            m = _HUNK_RE.match(line)
            if m:
                start = int(m.group(3))
                count = int(m.group(4)) if m.group(4) else 1
                # A pure-deletion hunk reports "+start,0": keep a zero-width
                # marker at the position instead of an inverted range.
                end = start + max(count, 1) - 1
                diff.changed_line_ranges[current].append((start, end))

    # Function-level changes for Solidity files present on either side.
    paths = {f.path for f in diff.files if f.path.endswith(".sol")}
    paths |= {f.old_path for f in diff.files if f.old_path and f.old_path.endswith(".sol")}
    for path in sorted(paths):
        old_src = file_content_at(repo, ref_a, path)
        new_src = file_content_at(repo, ref_b, path)
        old_fns = extract_solidity_functions(old_src) if old_src else {}
        new_fns = extract_solidity_functions(new_src) if new_src else {}
        added = [n for n in new_fns if n not in old_fns]
        removed = [n for n in old_fns if n not in new_fns]
        changed = [n for n in new_fns if n in old_fns and new_fns[n] != old_fns[n]]
        if added:
            diff.added_functions[path] = sorted(added)
        if removed:
            diff.removed_functions[path] = sorted(removed)
        if changed:
            diff.changed_functions[path] = sorted(changed)
    return diff


def functions_touched_between(
    repo: str | Path, ref_a: str, ref_b: str, path: str
) -> list[str]:
    """Convenience: function names added/removed/changed in one file."""
    diff = diff_refs(repo, ref_a, ref_b)
    out: list[str] = []
    for src in (diff.added_functions, diff.removed_functions, diff.changed_functions):
        for name in src.get(path, []):
            if name not in out:
                out.append(name)
    return out

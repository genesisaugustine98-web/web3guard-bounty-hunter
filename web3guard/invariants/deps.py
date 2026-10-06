"""Dependency-aware harness bundling (Fix #11).

The invariant fuzz harness renders a self-contained Foundry project, but it
used to copy only the single target ``.sol`` file. Real contracts import
OpenZeppelin, sibling files, etc., so every real-target campaign failed to
compile.

This module resolves the transitive import closure of the target file --
against ``remappings.txt``, ``foundry.toml`` remappings, ``node_modules/``
and ``lib/`` -- and bundles it into the rendered project so ``forge build``
succeeds on real-world targets.

Design notes
------------
* Resolution is read-only and offline: only files already on disk are used.
  Nothing is ever fetched from the network.
* The hook point is :func:`web3guard.invariants.fuzz.run_fuzz_campaign`,
  which funnels every Solidity campaign (main leg, compromised-key leg,
  ghost harness). When ``contract_path`` is empty or missing (isolated
  fixtures), bundling is skipped and behaviour is unchanged.
* Placement rule: a dependency's in-harness path is derived from the
  *importer's* in-harness path, so relative imports keep resolving no
  matter where files land:

  - relative import ``P`` from a file at harness path ``H`` lands at
    ``normpath(dirname(H) / P)``;
  - remapped import ``P`` (prefix ``pfx`` resolved via anchor dir ``A``)
    lands at ``lib/__web3guard_dep{i}/`` + ``relpath(resolved, A)`` for a
    per-(prefix, anchor) group dir, and ``pfx=lib/__web3guard_dep{i}/`` is
    emitted into the generated ``remappings.txt``.

  The two schemes compose: a remapped file's own relative imports land
  inside its group dir at the right relative spot.
* Unresolvable imports produce an explicit warning naming the import --
  never a silently broken harness.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Import parsing
# ---------------------------------------------------------------------------

# Matches the four Solidity import forms:
#   import "path";
#   import * as ns from "path";
#   import {A, B} from "path";
#   import {A as B} from "path";
_IMPORT_RE = re.compile(
    r"""import\s+(?:[^\w"'][^"']*?from\s+)?["']([^"']+)["']\s*;""",
)

_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")


def _strip_comments(source: str) -> str:
    """Remove // and /* */ comments so commented-out imports are ignored."""
    no_block = _BLOCK_COMMENT_RE.sub("", source)
    return _LINE_COMMENT_RE.sub("", no_block)


def extract_imports(source: str) -> list[str]:
    """Return the raw import paths in ``source``, in order, deduplicated."""
    seen: set[str] = set()
    out: list[str] = []
    for match in _IMPORT_RE.finditer(_strip_comments(source)):
        path = match.group(1).strip()
        if path and path not in seen:
            seen.add(path)
            out.append(path)
    return out


# ---------------------------------------------------------------------------
# Remappings
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Remapping:
    """A single remapping entry.

    ``context`` is the optional Foundry context prefix
    (``lib/chainlink-ace/:@openzeppelin/...=...``); ``prefix`` is the import
    prefix; ``target`` is the filesystem path relative to the project root.
    """

    prefix: str
    target: str
    context: str | None = None


def parse_remappings_txt(text: str) -> list[Remapping]:
    """Parse a ``remappings.txt`` file (supports context prefixes)."""
    out: list[Remapping] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        left, _, target = line.partition("=")
        left, target = left.strip(), target.strip()
        if not left or not target:
            continue
        context: str | None = None
        if ":" in left:
            maybe_context, _, maybe_prefix = left.partition(":")
            # The part before the FIRST colon is a context only if it does
            # NOT start with "@" (scoped npm prefixes like "@scope/pkg/"
            # contain "/" but are not contexts).
            if not maybe_context.startswith("@"):
                context, left = maybe_context.strip(), maybe_prefix.strip()
        if left:
            out.append(Remapping(prefix=left, target=target, context=context))
    return out


def parse_foundry_toml_remappings(toml_text: str) -> list[Remapping]:
    """Parse ``remappings = [...]`` from a foundry.toml (best-effort)."""
    out: list[Remapping] = []
    match = re.search(
        r"^\s*remappings\s*=\s*\[(.*?)\]",
        toml_text,
        re.DOTALL | re.MULTILINE,
    )
    if not match:
        return out
    for item in re.findall(r'"([^"]+)"', match.group(1)):
        out.extend(parse_remappings_txt(item))
    return out


def find_project_root(start: Path) -> Path | None:
    """Walk up from ``start`` looking for remappings.txt / foundry.toml."""
    current = start if start.is_dir() else start.parent
    for _ in range(12):  # bound the walk
        if (current / "remappings.txt").is_file() or (current / "foundry.toml").is_file():
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def load_remappings(project_root: Path) -> list[Remapping]:
    """Load remappings.txt + foundry.toml remappings for a project root."""
    remappings: list[Remapping] = []
    txt = project_root / "remappings.txt"
    if txt.is_file():
        try:
            remappings.extend(parse_remappings_txt(txt.read_text()))
        except OSError as exc:
            LOGGER.warning("could not read %s: %s", txt, exc)
    toml = project_root / "foundry.toml"
    if toml.is_file():
        try:
            remappings.extend(parse_foundry_toml_remappings(toml.read_text()))
        except OSError as exc:
            LOGGER.warning("could not read %s: %s", toml, exc)
    return remappings


# ---------------------------------------------------------------------------
# Import resolution
# ---------------------------------------------------------------------------


@dataclass
class ResolvedImport:
    """One resolved import: the on-disk file plus how it was reached."""

    path: Path  # absolute, resolved on disk
    # "relative": via ./ or ../ import.
    # "remapped": via a remapping / node_modules / lib heuristic.
    kind: str
    # For "remapped": the import prefix and the anchor dir it mapped to.
    prefix: str = ""
    anchor: Path | None = None


def _is_sol_file(candidate: Path) -> bool:
    return candidate.is_file() and candidate.suffix == ".sol"


def _resolve_relative(import_path: str, importer_file: Path) -> Path | None:
    candidate = (importer_file.parent / import_path).resolve()
    return candidate if _is_sol_file(candidate) else None


def _resolve_remapped(
    import_path: str,
    importer_file: Path,
    project_root: Path,
    remappings: list[Remapping],
) -> ResolvedImport | None:
    """Longest-prefix remapping match (context-aware)."""
    try:
        importer_rel_posix = (
            importer_file.resolve().relative_to(project_root.resolve())
        ).as_posix()
    except ValueError:
        importer_rel_posix = ""
    best: Remapping | None = None
    for remap in remappings:
        if not import_path.startswith(remap.prefix):
            continue
        if remap.context:
            ctx = remap.context.strip("/")
            if not (importer_rel_posix == ctx or importer_rel_posix.startswith(ctx + "/")):
                continue
        if best is None or len(remap.prefix) > len(best.prefix):
            best = remap
    if best is None:
        return None
    remainder = import_path[len(best.prefix) :]
    anchor = (project_root / best.target).resolve()
    candidate = (anchor / remainder).resolve()
    try:
        candidate.relative_to(anchor)  # guard: must stay inside the anchor
    except ValueError:
        return None
    if _is_sol_file(candidate):
        return ResolvedImport(
            path=candidate,
            kind="remapped",
            prefix=best.prefix,
            anchor=anchor,
        )
    return None


def _resolve_node_modules(import_path: str, importer_file: Path) -> ResolvedImport | None:
    """Walk up looking for node_modules/<import_path>."""
    current = importer_file.parent.resolve()
    for _ in range(12):
        candidate = (current / "node_modules" / import_path).resolve()
        if _is_sol_file(candidate):
            anchor = (current / "node_modules").resolve()
            return ResolvedImport(
                path=candidate,
                kind="remapped",
                prefix=import_path.split("/")[0] + "/",
                anchor=anchor,
            )
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def _resolve_lib_heuristic(import_path: str, project_root: Path) -> ResolvedImport | None:
    """Forge-install layout heuristic for bare imports.

    ``@scope/pkg/rest`` -> ``lib/pkg/rest``; ``pkg/rest`` ->
    ``lib/pkg/rest``. (The ``lib/<pkg>-contracts`` variants are normally
    covered by remappings when present.)
    """
    lib = project_root / "lib"
    if not lib.is_dir():
        return None
    segments = import_path.split("/")
    candidates: list[str] = []
    if import_path.startswith("@") and len(segments) >= 2:
        pkg = segments[1]
        rest = "/".join(segments[2:])
        candidates.append(f"{pkg}/{rest}")
        candidates.append(f"{segments[0][1:]}-{pkg}/{rest}")
    elif segments:
        candidates.append(import_path)
    lib_resolved = lib.resolve()
    for cand in candidates:
        resolved = (lib / cand).resolve()
        try:
            resolved.relative_to(lib_resolved)
        except ValueError:
            continue
        if _is_sol_file(resolved):
            anchor = (lib / cand.split("/")[0]).resolve()
            prefix = (
                "/".join(segments[:2]) + "/" if import_path.startswith("@") else segments[0] + "/"
            )
            return ResolvedImport(
                path=resolved,
                kind="remapped",
                prefix=prefix,
                anchor=anchor,
            )
    return None


def resolve_import(
    import_path: str,
    importer_file: Path,
    project_root: Path | None,
    remappings: list[Remapping],
) -> ResolvedImport | None:
    """Resolve one import path to a file on disk (offline only)."""
    if import_path.startswith("."):
        resolved = _resolve_relative(import_path, importer_file)
        if resolved is not None:
            return ResolvedImport(path=resolved, kind="relative")
        return None
    if import_path.startswith("/"):
        # Absolute import: treat as relative to the project root when known.
        if project_root is not None:
            candidate = (project_root / import_path.lstrip("/")).resolve()
            if _is_sol_file(candidate):
                return ResolvedImport(path=candidate, kind="relative")
        return None
    if project_root is not None:
        remapped = _resolve_remapped(import_path, importer_file, project_root, remappings)
        if remapped is not None:
            return remapped
    node = _resolve_node_modules(import_path, importer_file)
    if node is not None:
        return node
    if project_root is not None:
        return _resolve_lib_heuristic(import_path, project_root)
    return None


@dataclass
class DependencyClosure:
    """Result of transitive import resolution for one target file."""

    target: Path
    # (resolved on-disk path, in-harness path) in BFS order.
    files: list[tuple[Path, str]] = field(default_factory=list)
    # (import_path, importer) pairs that could not be resolved.
    unresolvable: list[tuple[str, Path]] = field(default_factory=list)
    # Generated remappings.txt lines.
    remap_lines: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


#: Distinctive lib dir for remapped deps inside the harness project.
_DEP_LIB_PREFIX = "lib/__web3guard_dep"


def _posix(path: str) -> str:
    return path.replace(os.sep, "/")


def collect_closure(target_file: Path, target_harness_path: str) -> DependencyClosure:
    """Resolve the transitive import closure of ``target_file`` (BFS).

    ``target_harness_path`` is where the target itself lives inside the
    generated project (e.g. ``src/Vault.sol``); every dependency's
    in-harness path is derived from its importer's in-harness path so
    relative imports keep resolving.
    """
    target_file = target_file.resolve()
    project_root = find_project_root(target_file)
    remappings = load_remappings(project_root) if project_root is not None else []
    closure = DependencyClosure(target=target_file)
    # resolved path -> in-harness path (first placement wins).
    placed: dict[Path, str] = {target_file: target_harness_path}
    # (prefix, anchor) -> group lib dir, in first-seen order.
    groups: dict[tuple[str, str], str] = {}
    seen_prefixes: set[str] = set()
    queue: list[tuple[Path, str]] = [(target_file, target_harness_path)]
    warned_unresolvable: set[tuple[str, str]] = set()

    def group_dir_for(prefix: str, anchor: Path) -> str | None:
        key = (prefix, str(anchor))
        if key in groups:
            return groups[key]
        if prefix in seen_prefixes:
            # Same import prefix resolving to two different locations
            # (e.g. conflicting context remappings): first wins, loudly.
            closure.notes.append(
                "dependency bundling: import prefix "
                f"{prefix!r} resolves to multiple locations; using the "
                "first one for all files. Version conflicts between "
                "contexts are not supported."
            )
            return None
        seen_prefixes.add(prefix)
        lib_dir = f"{_DEP_LIB_PREFIX}{len(groups)}__"
        groups[key] = lib_dir
        closure.remap_lines.append(f"{prefix}={lib_dir}/")
        return lib_dir

    while queue:
        current, current_harness = queue.pop(0)
        try:
            source = current.read_text()
        except OSError as exc:
            LOGGER.warning("could not read %s: %s", current, exc)
            continue
        for import_path in extract_imports(source):
            resolved = resolve_import(import_path, current, project_root, remappings)
            if resolved is None:
                key = (import_path, str(current))
                if key not in warned_unresolvable:
                    warned_unresolvable.add(key)
                    closure.unresolvable.append((import_path, current))
                continue
            if resolved.path in placed:
                # Already bundled (possibly via another route). If the
                # existing placement differs from what this route wants,
                # the first placement wins; flag it.
                existing = placed[resolved.path]
                if resolved.kind == "remapped":
                    lib_dir = group_dir_for(resolved.prefix, resolved.anchor or Path())
                    want = (
                        _posix(
                            os.path.normpath(
                                os.path.join(
                                    lib_dir or "",
                                    os.path.relpath(resolved.path, resolved.anchor or Path()),
                                )
                            )
                        )
                        if lib_dir
                        else None
                    )
                else:
                    want = _posix(
                        os.path.normpath(
                            os.path.join(os.path.dirname(current_harness), import_path)
                        )
                    )
                if want and want != existing:
                    closure.notes.append(
                        "dependency bundling: "
                        f"{resolved.path.name} is imported via two routes "
                        f"({existing} vs {want}); keeping the first."
                    )
                continue
            if resolved.kind == "remapped":
                assert resolved.anchor is not None
                lib_dir = group_dir_for(resolved.prefix, resolved.anchor)
                if lib_dir is None:
                    continue  # conflict already noted
                rel = os.path.relpath(resolved.path, resolved.anchor)
                harness_path = _posix(os.path.normpath(os.path.join(lib_dir, rel)))
            else:
                harness_path = _posix(
                    os.path.normpath(os.path.join(os.path.dirname(current_harness), import_path))
                )
            placed[resolved.path] = harness_path
            closure.files.append((resolved.path, harness_path))
            queue.append((resolved.path, harness_path))
    return closure


def bundle_dependencies(
    files: Mapping[str, str],
    contract_path: str,
    notes: list[str] | None = None,
    *,
    target_harness_path: str | None = None,
) -> dict[str, str]:
    """Bundle the target's transitive import closure into a rendered project.

    ``files`` is the rendered ``{relpath: content}`` project dict;
    ``contract_path`` is the real on-disk target file (may be "").
    ``target_harness_path`` is where the target itself lives in ``files``
    (defaults to ``src/<stem>.sol``). Returns a new dict with dependency
    files added plus a generated ``remappings.txt``.

    When ``contract_path`` is empty/missing/not a ``.sol`` file, ``files``
    is returned unchanged (isolated fixtures keep working exactly as
    before).
    """
    if not contract_path or not contract_path.endswith(".sol"):
        return dict(files)
    target = Path(contract_path)
    if not target.is_file():
        return dict(files)

    if target_harness_path is None:
        target_harness_path = f"src/{target.stem}.sol"

    closure = collect_closure(target, target_harness_path)
    if not closure.files and not closure.unresolvable:
        return dict(files)

    bundled: dict[str, str] = dict(files)
    for disk_path, harness_path in closure.files:
        if harness_path in bundled:
            # The renderer already emitted this path (e.g. attacker
            # contracts under test/). Keep the renderer's version.
            continue
        try:
            bundled[harness_path] = disk_path.read_text()
        except OSError as exc:
            LOGGER.warning("could not read %s: %s", disk_path, exc)
            continue

    if closure.remap_lines:
        existing = bundled.get("remappings.txt", "")
        bundled["remappings.txt"] = existing + "".join(line + "\n" for line in closure.remap_lines)

    try:
        target_display = str(target.relative_to(Path.cwd()))
    except ValueError:
        target_display = str(target)
    for import_path, importer in closure.unresolvable:
        try:
            importer_display = str(importer.relative_to(target.parent))
        except ValueError:
            importer_display = str(importer)
        msg = (
            "dependency bundling: could not resolve import "
            f"{import_path!r} (imported by {importer_display} in "
            f"{target_display}); checked relative path, remappings.txt, "
            "foundry.toml, node_modules/, lib/. The generated harness "
            "may fail to compile."
        )
        LOGGER.warning(msg)
        if notes is not None:
            notes.append(msg)

    if notes is not None:
        notes.extend(closure.notes)
        if len(bundled) > len(files) or closure.remap_lines:
            notes.append(
                f"dependency bundling (Fix #11): {len(closure.files)} "
                f"dependency file(s) bundled into the fuzz project "
                f"({len(closure.remap_lines)} remapping(s) generated)."
            )
    else:
        for note in closure.notes:
            LOGGER.warning(note)
    return bundled

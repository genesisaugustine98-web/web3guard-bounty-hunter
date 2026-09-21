"""Declarative language adapter.

Every adapter repeats the same shapes: extension detection, a
declaration-regex chunker, an import-context resolver, a regex summary,
and a prompt pair. :class:`SimpleAdapter` implements all of that once,
parameterized by class attributes. A new language is now ~40 lines of
attributes instead of ~200 lines of boilerplate.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from web3guard.languages.base import (
    Chunk,
    DiscoveryEngine,
    LanguageAdapter,
    RepoSummary,
    TargetLanguage,
    TestRunner,
)


class SimpleAdapter(LanguageAdapter):
    """A fully-declarative :class:`LanguageAdapter`.

    Subclasses set the class attributes below and get the complete
    adapter behavior. Only the chunker regex is mandatory.
    """

    language: TargetLanguage = TargetLanguage.UNKNOWN
    extensions: tuple[str, ...] = ()
    priority: int = 150

    # --- detection --------------------------------------------------------
    # Root-level marker files/dirs that prove the language is present
    # (checked before the rglob extension fallback for speed).
    detect_markers: tuple[str, ...] = ()
    # Path substrings that disqualify a file from detection/analysis.
    detect_skip_markers: tuple[str, ...] = ("/.git/", "/node_modules/", "/vendor/", "/target/")

    # --- chunking ---------------------------------------------------------
    # Regex matching the *start* of top-level declarations. Required.
    decl_re: re.Pattern[str] | None = None
    chunk_kind: str = "block"

    # --- context ----------------------------------------------------------
    # Regex whose group(1) is a relative import path to inline.
    import_re: re.Pattern[str] | None = None
    # Regex whose matches are recorded as one-line context notes (stdlib
    # / framework imports that cannot be inlined).
    note_import_re: re.Pattern[str] | None = None
    max_context_chars: int = 6000

    # --- summarizing ------------------------------------------------------
    fn_count_re: re.Pattern[str] | None = None
    ext_call_re: re.Pattern[str] | None = None
    value_move_re: re.Pattern[str] | None = None
    oracle_re: re.Pattern[str] | None = None
    assembly_re: re.Pattern[str] | None = None

    # --- prompts ----------------------------------------------------------
    analysis_system: str = ""
    exploit_template: str = ""

    # --- engines + runner -------------------------------------------------
    discovery_engines: tuple[DiscoveryEngine, ...] = ()
    test_runner: TestRunner  # required; set at class level

    def detect(self, target_path: Path) -> bool:
        if not target_path.is_dir():
            return False
        for marker in self.detect_markers:
            if (target_path / marker).exists():
                return True
        for ext in self.extensions:
            for f in target_path.rglob(f"*{ext}"):
                s = "/" + str(f).replace("\\\\", "/").lower().strip("/") + "/"
                if any(m in s for m in self.detect_skip_markers):
                    continue
                return True
        return False

    def discover_files(self, target_path: Path) -> list[Path]:
        out: list[Path] = []
        for ext in self.extensions:
            for f in target_path.rglob(f"*{ext}"):
                if self.is_user_code(f.relative_to(target_path)):
                    out.append(f)
        return sorted(out)

    def chunk(self, file_path: Path, max_chars: int) -> list[Chunk]:
        text = file_path.read_text(errors="ignore")
        if not text:
            return []
        pattern = self.decl_re
        if pattern is None:
            return [Chunk(file=str(file_path), chunk_id=0, content=text,
                          kind="file", language=self.language.value)]
        boundaries = [m.start() for m in pattern.finditer(text)]
        if not boundaries:
            return [Chunk(file=str(file_path), chunk_id=0, content=text,
                          kind="file", language=self.language.value)]
        chunks: list[Chunk] = []
        cur_start = 0
        cur_end = boundaries[0]
        cid = 0
        for i, _start in enumerate(boundaries):
            end = boundaries[i + 1] if i + 1 < len(boundaries) else len(text)
            if end - cur_start > max_chars and cur_end > cur_start:
                chunks.append(Chunk(
                    file=str(file_path), chunk_id=cid,
                    content=text[cur_start:cur_end],
                    kind=self.chunk_kind, language=self.language.value,
                ))
                cid += 1
                cur_start = cur_end
            cur_end = end
        if cur_end > cur_start:
            chunks.append(Chunk(
                file=str(file_path), chunk_id=cid,
                content=text[cur_start:cur_end],
                kind=self.chunk_kind, language=self.language.value,
            ))
        return chunks

    def resolve_context(self, file_path: Path, target_root: Path) -> str:
        if not file_path.is_file():
            return ""
        try:
            content = file_path.read_text(errors="ignore")
        except Exception:  # noqa: BLE001
            return ""
        snippets: list[str] = []
        notes: list[str] = []
        used = 0
        if self.import_re is not None:
            for m in self.import_re.finditer(content):
                rel = m.group(1)
                candidate = (file_path.parent / rel).resolve()
                if not candidate.exists():
                    continue
                if target_root not in candidate.parents and candidate != target_root:
                    continue
                try:
                    text = candidate.read_text(errors="ignore")
                except Exception:  # noqa: BLE001
                    continue
                if used + len(text) > self.max_context_chars:
                    text = text[: self.max_context_chars - used]
                snippets.append(
                    f"// ---- imported from {candidate.relative_to(target_root)} ----\n{text}"
                )
                used += len(text)
                if used >= self.max_context_chars:
                    break
        if self.note_import_re is not None:
            for m in self.note_import_re.finditer(content):
                note = m.group(0).strip()
                if note not in notes:
                    notes.append(note)
        if notes:
            snippets.append("// ---- imports (not inlined): ----\n" + "\n".join(notes))
        return "\n".join(snippets)

    def summarize(self, file_path: Path, target_root: Path) -> RepoSummary:
        try:
            content = file_path.read_text(errors="ignore")
        except Exception:  # noqa: BLE001
            return RepoSummary(file=str(file_path), language=self.language.value)
        rel = str(file_path.relative_to(target_root)) if target_root in file_path.parents else str(file_path)
        return RepoSummary(
            file=rel,
            language=self.language.value,
            loc=content.count("\n") + 1,
            functions=len(self.fn_count_re.findall(content)) if self.fn_count_re else 0,
            external_calls=len(self.ext_call_re.findall(content)) if self.ext_call_re else 0,
            reads_oracle=bool(self.oracle_re.search(content)) if self.oracle_re else False,
            moves_value=bool(self.value_move_re.search(content)) if self.value_move_re else False,
            has_assembly=bool(self.assembly_re.search(content)) if self.assembly_re else False,
        )

    def detect_framework(self, target_path: Path) -> dict[str, Any]:
        return {
            "language": self.language.value,
            "build_tool": self.detect_markers[0] if self.detect_markers else "unknown",
        }

    def analysis_system_prompt(self) -> str:
        return self.analysis_system

    def exploit_user_template(self) -> str:
        return self.exploit_template

    @property
    def discovery_engines_list(self) -> list[DiscoveryEngine]:
        return list(self.discovery_engines)

    @property
    def test_runner(self) -> TestRunner:  # type: ignore[override]
        return self._runner

    # Set by subclasses alongside the class definition.
    _runner: TestRunner


# Placeholder to keep dataclass-free inheritance simple: TestRunner on the
# base is declared as a class annotation only.
SimpleAdapter.test_runner = property(lambda self: self._runner)  # type: ignore[method-assign]

"""Variant sweeping — hunt the same bug shape across similar codebases.

When a bug class or finding signature is confirmed somewhere (a fresh
audit, a bounty payout, one of our own CONFIRMED findings), the same
mistake usually exists in forks and sibling projects. This module
sweeps a *local* corpus of codebases (cloned repos) for the same
shape and reports file/line evidence for each candidate.

Inputs:

- a :class:`FindingSignature` — derived from the scanner's canonical
  finding shape (:class:`web3guard.scanner.Finding` /
  :class:`web3guard.findings_db.FindingRecord`, or a plain dict with
  the same keys) via :meth:`FindingSignature.from_finding`;
- a corpus directory of local clones.

Matching is deliberately conservative text-shape matching (function
name, an optional regex pattern, keyword co-occurrence) — it finds
*candidates* for a human or the verification layer to confirm, not
verdicts.

An opt-in extra, :class:`GitHubCodeSearch`, queries GitHub code
search when ``GITHUB_TOKEN`` is set in the environment (never in
files); without a token it degrades gracefully to "no remote
results" instead of failing.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger("web3guard.discovery.variant_sweep")

# Env var for the opt-in GitHub code-search extra. Unset => skipped.
GITHUB_TOKEN_ENV = "GITHUB_TOKEN"

DEFAULT_EXTENSIONS = frozenset({
    ".sol", ".vy",               # EVM
    ".move",                     # Move (Aptos/Sui)
    ".cairo",                    # Cairo/Starknet
    ".clar",                     # Clarity/Stacks
    ".fc", ".func",              # FunC/TON
    ".rs",                       # Rust (Solana/ink!/Soroban)
    ".ts", ".js",                # off-chain SDKs
})

MAX_FILE_BYTES = 1_000_000
MAX_MATCHES_TOTAL = 500
GITHUB_SEARCH_DELAY_SECONDS = 2.0
GITHUB_SEARCH_MAX_PAGES = 3

_STOPWORDS = frozenset({
    "the", "a", "an", "and", "or", "of", "in", "on", "to", "for", "with",
    "is", "are", "was", "were", "be", "by", "as", "at", "it", "its",
    "this", "that", "from", "into", "which", "when", "where", "can",
    "may", "not", "no", "all", "any", "contract", "function",
})


def _tokenize(text: str) -> list[str]:
    words = re.findall(r"[a-zA-Z][a-zA-Z0-9_]{3,}", text.lower())
    seen: list[str] = []
    for w in words:
        if w not in _STOPWORDS and w not in seen:
            seen.append(w)
    return seen


# ---------------------------------------------------------------------------
# Finding signature
# ---------------------------------------------------------------------------

@dataclass
class FindingSignature:
    """The matchable shape of a confirmed finding.

    ``category``/``swc_id`` identify the bug class; ``function``,
    ``keywords`` and ``pattern`` drive the text-shape matching.
    """

    category: str = ""
    swc_id: str = ""
    function: str = ""
    keywords: tuple[str, ...] = ()
    pattern: str = ""            # optional regex, matched case-insensitively
    source_fingerprint: str = ""

    @classmethod
    def from_finding(cls, finding: Any) -> FindingSignature:
        """Build a signature from the scanner's canonical finding shape.

        Accepts :class:`web3guard.scanner.Finding`,
        :class:`web3guard.findings_db.FindingRecord`, or a plain dict
        with the same attribute/key names. (Duck-typed on purpose: this
        module must not import the scanner core.)
        """
        def _get(name: str, default: str = "") -> str:
            if isinstance(finding, dict):
                return str(finding.get(name, default) or default)
            return str(getattr(finding, name, default) or default)

        category = _get("category")
        description = _get("description")
        function = _get("function")
        words = _tokenize(f"{category} {function} {description}")
        # The function name is the strongest single signal; keep it
        # first so scoring can weight it.
        if function:
            fn = function.strip().lower()
            words = [fn, *[k for k in words if k != fn]]
        return cls(
            category=category,
            swc_id=_get("swc_id"),
            function=function,
            keywords=tuple(words[:24]),
            source_fingerprint=_get("fingerprint"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "swc_id": self.swc_id,
            "function": self.function,
            "keywords": list(self.keywords),
            "pattern": self.pattern,
            "source_fingerprint": self.source_fingerprint,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FindingSignature:
        return cls(
            category=str(data.get("category", "")),
            swc_id=str(data.get("swc_id", "")),
            function=str(data.get("function", "")),
            keywords=tuple(data.get("keywords", []) or ()),
            pattern=str(data.get("pattern", "")),
            source_fingerprint=str(data.get("source_fingerprint", "")),
        )


@dataclass
class VariantMatch:
    """One candidate occurrence of the signature in the corpus."""
    file: str
    line: int
    evidence: str            # snippet with surrounding context
    matched_on: str          # "function" | "pattern" | "keywords"
    score: float = 0.0       # 0-1, higher = stronger shape resemblance

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "matched_on": self.matched_on,
            "score": self.score,
        }


# ---------------------------------------------------------------------------
# Local corpus sweeper
# ---------------------------------------------------------------------------

_SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "target", "out", "artifacts"}


class VariantSweeper:
    """Sweep a local corpus directory for a finding signature's shape."""

    def __init__(
        self,
        corpus_dir: Path | str,
        *,
        extensions: frozenset[str] | set[str] | None = None,
        context_lines: int = 3,
        min_keyword_hits: int = 2,
        max_matches: int = MAX_MATCHES_TOTAL,
    ) -> None:
        self.corpus_dir = Path(corpus_dir)
        self.extensions = frozenset(extensions) if extensions else DEFAULT_EXTENSIONS
        self.context_lines = max(0, context_lines)
        self.min_keyword_hits = max(1, min_keyword_hits)
        self.max_matches = max_matches

    def corpus_files(self) -> list[Path]:
        """Source files in the corpus, skipping VCS/build dirs."""
        if not self.corpus_dir.is_dir():
            LOGGER.warning("variant sweep: corpus dir %s missing", self.corpus_dir)
            return []
        files: list[Path] = []
        for path in sorted(self.corpus_dir.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() not in self.extensions:
                continue
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            files.append(path)
        return files

    def sweep(self, signature: FindingSignature) -> list[VariantMatch]:
        """Return candidate matches, strongest first."""
        matches: list[VariantMatch] = []
        seen: set[tuple[str, int, str]] = set()
        pattern_re: re.Pattern[str] | None = None
        if signature.pattern:
            try:
                pattern_re = re.compile(signature.pattern, re.IGNORECASE)
            except re.error as e:
                LOGGER.warning("variant sweep: bad pattern %r: %s",
                               signature.pattern, e)
        fn_re: re.Pattern[str] | None = None
        if signature.function:
            fn_re = re.compile(
                r"\b" + re.escape(signature.function.strip()) + r"\b")

        for path in self.corpus_files():
            if len(matches) >= self.max_matches:
                LOGGER.info("variant sweep: match cap reached (%d)",
                            self.max_matches)
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lines = text.splitlines()
            lowered = text.lower()

            def add(path: Path, lines: list[str], line_no: int,
                    matched_on: str, score: float) -> None:
                key = (str(path), line_no, matched_on)
                if key in seen:
                    return
                seen.add(key)
                matches.append(VariantMatch(
                    file=str(path), line=line_no,
                    evidence=self._snippet(lines, line_no),
                    matched_on=matched_on, score=score))

            if pattern_re:
                for m in pattern_re.finditer(text):
                    line_no = text.count("\n", 0, m.start()) + 1
                    add(path, lines, line_no, "pattern", 1.0)
            if fn_re:
                for m in fn_re.finditer(text):
                    line_no = text.count("\n", 0, m.start()) + 1
                    add(path, lines, line_no, "function", 0.9)
            if signature.keywords:
                hits = [k for k in signature.keywords if k in lowered]
                if len(hits) >= self.min_keyword_hits:
                    first = min(
                        (lowered.index(k) for k in hits), default=0)
                    line_no = lowered.count("\n", 0, first) + 1
                    add(path, lines, line_no, "keywords",
                        len(hits) / max(1, len(signature.keywords)))

        matches.sort(key=lambda m: (-m.score, m.file, m.line))
        return matches

    def _snippet(self, lines: list[str], line_no: int) -> str:
        start = max(0, line_no - 1 - self.context_lines)
        end = min(len(lines), line_no + self.context_lines)
        return "\n".join(
            f"{i + 1:>5}: {lines[i]}" for i in range(start, end))


# ---------------------------------------------------------------------------
# Opt-in GitHub code search extra
# ---------------------------------------------------------------------------

class GitHubCodeSearch:
    """GitHub code search for a signature's keywords — opt-in extra.

    Requires ``GITHUB_TOKEN`` in the environment (a fine-grained
    personal access token; never stored in files). Without a token,
    :meth:`from_env` returns ``None`` and callers skip remote search
    gracefully. Requests are paced (2 s between pages, max 3 pages)
    and any auth/rate-limit/transport failure degrades to an empty
    result with a warning — never an exception to the caller.
    """

    API = "https://api.github.com/search/code"

    def __init__(self, token: str, *,
                 delay_seconds: float = GITHUB_SEARCH_DELAY_SECONDS,
                 max_pages: int = GITHUB_SEARCH_MAX_PAGES) -> None:
        self._token = token
        self._delay = delay_seconds
        self._max_pages = max_pages

    @classmethod
    def from_env(cls, **kwargs: Any) -> GitHubCodeSearch | None:
        token = os.environ.get(GITHUB_TOKEN_ENV, "").strip()
        if not token:
            LOGGER.info("GitHub code search disabled: %s not set",
                        GITHUB_TOKEN_ENV)
            return None
        return cls(token, **kwargs)

    def search(self, signature: FindingSignature) -> list[dict[str, Any]]:
        """Code-search the signature's keywords; [] when unavailable."""
        query_terms = [signature.function, *signature.keywords[:6]]
        query_terms = [t for t in query_terms if t]
        if not query_terms:
            return []
        query = " ".join(query_terms[:4])
        results: list[dict[str, Any]] = []
        try:
            for page in range(1, self._max_pages + 1):
                if page > 1:
                    time.sleep(self._delay)
                batch = self._search_page(query, page)
                if not batch:
                    break
                results.extend(batch)
        except Exception as e:  # noqa: BLE001 - graceful degradation by design
            LOGGER.warning("GitHub code search degraded: %s", e)
            return []
        return results

    def _search_page(self, query: str, page: int) -> list[dict[str, Any]]:
        params = urllib.parse.urlencode(
            {"q": query, "per_page": "30", "page": str(page)})
        req = urllib.request.Request(
            f"{self.API}?{params}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "web3guard-variant-sweep/1.0",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                payload = json.loads(resp.read().decode("utf-8", "replace"))
        except OSError as e:
            LOGGER.warning("GitHub code search request failed: %s", e)
            return []
        items = payload.get("items", []) or []
        out: list[dict[str, Any]] = []
        for item in items:
            repo = item.get("repository") or {}
            out.append({
                "repo": repo.get("full_name", ""),
                "path": item.get("path", ""),
                "url": item.get("html_url", ""),
            })
        return out


__all__ = [
    "FindingSignature",
    "VariantMatch",
    "VariantSweeper",
    "GitHubCodeSearch",
    "GITHUB_TOKEN_ENV",
]

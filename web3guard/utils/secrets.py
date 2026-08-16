"""Shared, hardened secret-scanning patterns and helpers.

The original scanner (and the Gitleaks builtin fallback) shipped a
naive ``mnemonic`` regex:

.. code-block:: python

    re.compile(r"\\b(?:[a-z]{3,8}\\s+){11,23}[a-z]{3,8}\\b")

which matched any English sentence of 12+ short lowercase words (e.g.
a comment saying "return the amount if the user has the required
balance and the transfer succeeds"). This module replaces that with a
post-validated matcher that only flags BIP39-length mnemonic phrases
that appear standalone or near a "seed/phrase/recovery" keyword.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

_MNEMONIC_LENGTHS = (12, 15, 18, 21, 24)

# A run of 12..24 lowercase words (3-8 chars each). We validate counts
# and context in `_validate_mnemonic` afterwards.
_MNEMONIC_RE = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}"
    r"(?![A-Za-z0-9_])"
)

# Words that indicate a mnemonic/seed/recovery phrase nearby.
_MNEMONIC_HINTS = (
    "seed", "mnemonic", "phrase", "recovery", "bip39", "bip-39",
    "words", "backup", "passphrase", "wallet",
)

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "alchemy_rpc": re.compile(r"https://[a-zA-Z0-9._-]*alchemy[a-zA-Z0-9._-]*/v2/[A-Za-z0-9_-]{20,}"),
    "infura_rpc": re.compile(r"https://[a-zA-Z0-9._-]*infura[a-zA-Z0-9._-]*/v3/[A-Za-z0-9_-]{20,}"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
    "openai_key": re.compile(r"sk-[A-Za-z0-9]{20,}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "mnemonic": _MNEMONIC_RE,
}


@dataclass(frozen=True)
class SecretMatch:
    """A single secret-leak match."""
    kind: str
    value: str
    line: int
    start: int
    end: int


def _validate_mnemonic(text: str, start: int, end: int) -> bool:
    """Return True if the matched phrase is plausibly a BIP39 mnemonic.

    Heuristics, chosen to keep precision high while still catching the
    common leak shapes:
    - The phrase must be 12/15/18/21/24 words (BIP39 standard lengths).
    - The phrase must contain only lowercase letters and single spaces.
    - The phrase must either (a) sit on its own line, (b) be quoted,
      or (c) appear near a seed/phrase/mnemonic keyword.
    """
    phrase = text[start:end]
    words = phrase.split()
    if len(words) not in _MNEMONIC_LENGTHS:
        return False
    if phrase != phrase.lower():
        return False
    if re.search(r"[^a-z ]", phrase) or "  " in phrase:
        return False

    # Context check.
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end]
    before = text[max(0, line_start):start]
    after = text[end:line_end]
    before_context = text[max(0, start - 60):start]

    if line.strip() == phrase:
        return True
    if before.strip().startswith('"') and after.strip().endswith('"'):
        return True
    if re.search(r"[\"'`=]", before[:40]) or re.search(r"[\"'`]", after[:20]):
        return True
    hint = before_context.lower()
    if any(k in hint for k in _MNEMONIC_HINTS):
        return True
    return False


def iter_secret_matches(content: str) -> Iterator[SecretMatch]:
    """Yield validated secret matches found in ``content``.

    Cheap, regex-only, and shared by the scanner core and the Gitleaks
    discovery engine's builtin fallback so the two can never drift.
    """
    for kind, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(content):
            if kind == "mnemonic" and not _validate_mnemonic(content, m.start(), m.end()):
                continue
            line = content[: m.start()].count("\n") + 1
            yield SecretMatch(kind=kind, value=m.group(0), line=line,
                              start=m.start(), end=m.end())


# Directories that are never interesting for secret scanning.
SKIP_DIR_MARKERS = (
    "/.git/", "/node_modules/", "/target/", "/build/", "/out/",
    "/dist/", "/.cache/", "/.venv/", "/venv/",
)


def scan_path(target_path: Path) -> list[dict[str, object]]:
    """Scan every file under ``target_path`` for secrets.

    Returns a list of dicts shaped like the scanner's legacy
    ``secrets_findings`` entries:
    ``{"kind", "file", "line", "snippet"}``.
    """
    findings: list[dict[str, object]] = []
    for fp in target_path.rglob("*"):
        if not fp.is_file():
            continue
        normalized = "/" + fp.relative_to(target_path).as_posix().lower().strip("/") + "/"
        if any(marker in normalized for marker in SKIP_DIR_MARKERS):
            continue
        try:
            content = fp.read_text(errors="ignore")
        except Exception:  # noqa: BLE001
            continue
        for m in iter_secret_matches(content):
            findings.append({
                "kind": m.kind,
                "file": str(fp.relative_to(target_path)),
                "line": m.line,
                "snippet": m.value[:120],
            })
    return findings

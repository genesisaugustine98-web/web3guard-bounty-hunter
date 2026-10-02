"""Semantic normalization for refactor-resistant code comparison.

The history engine must not be fooled by renames, reformatting, or code
that moved between files. This module canonicalizes Solidity function
bodies so that:

- renaming identifiers (function name, parameters, locals) does not
  change the canonical form — a renamed-but-still-vulnerable function
  still matches its old self;
- whitespace, comments, and formatting never change the canonical form;
- statement **order is preserved** — reordering statements changes the
  canonical text, because order can be security-relevant
  (checks-effects-interactions). A pure reshuffle is still detectable as
  "same statements, different order" via :func:`statement_multiset`.

What canonicalization deliberately erases: identifier spellings, string
literal contents. What it keeps: keywords, operators, control-flow
structure, statement order, numeric literals (a changed constant is a
semantic change).
"""

from __future__ import annotations

import difflib
import re

_COMMENT_BLOCK_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_COMMENT_LINE_RE = re.compile(r"//.*")
_STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Solidity keywords, builtins and type names: semantically meaningful, so
# they are never renamed by canonicalization. Everything else that looks
# like an identifier is mapped to ID<n> by order of first appearance.
_KEYWORDS = frozenset(
    """
    pragma solidity contract interface library abstract is using for
    function modifier constructor fallback receive returns return
    if else while do for break continue
    uint uint8 uint16 uint32 uint64 uint128 uint256
    int int8 int16 int32 int64 int128 int256
    address bool string bytes bytes1 bytes2 bytes4 bytes8 bytes16 bytes32
    mapping memory storage calldata external public internal private
    payable pure view virtual override immutable constant
    new delete emit require assert revert try catch
    true false this super self msg block tx abi
    unchecked assembly
    """.split()
)


def strip_comments(source: str) -> str:
    """Remove block and line comments from Solidity source."""
    no_block = _COMMENT_BLOCK_RE.sub(" ", source)
    return _COMMENT_LINE_RE.sub(" ", no_block)


def canonicalize(body: str) -> str:
    """Return the rename-resistant canonical form of a function body.

    Identifier spellings are replaced by ``ID<n>`` tokens assigned in
    order of first appearance (the function's own name becomes ``FN`` and
    is expected to be substituted by the caller when comparing across
    renames — see :func:`canonicalize_function`). String literals become
    ``STR``. Statement order is preserved.
    """
    text = strip_comments(body)
    text = _STRING_RE.sub("STR", text)
    mapping: dict[str, str] = {}
    counter = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal counter
        word = match.group(0)
        if word in _KEYWORDS:
            return word
        if word not in mapping:
            counter += 1
            mapping[word] = f"ID{counter}"
        return mapping[word]

    text = _IDENT_RE.sub(replace, text)
    return re.sub(r"\s+", " ", text).strip()


def canonicalize_function(name: str, body: str) -> str:
    """Canonical form of a whole function, with its own name normalised.

    Two functions that differ only by their name (a rename) produce the
    identical string, so a renamed-but-still-vulnerable function matches
    its previous self.
    """
    # The function's own name canonicalizes to ID<n> for some n depending
    # on first-appearance order; normalise the *definition occurrence* to
    # FN so renames compare equal. We re-run the same deterministic
    # identifier mapping canonicalize() uses, find which token the name
    # received, and rewrite its first occurrence (the definition).
    text = strip_comments(body)
    text = _STRING_RE.sub("STR", text)
    mapping: dict[str, str] = {}
    counter = 0
    name_token = None
    for match in _IDENT_RE.finditer(text):
        word = match.group(0)
        if word in _KEYWORDS:
            continue
        if word not in mapping:
            counter += 1
            mapping[word] = f"ID{counter}"
        if word == name and name_token is None:
            name_token = mapping[word]
    if name_token is not None:
        canon = canonicalize(body)
        canon = re.sub(r"\b" + re.escape(name_token) + r"\b", "FN", canon, count=1)
        return canon
    return canonicalize(body)


def split_statements(body: str) -> list[str]:
    """Split a function body into coarse statements.

    Splits on ``;`` and on brace boundaries at any depth, tracking
    parentheses/braces so ``for(;;)`` headers and nested blocks don't
    split mid-statement. This is deliberately coarse — it only needs to
    answer "same statements, different order?" for reshuffle detection.
    """
    text = strip_comments(body)
    text = _STRING_RE.sub("STR", text)
    statements: list[str] = []
    depth_paren = 0
    current: list[str] = []
    for ch in text:
        if ch == "(":
            depth_paren += 1
            current.append(ch)
        elif ch == ")":
            depth_paren = max(0, depth_paren - 1)
            current.append(ch)
        elif ch in "{;}" and depth_paren == 0:
            chunk = "".join(current).strip()
            if chunk:
                statements.append(re.sub(r"\s+", " ", chunk))
            current = []
            if ch == "{" or ch == "}":
                continue
        else:
            current.append(ch)
    tail = "".join(current).strip()
    if tail:
        statements.append(re.sub(r"\s+", " ", tail))
    return [s for s in statements if s]


def statement_multiset(body: str, name: str = "") -> tuple[str, ...]:
    """Canonicalized statements as a sorted tuple (order-insensitive).

    A pure reshuffle — same statements, different order — yields the
    identical multiset, while the order-preserving :func:`canonicalize`
    output differs. Comparing both tells "renamed", "reshuffled", and
    "genuinely changed" apart.
    """
    stmts = split_statements(body)
    canon_stmts: list[str] = []
    for stmt in stmts:
        c = canonicalize(stmt)
        canon_stmts.append(c)
    # Normalise the function's own name inside statements too.
    if name:
        canon_stmts = [
            re.sub(r"\b" + re.escape(name) + r"\b", "FN", s) for s in canon_stmts
        ]
    return tuple(sorted(canon_stmts))


def similarity(a: str, b: str) -> float:
    """Similarity ratio (0.0-1.0) between two canonical strings."""
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def is_rename(old_name: str, old_body: str, new_name: str, new_body: str) -> bool:
    """True when the bodies are identical modulo identifier renames."""
    if old_name == new_name:
        return False
    return canonicalize_function(old_name, old_body) == canonicalize_function(
        new_name, new_body
    )


def is_pure_reshuffle(old_name: str, old_body: str, new_name: str, new_body: str) -> bool:
    """True when the bodies hold the same statements in a different order."""
    if canonicalize_function(old_name, old_body) == canonicalize_function(
        new_name, new_body
    ):
        return False  # identical (possibly a pure rename), not a reshuffle
    return statement_multiset(old_body, old_name) == statement_multiset(
        new_body, new_name
    )

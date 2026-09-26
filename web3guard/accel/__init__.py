"""Selective Rust acceleration for Web3Guard.

v3.5: the hot loops that are pure-CPU and safety-trivial — content
hashing for the incremental graph, secret-pattern scanning, import-edge
extraction — are optionally served by a native Rust extension
(``web3guard_accel``, see ``native/web3guard-accel``) while **Python
stays the orchestration layer**: every accelerated function has a pure
Python fallback and the scanner never requires the native module.

Load policy (checked once at import, cached):

1. Try ``import web3guard_accel``.
2. Fall back to :class:`PythonAccelerator` otherwise.
3. ``WEB3GUARD_DISABLE_ACCEL=1`` forces the Python path (CI, debugging).

Every public function returns plain Python objects, so callers cannot
tell which implementation ran — except via :func:`accelerator`'s
``kind`` tag, which reports surface it in run metadata.
"""

from __future__ import annotations

import logging
import os
from typing import Any

LOGGER = logging.getLogger("web3guard.accel")

_ACCEL_ENV = "WEB3GUARD_DISABLE_ACCEL"


class PythonAccelerator:
    """Pure-Python reference implementation (always available)."""

    kind = "python"

    def hash_files(self, paths: list[Any]) -> dict[str, str]:
        """Content hashes for ``paths`` (bytes)."""
        import hashlib
        out: dict[str, str] = {}
        for p in paths:
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for block in iter(lambda: f.read(65536), b""):
                    h.update(block)
            out[str(p)] = h.hexdigest()[:24]
        return out

    def scan_secrets(self, content: str) -> list[dict[str, Any]]:
        """Delegate to the hardened secret scanner (same patterns + validation)."""
        from web3guard.utils.secrets import iter_secret_matches
        return [
            {"rule": m.kind, "match": m.value, "line": m.line}
            for m in iter_secret_matches(content)
        ]

    def extract_imports(self, content: str) -> list[str]:
        """First import match per pattern — mirrors graph._IMPORT_PATTERNS."""
        from web3guard.graph.analyzer import _IMPORT_PATTERNS
        out: list[str] = []
        for _lang, pat in _IMPORT_PATTERNS:
            m = pat.search(content)
            if m:
                out.append(m.group(1))
        return out


class RustAccelerator:
    """Thin wrapper over the native ``web3guard_accel`` module."""

    kind = "rust"

    def __init__(self, module: Any) -> None:
        self._mod = module

    def hash_files(self, paths: list[Any]) -> dict[str, str]:
        raw = self._mod.hash_files([str(p) for p in paths])
        return dict(raw)

    def scan_secrets(self, content: str) -> list[dict[str, Any]]:
        raw = self._mod.scan_secrets(content)
        return [dict(x) for x in raw]

    def extract_imports(self, crate_dir: str) -> list[str]:
        return list(self._mod.extract_imports(crate_dir))


_NONE: list[Any] = []


def accelerator() -> Any:
    """Return the best available accelerator (cached).

    Order: Rust extension -> Python fallback. The choice is made once
    per process; call :func:`reset_accelerator` to re-detect (tests).
    """
    global _SELECTED
    if _SELECTED is not None:
        return _SELECTED
    if os.environ.get(_ACCEL_ENV, "") not in ("", "0"):
        LOGGER.info("acceleration disabled by %s", _ACCEL_ENV)
        _SELECTED = PythonAccelerator()
        return _SELECTED
    try:
        import web3guard_accel as mod  # type: ignore[import-not-found]
        _SELECTED = RustAccelerator(mod)
        LOGGER.info("rust acceleration active (%s)", getattr(mod, "__version__", "?"))
    except ImportError:
        LOGGER.info("rust acceleration not installed; using Python fallback")
        _SELECTED = PythonAccelerator()
    return _SELECTED


def reset_accelerator() -> None:
    """Drop the cached accelerator (re-detects on next use)."""
    global _SELECTED
    _SELECTED = None


_SELECTED: Any = None

__all__ = [
    "PythonAccelerator",
    "RustAccelerator",
    "accelerator",
    "reset_accelerator",
]
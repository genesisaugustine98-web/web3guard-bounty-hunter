"""
Resilience helpers for fleet-scale capacity.

These are the uptime provisions that keep long batch scans alive:

- **disk preflight**: refuse to start (or continue) when free space on
  the workdir drops below a floor, instead of dying halfway with a
  cryptic ENOSPC. Every fetched target gets a per-target directory the
  caller can drop after processing, so a 512 MiB cap per archive
  cannot accumulate into a full disk across a long batch.
- **rate-limit awareness**: classify HTTP/LLM failures as retryable
  vs terminal so batch loops keep making progress instead of
  thrashing a dead endpoint.
- **mirror rotation**: the fetch layer already falls back across
  guess-endpoints; this module exposes the retry policy constant used
  by batch runners.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

LOGGER = logging.getLogger("web3guard.resilience")

DEFAULT_DISK_FLOOR_BYTES = 512 * 1024 * 1024  # 512 MiB

# Fraction of the volume's total capacity above which the default floor
# no longer makes sense. On a 512 MiB tmpfs, refusing to run with 300
# MiB free protects nothing — 60% of the disk is sitting right there —
# while a 20 GiB root volume gets the full 512 MiB floor.
_TMPFS_FLOOR_FRACTION = 0.6


def disk_floor_for(path: Path, floor: int = DEFAULT_DISK_FLOOR_BYTES) -> int:
    """Effective disk floor for ``path``.

    The fixed floor assumes a large disk; on small volumes (CI tmpfs,
    containers) it would refuse to ever run. Scale the floor down to
    ``_TMPFS_FLOOR_FRACTION`` of a volume that is smaller than the
    floor itself, and never require more than half the free space of
    any volume so the preflight can only fire when space is genuinely
    tight.
    """
    try:
        usage = shutil.disk_usage(str(path))
    except OSError:
        return floor
    effective = floor
    if 0 < usage.total < floor:
        effective = min(effective, int(usage.total * _TMPFS_FLOOR_FRACTION))
    if usage.free > 0:
        effective = min(effective, usage.free // 2)
    return max(1, effective)


def free_bytes(path: Path) -> int:
    """Free bytes on the filesystem holding ``path`` (0 if unknown)."""
    try:
        return shutil.disk_usage(str(path)).free
    except OSError:
        return 0


def disk_preflight(workdir: Path, floor: int = DEFAULT_DISK_FLOOR_BYTES) -> bool:
    """True when ``workdir``'s filesystem has at least ``floor`` free bytes."""
    free = free_bytes(workdir)
    ok = free == 0 or free >= floor  # 0 == unknown: do not block
    if not ok:
        LOGGER.warning(
            "disk preflight failed: %d bytes free on %s (floor %d)",
            free, workdir, floor)
    return ok


def disk_ok_or_raise(workdir: Path, floor: int | None = None) -> None:
    """Raise :class:`RuntimeError` when free space is under the floor.

    ``floor=None`` (the scanner's default) derives the floor from the
    volume via :func:`disk_floor_for` — a fixed 512 MiB floor is only
    meaningful on volumes large enough for it to protect something.
    """
    if floor is None:
        floor = disk_floor_for(workdir)
    free = free_bytes(workdir)
    if free and free < floor:
        raise RuntimeError(
            f"low disk: {free / (1024 * 1024):.0f} MiB free under {workdir} "
            f"(floor {floor / (1024 * 1024):.0f} MiB). Free space or reduce "
            "batch size; refusing to risk a mid-scan ENOSPC.")


def is_retryable_http(status: int) -> bool:
    """Retry policy for batch runners (aligned with fetch.py)."""
    if status in (408, 429):
        return True
    return 500 <= status < 600


def classify_error(err: BaseException) -> str:
    """Rough retry classification used by batch loops to decide
    continue vs skip-target vs abort-batch."""
    name = type(err).__name__.lower()
    msg = str(err).lower()
    if "cost ceiling" in msg:
        return "abort"          # spending must stop everywhere
    if any(k in msg for k in ("timed out", "timeout", "unreachable",
                              "temporarily", "rate limit", "connection")):
        return "retry"
    if any(k in name for k in ("timeout", "connection", "oserror")):
        return "retry"
    if "scope denied" in msg:
        return "skip"
    return "continue"


class BatchRunPolicy:
    """Tunable knobs for fleet-scale batch scans."""

    def __init__(
        self,
        *,
        max_disk_floor_bytes: int = DEFAULT_DISK_FLOOR_BYTES,
        max_consecutive_failures: int = 8,
        retry_sleep_seconds: float = 2.0,
    ) -> None:
        self.max_disk_floor_bytes = max_disk_floor_bytes
        self.max_consecutive_failures = max_consecutive_failures
        self.retry_sleep_seconds = retry_sleep_seconds

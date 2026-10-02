"""Re-dive queue — findings that need human or deeper automated attention.

The queue is a persistent, JSON-backed work list. Two things land here
automatically:

- every ``BAND-AID`` and ``REGRESSED`` verdict, at *every* version they
  appear (mid-history band-aids count, not just the latest version);
- "adjacent code" suggestions — functions/files near a past
  high/critical finding that deserve a fresh look, including cross-file
  neighbours (importers, imports, inheritance kin) from the
  :mod:`web3guard.history.xref` reference map.

Nothing is silently dropped: :meth:`RediveQueue.sync_from_history`
reconciles the queue against a finding's full verdict timeline so every
band-aid, regression, and still-open high/critical lead has a tracked
item, and every item stays tracked until it reaches an explicit
resolved state:

- ``RESOLVED_FIXED`` — re-dived and confirmed fixed;
- ``RESOLVED_ACCEPTED_RISK`` — re-dived; the risk is known and accepted;
- ``RESOLVED_STILL_OPEN`` — re-dived and confirmed still exploitable
  (tracked as a conscious decision, not a forgotten todo).

Items never auto-resolve: when a finding later reads FIXED, open items
from earlier versions get an event noting it ("verify and resolve
explicitly") rather than being closed by the machine.

Storage follows the repo's existing convention: SQLite state lives in
``<workdir>/.web3guard/*.db`` (see :mod:`web3guard.storage`); this queue
is JSON-backed by design, so it lives at
``<workdir>/.web3guard/redive_queue.json`` next to those files. The path
is explicit and overridable — nothing is written to a surprise location.
Writes are atomic (temp file + fsync + rename); a corrupt queue file is
moved aside with a timestamped backup instead of being silently
truncated.

Each item keeps an append-only event log (added / claimed / resolved and
why), so the queue doubles as an audit trail of what was looked at and
what was decided.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from web3guard.history.ingest import AuditFinding
from web3guard.history.verdicts import BAND_AID, REGRESSED, STILL_OPEN, VersionVerdict

if TYPE_CHECKING:
    from web3guard.history.xref import XRefMap

STATUS_OPEN = "open"
STATUS_CLAIMED = "claimed"
STATUS_RESOLVED = "resolved"

# Explicit resolved states. The ``status`` field keeps its historic
# values ("open" / "claimed" / "resolved") for backward compatibility;
# ``outcome`` records *which* resolved state was decided.
RESOLVED_FIXED = "resolved:fixed"
RESOLVED_ACCEPTED_RISK = "resolved:accepted-risk"
RESOLVED_STILL_OPEN = "still-open"
VALID_OUTCOMES = (RESOLVED_FIXED, RESOLVED_ACCEPTED_RISK, RESOLVED_STILL_OPEN)

# Alias: RediveQueue.list (the required queue operation) shadows the
# builtin inside the class body, so annotations there use this alias.
_BuiltinList = list


def _last_claim_at(item: RediveItem) -> float:
    """Timestamp of the latest 'claimed' event; ``created_at`` fallback.

    A claim is a promise to look, not a resolution — so the watchdog
    measures how long ago the promise was made, not how long ago the
    item was created. An item added 30 days ago but claimed yesterday
    is a fresh promise, not a stale one.
    """
    stamps: list[float] = []
    for e in item.events:
        if e.get("event") == "claimed":
            at = e.get("at")
            if isinstance(at, (int, float)):
                stamps.append(float(at))
    return max(stamps) if stamps else item.created_at


def default_queue_path(workdir: str | Path | None = None) -> Path:
    """Queue location following the ``<workdir>/.web3guard/`` convention."""
    base = Path(workdir) if workdir is not None else Path.cwd()
    return base / ".web3guard" / "redive_queue.json"


@dataclass
class RediveItem:
    """One queue entry."""

    id: str
    finding_id: str
    title: str
    reason: str
    status: str = STATUS_OPEN
    claimed_by: str = ""
    created_at: float = field(default_factory=time.time)
    events: list[dict] = field(default_factory=list)
    # Explicit resolved state; "" until resolved. One of VALID_OUTCOMES
    # once status == STATUS_RESOLVED.
    outcome: str = ""

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "title": self.title,
            "reason": self.reason,
            "status": self.status,
            "claimed_by": self.claimed_by,
            "created_at": self.created_at,
            "events": list(self.events),
            "outcome": self.outcome,
        }

    @classmethod
    def from_dict(cls, data: dict) -> RediveItem:
        item = cls(
            id=str(data["id"]),
            finding_id=str(data.get("finding_id", "")),
            title=str(data.get("title", "")),
            reason=str(data.get("reason", "")),
            status=str(data.get("status", STATUS_OPEN)),
            claimed_by=str(data.get("claimed_by", "")),
            created_at=float(data.get("created_at", time.time())),
            events=list(data.get("events", [])),
            outcome=str(data.get("outcome", "")),
        )
        # Legacy items (written before the outcome taxonomy): a resolved
        # item without an outcome is migrated explicitly rather than
        # left ambiguous.
        if item.status == STATUS_RESOLVED and not item.outcome:
            item.outcome = RESOLVED_FIXED
            item.events.append(
                {
                    "at": time.time(),
                    "event": "outcome-migrated",
                    "detail": (
                        "Legacy 'resolved' item migrated to "
                        f"{RESOLVED_FIXED}; re-classify if the decision "
                        "was actually accepted-risk or still-open."
                    ),
                }
            )
        return item

    @property
    def is_terminal(self) -> bool:
        """True once the item reached an explicit resolved state."""
        return self.status == STATUS_RESOLVED and self.outcome in VALID_OUTCOMES


class RediveQueue:
    """Persistent JSON-backed queue of findings needing a re-dive."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else default_queue_path()
        self._items: dict[str, RediveItem] = {}
        self._load()

    # -- persistence ----------------------------------------------------

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self._quarantine_corrupt()
            return
        if not isinstance(raw, list):
            self._quarantine_corrupt()
            return
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            try:
                item = RediveItem.from_dict(entry)
            except (KeyError, TypeError, ValueError):
                continue
            self._items[item.id] = item

    def _quarantine_corrupt(self) -> None:
        """Move a corrupt/unreadable queue file aside; never truncate it."""
        backup = self.path.with_name(
            f"{self.path.stem}.corrupt-{int(time.time())}.bak"
        )
        try:
            self.path.replace(backup)
        except OSError:
            pass

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        payload = [item.as_dict() for item in self._items.values()]
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        tmp.replace(self.path)

    # -- operations -----------------------------------------------------

    def add(
        self,
        finding_id: str,
        title: str,
        reason: str,
        *,
        item_id: str | None = None,
    ) -> RediveItem:
        """Add an item; duplicate (finding_id + reason) adds are merged.

        Merging also applies to resolved items: a human already looked at
        that exact reason, so re-adding it must not resurrect it. A
        genuinely new occurrence carries a different version/evidence in
        its reason and therefore becomes a new item.
        """
        for existing in self._items.values():
            if existing.finding_id == finding_id and existing.reason == reason:
                return existing
        item = RediveItem(
            id=item_id or f"rd-{uuid.uuid4().hex[:8]}",
            finding_id=finding_id,
            title=title,
            reason=reason,
        )
        item.events.append(
            {"at": time.time(), "event": "added", "detail": reason}
        )
        self._items[item.id] = item
        self._save()
        return item

    def list(self, status: str | None = None) -> _BuiltinList[RediveItem]:
        """List items, optionally filtered by status; oldest first."""
        items = sorted(self._items.values(), key=lambda i: i.created_at)
        if status is not None:
            items = [i for i in items if i.status == status]
        return items

    def unresolved(self) -> _BuiltinList[RediveItem]:
        """Every item that has not reached an explicit resolved state."""
        return [i for i in self.list() if not i.is_terminal]

    def get(self, item_id: str) -> RediveItem | None:
        return self._items.get(item_id)

    def claim(self, item_id: str, by: str, note: str = "") -> RediveItem:
        item = self._require(item_id)
        if item.status == STATUS_RESOLVED:
            raise ValueError(f"Item {item_id} is already resolved")
        item.status = STATUS_CLAIMED
        item.claimed_by = by
        item.events.append(
            {"at": time.time(), "event": "claimed", "by": by, "detail": note}
        )
        self._save()
        return item

    def resolve(
        self,
        item_id: str,
        resolution: str,
        by: str = "",
        outcome: str = RESOLVED_FIXED,
    ) -> RediveItem:
        """Resolve an item with an explicit outcome.

        ``resolution`` is the human's free-text note; ``outcome`` must be
        one of ``RESOLVED_FIXED``, ``RESOLVED_ACCEPTED_RISK`` or
        ``RESOLVED_STILL_OPEN``. Items are never auto-resolved: reaching
        this method is always a deliberate decision.
        """
        if outcome not in VALID_OUTCOMES:
            raise ValueError(
                f"outcome must be one of {VALID_OUTCOMES}, got {outcome!r}"
            )
        item = self._require(item_id)
        item.status = STATUS_RESOLVED
        item.outcome = outcome
        item.events.append(
            {
                "at": time.time(),
                "event": "resolved",
                "by": by,
                "outcome": outcome,
                "detail": resolution,
            }
        )
        self._save()
        return item

    def stale_claims(self, max_age_days: float = 14.0) -> _BuiltinList[RediveItem]:
        """Claimed-but-never-resolved items claimed more than
        ``max_age_days`` ago.

        The watchdog for "nothing is silently dropped": a claim is a
        promise to look, not a resolution. Age is measured from the
        latest 'claimed' event — an item created long ago but claimed
        recently is a fresh promise, not a stale one.
        """
        cutoff = time.time() - max_age_days * 86400
        return [
            i
            for i in self.list(status=STATUS_CLAIMED)
            if _last_claim_at(i) < cutoff
        ]

    def _require(self, item_id: str) -> RediveItem:
        item = self._items.get(item_id)
        if item is None:
            raise KeyError(f"Unknown re-dive item {item_id!r}")
        return item

    # -- builders -------------------------------------------------------

    def add_from_verdicts(
        self,
        verdicts: _BuiltinList[VersionVerdict],
        findings: dict[str, AuditFinding] | None = None,
    ) -> _BuiltinList[RediveItem]:
        """Queue every BAND-AID and REGRESSED verdict with its evidence."""
        findings = findings or {}
        added: list[RediveItem] = []
        for v in verdicts:
            if v.verdict not in (BAND_AID, REGRESSED):
                continue
            finding = findings.get(v.finding_id)
            title = finding.title if finding else v.finding_id
            if v.verdict == BAND_AID:
                reason = (
                    f"BAND-AID fix detected at {v.version}: the implicated "
                    f"spot was touched but the same risky property persists "
                    f"(same spot or elsewhere). Re-dive the surrounding "
                    f"code. Evidence: {'; '.join(v.evidence[:3])}"
                )
            else:
                reason = (
                    f"REGRESSION at {v.version}: a previously addressed "
                    f"vulnerable shape has reappeared. Re-dive immediately. "
                    f"Evidence: {'; '.join(v.evidence[:3])}"
                )
            added.append(self.add(v.finding_id, title, reason))
        return added

    def sync_from_history(
        self,
        finding_id: str,
        verdicts: _BuiltinList[VersionVerdict],
        finding: AuditFinding | None = None,
    ) -> _BuiltinList[RediveItem]:
        """Reconcile the queue against one finding's full verdict timeline.

        This is the "misses nothing" entry point: it queues every
        BAND-AID and REGRESSED verdict at *every* version (mid-history
        band-aids count, not just the latest), queues still-open
        high/critical findings at the latest version, and annotates —
        never auto-resolves — open items whose finding later read FIXED
        so a human can verify and resolve them explicitly.

        Idempotent: re-running never duplicates or drops items.
        """
        mine = [v for v in verdicts if v.finding_id == finding_id]
        # Pass the finding through so queued band-aid/regressed items
        # carry the human-readable title (not the raw finding id) —
        # add_from_verdicts falls back to the id when no finding is given.
        added = self.add_from_verdicts(
            mine, {finding_id: finding} if finding is not None else None
        )
        title = finding.title if finding else finding_id
        severity = str(finding.severity).lower() if finding else ""

        latest_fixed_at: str | None = None
        latest_verdict: VersionVerdict | None = None
        for v in verdicts:
            if v.finding_id != finding_id:
                continue
            latest_verdict = v
            if v.verdict == "FIXED":
                latest_fixed_at = v.version

        if (
            latest_verdict is not None
            and latest_verdict.verdict == STILL_OPEN
            and severity in ("critical", "high")
        ):
            reason = (
                f"STILL OPEN at latest version {latest_verdict.version}: "
                f"{severity}-severity finding never addressed. "
                f"Evidence: {'; '.join(latest_verdict.evidence[:3])}"
            )
            added.append(self.add(finding_id, title, reason))

        # Surface superseded items: the finding later read FIXED, so an
        # open item from an earlier band-aid may be closable — but only a
        # human decides that.
        if latest_fixed_at:
            for item in self.list():
                if item.finding_id != finding_id or item.is_terminal:
                    continue
                if any(
                    e.get("event") == "superseded-noted"
                    and latest_fixed_at in e.get("detail", "")
                    for e in item.events
                ):
                    continue
                item.events.append(
                    {
                        "at": time.time(),
                        "event": "superseded-noted",
                        "detail": (
                            f"Finding later read FIXED at {latest_fixed_at}. "
                            f"Verify the fix covers this item's reason, "
                            f"then resolve explicitly "
                            f"({RESOLVED_FIXED} / {RESOLVED_ACCEPTED_RISK} / "
                            f"{RESOLVED_STILL_OPEN})."
                        ),
                    }
                )
            self._save()
        return added

    def add_adjacent_suggestions(
        self,
        suggestions: _BuiltinList[dict],
    ) -> _BuiltinList[RediveItem]:
        """Queue 'adjacent code' suggestions (see :func:`suggest_adjacent`)."""
        added: _BuiltinList[RediveItem] = []
        for s in suggestions:
            reason = (
                f"Adjacent-code re-dive: {s.get('target')} sits "
                f"{s.get('relation')} a past "
                f"{s.get('severity', 'high')}-severity finding "
                f"({s.get('finding_id')}). {s.get('detail', '')}".strip()
            )
            added.append(
                self.add(
                    finding_id=str(s.get("finding_id", "")),
                    title=str(s.get("title", s.get("target", "adjacent code"))),
                    reason=reason,
                )
            )
        return added


def suggest_adjacent(
    findings: list[AuditFinding],
    changed_functions: dict[str, list[str]] | None = None,
    xref: XRefMap | None = None,
) -> list[dict]:
    """Suggest code near past high/critical findings that deserves a re-dive.

    Suggestion kinds:

    - ``same-file``: other functions in a file touched by a past
      high/critical finding (callers must supply the file's function
      list, or pass ``None`` and get a file-level suggestion).
    - ``recently-changed``: functions changed between versions that live
      in a file a past finding implicated (from a
      :class:`~web3guard.history.diff.VersionDiff`'s ``touched_functions()``).
    - ``cross-file`` (needs ``xref``): files that import an implicated
      file, files an implicated file imports, and contracts linked by
      inheritance — the neighbours a same-file-only scan misses.

    Every suggestion is meant to be queued via
    :meth:`RediveQueue.add_adjacent_suggestions` and tracked until it
    reaches an explicit resolved state.
    """
    suggestions: list[dict] = []
    serious = [f for f in findings if f.severity in ("critical", "high")]
    for finding in serious:
        for path in finding.files:
            touched = (changed_functions or {}).get(path, [])
            for fn in touched:
                if fn in finding.functions:
                    continue
                suggestions.append(
                    {
                        "finding_id": finding.id,
                        "title": finding.title,
                        "severity": finding.severity,
                        "target": f"{fn} ({path})",
                        "relation": "in a file implicated by",
                        "detail": (
                            f"{fn} changed recently in {path}, which a past "
                            f"{finding.severity} finding ({finding.id}) also touched."
                        ),
                    }
                )
            if not touched:
                suggestions.append(
                    {
                        "finding_id": finding.id,
                        "title": finding.title,
                        "severity": finding.severity,
                        "target": path,
                        "relation": "implicated by",
                        "detail": (
                            f"{path} was implicated by {finding.id}; review "
                            "neighbouring functions for the same bug class."
                        ),
                    }
                )
            # Cross-file neighbours from the reference map.
            if xref is not None and path in xref.files:
                neighbours = xref.neighbors(path)
                for other in neighbours["importers"]:
                    suggestions.append(
                        {
                            "finding_id": finding.id,
                            "title": finding.title,
                            "severity": finding.severity,
                            "target": other,
                            "relation": "importing code implicated by",
                            "detail": (
                                f"{other} imports {path}, which {finding.id} "
                                f"implicated — callers may inherit the flaw."
                            ),
                        }
                    )
                for other in neighbours["imports"]:
                    suggestions.append(
                        {
                            "finding_id": finding.id,
                            "title": finding.title,
                            "severity": finding.severity,
                            "target": other,
                            "relation": "imported by code implicated by",
                            "detail": (
                                f"{path} (implicated by {finding.id}) imports "
                                f"{other} — shared logic may share the flaw."
                            ),
                        }
                    )
                for other in neighbours["inheritance"]:
                    suggestions.append(
                        {
                            "finding_id": finding.id,
                            "title": finding.title,
                            "severity": finding.severity,
                            "target": other,
                            "relation": "inheritance-linked to code implicated by",
                            "detail": (
                                f"{other} shares an inheritance edge with "
                                f"{path}, implicated by {finding.id} — "
                                f"inherited logic may carry the same flaw."
                            ),
                        }
                    )
    return suggestions

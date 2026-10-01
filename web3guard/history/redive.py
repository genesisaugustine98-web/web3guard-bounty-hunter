"""Re-dive queue — findings that need human or deeper automated attention.

The queue is a persistent, JSON-backed work list. Two things land here
automatically:

- every ``BAND-AID`` (and ``REGRESSED``) verdict — a fix that looks done
  but left the same risky pattern alive elsewhere, or a bug that came
  back;
- "adjacent code" suggestions — functions/files near a past
  high/critical finding that deserve a fresh look.

Storage follows the repo's existing convention: SQLite state lives in
``<workdir>/.web3guard/*.db`` (see :mod:`web3guard.storage`); this queue
is JSON-backed by design, so it lives at
``<workdir>/.web3guard/redive_queue.json`` next to those files. The path
is explicit and overridable — nothing is written to a surprise location.

Each item keeps an append-only event log (added / claimed / resolved and
why), so the queue doubles as an audit trail of what was looked at and
what was decided.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from web3guard.history.ingest import AuditFinding
from web3guard.history.verdicts import BAND_AID, REGRESSED, VersionVerdict

STATUS_OPEN = "open"
STATUS_CLAIMED = "claimed"
STATUS_RESOLVED = "resolved"

# Alias: RediveQueue.list (the required queue operation) shadows the
# builtin inside the class body, so annotations there use this alias.
_BuiltinList = list


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
        }

    @classmethod
    def from_dict(cls, data: dict) -> RediveItem:
        return cls(
            id=str(data["id"]),
            finding_id=str(data.get("finding_id", "")),
            title=str(data.get("title", "")),
            reason=str(data.get("reason", "")),
            status=str(data.get("status", STATUS_OPEN)),
            claimed_by=str(data.get("claimed_by", "")),
            created_at=float(data.get("created_at", time.time())),
            events=list(data.get("events", [])),
        )


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
            raw = []
        for entry in raw if isinstance(raw, list) else []:
            try:
                item = RediveItem.from_dict(entry)
            except (KeyError, TypeError, ValueError):
                continue
            self._items[item.id] = item

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        payload = [item.as_dict() for item in self._items.values()]
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
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

    def resolve(self, item_id: str, resolution: str, by: str = "") -> RediveItem:
        item = self._require(item_id)
        item.status = STATUS_RESOLVED
        item.events.append(
            {"at": time.time(), "event": "resolved", "by": by, "detail": resolution}
        )
        self._save()
        return item

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
                    f"spot was touched but the same risky pattern persists "
                    f"elsewhere. Re-dive the surrounding code. "
                    f"Evidence: {'; '.join(v.evidence[:3])}"
                )
            else:
                reason = (
                    f"REGRESSION at {v.version}: a previously addressed "
                    f"vulnerable shape has reappeared. Re-dive immediately. "
                    f"Evidence: {'; '.join(v.evidence[:3])}"
                )
            added.append(self.add(v.finding_id, title, reason))
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
) -> list[dict]:
    """Suggest code near past high/critical findings that deserves a re-dive.

    Two suggestion kinds:

    - ``same-file``: other functions in a file touched by a past
      high/critical finding (callers must supply the file's function
      list, or pass ``None`` and get a file-level suggestion).
    - ``recently-changed``: functions changed between versions that live
      in a file a past finding implicated (from a
      :class:`~web3guard.history.diff.VersionDiff`'s ``touched_functions()``).
    """
    suggestions: list[dict] = []
    serious = [
        f
        for f in findings
        if f.severity in ("critical", "high")
    ]
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
    return suggestions

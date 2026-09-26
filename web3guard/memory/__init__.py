"""Evidence + security memory for Web3Guard.

v3.5: the scanner forgets everything between runs. A target rescanned
next week re-derives the same findings from scratch, pays for the same
LLM calls, and can re-submit a bounty program's known duplicate.

This module gives the scanner a durable memory:

- **Evidence memory**: verified verdicts (confirmed exploits, ensemble
  overturns, rejected FPs) are stored per fingerprint. On a later run a
  previously-confirmed finding is re-attached instantly and a
  previously-rejected one is skipped — before any LLM spend.
- **Target security profile**: a rollup per target (categories seen,
  confirm rate, adapter reliability) that adaptive planning uses to
  re-rank chunks toward the categories this program actually ships.

Storage goes through :class:`web3guard.storage.durable.DurableStore`
(SQLite locally, Supabase/Postgres when configured), with retention
managed by the store's cleanup pass.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

LOGGER = logging.getLogger("web3guard.memory")


@dataclass
class EvidenceRecord:
    """One durable security verdict."""
    fingerprint: str
    target: str
    category: str = ""
    severity: str = ""
    verdict: str = "unknown"   # confirmed | rejected | overturned | upheld
    evidence: dict[str, Any] = field(default_factory=dict)
    ts: float = 0.0


class SecurityMemory:
    """Durable evidence + target-profile memory."""

    def __init__(self, store: Any) -> None:  # DurableStore
        self._store = store

    # ------------------------------------------------------------------
    # Evidence records
    # ------------------------------------------------------------------

    def remember(self, record: EvidenceRecord) -> None:
        """Upsert a verdict keyed by fingerprint."""
        if not record.ts:
            record.ts = time.time()
        self._store.write("evidence_memory", "fingerprint", {
            "fingerprint": record.fingerprint,
            "target": record.target,
            "category": record.category,
            "severity": record.severity,
            "verdict": record.verdict,
            "evidence": record.evidence,
            "ts": record.ts,
        })

    def lookup(self, fingerprint: str) -> EvidenceRecord | None:
        rows = self._store.local.query_all(
            "SELECT fingerprint, target, category, severity, verdict, evidence, ts"
            " FROM evidence_memory WHERE fingerprint = ?", (fingerprint,))
        if not rows:
            return None
        r = rows[0]
        try:
            evidence = json_loads(r.get("evidence"))
        except Exception:  # noqa: BLE001
            evidence = {}
        return EvidenceRecord(
            fingerprint=r["fingerprint"], target=r.get("target") or "",
            category=r.get("category") or "", severity=r.get("severity") or "",
            verdict=r.get("verdict") or "unknown",
            evidence=evidence, ts=float(r.get("ts") or 0),
        )

    def lookup_many(self, fingerprints: list[str]) -> dict[str, EvidenceRecord]:
        out: dict[str, EvidenceRecord] = {}
        for fp in fingerprints:
            rec = self.lookup(fp)
            if rec is not None:
                out[fp] = rec
        return out

    # ------------------------------------------------------------------
    # Application to a live scan (the actual value)
    # ------------------------------------------------------------------

    def apply_to_findings(self, findings: list[Any]) -> dict[str, int]:
        """Re-attach durable verdicts to a fresh scan's findings.

        - previously **confirmed** findings regain ``CONFIRMED EXPLOIT``
          status and their stored PoC/evidence — no re-exploitation cost;
        - previously **rejected/overturned** findings are marked
          ``REJECTED`` with the stored reason — skipped by reports and
          queues, and the exploit loop is never re-entered.

        Returns counts for the run metadata.
        """
        stats = {"reconfirmed": 0, "pre_rejected": 0}
        for f in findings:
            fp = str(getattr(f, "fingerprint", "") or "")
            if not fp:
                continue
            rec = self.lookup(fp)
            if rec is None:
                continue
            if rec.verdict == "confirmed":
                f.status = "CONFIRMED EXPLOIT"
                f.metadata["memory"] = {
                    "reconfirmed": True,
                    "ts": rec.ts,
                    "poc": rec.evidence.get("poc_code", ""),
                }
                if rec.evidence.get("poc_code") and not getattr(f, "poc_code", ""):
                    f.poc_code = rec.evidence["poc_code"]
                stats["reconfirmed"] += 1
            elif rec.verdict in ("rejected", "overturned"):
                f.status = "REJECTED"
                f.metadata["memory"] = {
                    "pre_rejected": True,
                    "ts": rec.ts,
                    "reason": rec.evidence.get("reason", "prior rejection"),
                }
                stats["pre_rejected"] += 1
        return stats

    def learn_from_result(self, targets: list[Any]) -> dict[str, int]:
        """Store verdicts from a finished scan for future runs."""
        stored = 0
        for tr in targets:
            for f in getattr(tr, "findings", []):
                status = str(getattr(f, "status", ""))
                verdict = None
                if status == "CONFIRMED EXPLOIT":
                    verdict = "confirmed"
                elif status.startswith("REJECTED"):
                    verdict = "rejected"
                elif "overturn" in json_dump_safe(getattr(f, "metadata", {})):
                    verdict = "overturned"
                if verdict is None:
                    continue
                self.remember(EvidenceRecord(
                    fingerprint=str(getattr(f, "fingerprint", "") or ""),
                    target=str(getattr(tr, "target", "")),
                    category=str(getattr(f, "category", "")),
                    severity=str(getattr(f, "severity", "")),
                    verdict=verdict,
                    evidence={
                        "poc_code": str(getattr(f, "poc_code", "") or "")[:20_000],
                        "reason": (getattr(f, "metadata", {}) or {}).get(
                            "rejection_reason", ""),
                    },
                ))
                stored += 1
        return {"stored": stored}

    # ------------------------------------------------------------------
    # Target security profile
    # ------------------------------------------------------------------

    def confirmed_categories(self, target: str) -> list[dict[str, Any]]:
        """Categories with at least one confirmed verdict for ``target``."""
        return self._store.local.query_all(
            "SELECT category, COUNT(*) AS n FROM evidence_memory"
            " WHERE target = ? AND verdict = 'confirmed' AND category != ''"
            " GROUP BY category ORDER BY n DESC", (target,))

    def target_profile(self, target: str) -> dict[str, Any]:
        """Rollup of what this target (or program) looked like before."""
        rows = self._store.local.query_all(
            "SELECT category, severity, verdict, COUNT(*) AS n"
            " FROM evidence_memory WHERE target = ? GROUP BY category, verdict",
            (target,))
        profile: dict[str, Any] = {"categories": {}, "verdicts": {}}
        for r in rows:
            cat = r.get("category") or "uncategorized"
            profile["categories"][cat] = profile["categories"].get(cat, 0) + int(r["n"])
            v = r.get("verdict") or "unknown"
            profile["verdicts"][v] = profile["verdicts"].get(v, 0) + int(r["n"])
        return profile


def json_loads(text: Any) -> Any:
    import json
    return json.loads(text) if isinstance(text, str) else (text or {})


def json_dump_safe(obj: Any) -> str:
    import json
    try:
        return json.dumps(obj, default=str)
    except (TypeError, ValueError):
        return ""

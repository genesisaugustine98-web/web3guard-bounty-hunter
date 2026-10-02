"""'What was fixed in which version' reporting.

Takes per-version verdicts and renders:

- :func:`summarize_verdicts` — a plain Python dict (JSON-serialisable)
  with a per-version counts table and a per-finding timeline.
- :func:`render_text` — the same information in plain English for a
  reader with zero coding knowledge. Phase 7 wires this into the main
  reports; the renderer is kept jargon-light on purpose.
"""

from __future__ import annotations

import json

from web3guard.history.verdicts import (
    BAND_AID,
    FIXED,
    REGRESSED,
    STILL_OPEN,
    VersionVerdict,
)

_COUNT_KEYS = ("fixed", "band_aid", "still_open", "regressed")


def summarize_verdicts(
    verdicts: list[VersionVerdict],
    versions: list[str] | None = None,
) -> dict:
    """Build the per-version summary table plus per-finding timelines."""
    ordered = versions or []
    if not ordered:
        seen: list[str] = []
        for v in verdicts:
            if v.version not in seen:
                seen.append(v.version)
        ordered = seen

    table: dict[str, dict[str, int]] = {
        version: {key: 0 for key in _COUNT_KEYS} for version in ordered
    }
    timeline: dict[str, dict[str, str]] = {}
    for v in verdicts:
        key = {
            FIXED: "fixed",
            BAND_AID: "band_aid",
            STILL_OPEN: "still_open",
            REGRESSED: "regressed",
        }[v.verdict]
        table.setdefault(v.version, {k: 0 for k in _COUNT_KEYS})
        table[v.version][key] += 1
        timeline.setdefault(v.finding_id, {})[v.version] = v.verdict

    return {
        "versions": ordered,
        "per_version": table,
        "per_finding": timeline,
    }


def summarize_to_json(summary: dict) -> str:
    """Serialise a summary dict to JSON."""
    return json.dumps(summary, indent=2)


_PLAIN_LABELS = {
    "fixed": "fully fixed",
    "band_aid": "patched only on the surface (still risky elsewhere)",
    "still_open": "still open",
    "regressed": "fixed before, but the problem came back",
}

_VERDICT_PLAIN = {
    FIXED: "fully fixed",
    BAND_AID: "patched only on the surface — the same risky pattern still exists elsewhere",
    STILL_OPEN: "still open",
    REGRESSED: "was fixed before, but the problem came back",
}


def render_text(summary: dict, title: str = "Audit fix history") -> str:
    """Render a summary in plain, jargon-light English.

    Written for a reader with zero coding knowledge: no mention of
    refs, hunks, or heuristics internals — just what happened to each
    past security issue in each version.
    """
    versions: list[str] = summary.get("versions", [])
    per_version: dict = summary.get("per_version", {})
    lines = [title, "=" * len(title), ""]

    if not versions:
        return "\n".join(lines + ["No versions were analysed yet."])

    for version in versions:
        counts = per_version.get(version, {})
        fixed = counts.get("fixed", 0)
        band_aid = counts.get("band_aid", 0)
        still_open = counts.get("still_open", 0)
        regressed = counts.get("regressed", 0)
        bits = [
            f"{fixed} {_plural(fixed, 'issue')} fully fixed",
            f"{band_aid} patched only on the surface",
            f"{still_open} still open",
            f"{regressed} came back after being fixed",
        ]
        lines.append(f"Version {version}: " + ", ".join(bits) + ".")

    # The bottom line speaks about the *latest* version checked — so it
    # must count only that version. Summing across versions would report
    # issues as needing attention even when they were fixed in the
    # latest version (e.g. STILL OPEN at v1, FIXED at v2).
    lines.append("")
    latest_counts = per_version.get(versions[-1], {})
    latest_fixed = latest_counts.get("fixed", 0)
    latest_open = (
        latest_counts.get("still_open", 0)
        + latest_counts.get("band_aid", 0)
        + latest_counts.get("regressed", 0)
    )
    if latest_fixed and not latest_open:
        lines.append(
            "Bottom line: every past issue we tracked is fully fixed in "
            "the latest version we checked."
        )
    elif latest_open:
        verb = "needs" if latest_open == 1 else "need"
        lines.append(
            f"Bottom line: {latest_open} {_plural(latest_open, 'issue')} "
            f"still {verb} attention in the latest version we checked — "
            "either never fixed, only patched on the surface, or back "
            "after a fix."
        )
    else:
        lines.append("Bottom line: no issues were tracked across these versions.")

    per_finding: dict = summary.get("per_finding", {})
    if per_finding:
        lines += ["", "Issue by issue:"]
        for fid in sorted(per_finding):
            trail = " -> ".join(
                f"{ver}: {_VERDICT_PLAIN.get(per_finding[fid][ver], per_finding[fid][ver])}"
                for ver in versions
                if ver in per_finding[fid]
            )
            lines.append(f"  {fid}: {trail}")
    return "\n".join(lines) + "\n"


def _plural(n: int, word: str) -> str:
    return word if n == 1 else word + "s"


def plain_verdict(verdict: str) -> str:
    """One-line plain-English explanation of a verdict label."""
    return _VERDICT_PLAIN.get(verdict, verdict)

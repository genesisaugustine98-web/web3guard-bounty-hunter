"""Thin CLI entry for the history package.

Phase 7 will wire this fully into :mod:`web3guard.cli`; until then this
module exposes clean, manually invocable subcommands::

    python -m web3guard.history ingest report.md
    python -m web3guard.history diff /path/to/repo v1.0 v2.0
    python -m web3guard.history verdicts /path/to/repo v1.0 v2.0 v3.0 --report report.md
    python -m web3guard.history queue list
    python -m web3guard.history report /path/to/repo v1.0 v2.0 v3.0 --report report.md

Use :func:`register_history_parser` to attach the ``history`` command to
an existing argparse subparsers object (the hook phase 7 will call).
"""

from __future__ import annotations

import argparse
import json
import sys

from web3guard.history.diff import diff_refs
from web3guard.history.ingest import parse_report
from web3guard.history.redive import RediveQueue, default_queue_path
from web3guard.history.report import render_text, summarize_to_json, summarize_verdicts
from web3guard.history.verdicts import walk_all_findings


def _add_history_subcommands(parser: argparse.ArgumentParser) -> None:
    """Attach ingest/diff/verdicts/queue/report subcommands to a parser."""
    sub = parser.add_subparsers(dest="history_cmd", required=True)

    p = sub.add_parser("ingest", help="Parse an audit report into findings")
    p.add_argument("report", help="Path to .md/.txt/.pdf audit report")
    p.add_argument("--json", action="store_true", help="Emit JSON")

    p = sub.add_parser("diff", help="Structured diff between two git refs")
    p.add_argument("repo", help="Local git repo path")
    p.add_argument("ref_a", help="Older ref (tag/commit)")
    p.add_argument("ref_b", help="Newer ref (tag/commit)")

    p = sub.add_parser("verdicts", help="Per-version verdicts for report findings")
    p.add_argument("repo", help="Local git repo path")
    p.add_argument("versions", nargs="+", help="Versions oldest -> newest")
    p.add_argument("--report", required=True, help="Audit report path")
    p.add_argument("--json", action="store_true", help="Emit JSON")

    p = sub.add_parser("queue", help="Re-dive queue operations")
    p.add_argument("op", choices=["list", "add", "claim", "resolve"])
    p.add_argument("--id", dest="item_id", default=None)
    p.add_argument("--finding", default="")
    p.add_argument("--title", default="")
    p.add_argument("--reason", default="")
    p.add_argument("--by", default="")
    p.add_argument("--note", default="")
    p.add_argument("--path", default=None, help="Queue file path override")

    p = sub.add_parser("report", help="'What was fixed in which version' summary")
    p.add_argument("repo", help="Local git repo path")
    p.add_argument("versions", nargs="+", help="Versions oldest -> newest")
    p.add_argument("--report", required=True, help="Audit report path")
    p.add_argument("--json", action="store_true", help="Emit JSON")


def register_history_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:  # noqa: SLF001
    """Attach the ``history`` command; called by web3guard.cli in phase 7."""
    parser = subparsers.add_parser(
        "history",
        help="Audit history: ingest reports, diff versions, verdicts, re-dive queue",
    )
    _add_history_subcommands(parser)
    return parser


def _cmd_ingest(args: argparse.Namespace) -> int:
    report = parse_report(args.report)
    if args.json:
        print(
            json.dumps(
                {
                    "title": report.title,
                    "auditor": report.auditor,
                    "report_date": report.report_date,
                    "findings": [
                        {
                            "id": f.id,
                            "title": f.title,
                            "severity": f.severity,
                            "description": f.description,
                            "files": f.files,
                            "functions": f.functions,
                            "confidence": f.confidence,
                        }
                        for f in report.findings
                    ],
                    "notes": report.notes,
                },
                indent=2,
            )
        )
    else:
        print(f"Report: {report.title}")
        if report.auditor:
            print(f"Auditor: {report.auditor}")
        if report.report_date:
            print(f"Date: {report.report_date}")
        print(f"Findings: {len(report.findings)}")
        for f in report.findings:
            print(f"  [{f.severity}] {f.id}: {f.title} (confidence {f.confidence})")
        for note in report.notes:
            print(f"Note: {note}")
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    diff = diff_refs(args.repo, args.ref_a, args.ref_b)
    print(f"Diff {diff.ref_a}..{diff.ref_b}: {len(diff.files)} file(s) changed")
    for f in diff.files:
        print(f"  {f.status:9s} {f.path}")
    for path, names in diff.touched_functions().items():
        print(f"  functions in {path}: {', '.join(names)}")
    return 0


def _load_verdicts(args: argparse.Namespace) -> tuple[list, list[str]]:
    report = parse_report(args.report)
    by_finding = walk_all_findings(report.findings, args.repo, args.versions)
    verdicts = [v for vs in by_finding.values() for v in vs]
    return verdicts, args.versions


def _cmd_verdicts(args: argparse.Namespace) -> int:
    verdicts, versions = _load_verdicts(args)
    if args.json:
        print(json.dumps([v.as_dict() for v in verdicts], indent=2))
    else:
        for v in verdicts:
            print(f"{v.finding_id} @ {v.version}: {v.verdict} (confidence: {v.confidence})")
            for e in v.evidence:
                print(f"    - {e}")
    return 0


def _cmd_queue(args: argparse.Namespace) -> int:
    queue = RediveQueue(args.path or default_queue_path())
    if args.op == "list":
        items = queue.list()
        if not items:
            print("Re-dive queue is empty.")
        for item in items:
            print(f"[{item.status}] {item.id} ({item.finding_id}): {item.title}")
            print(f"    reason: {item.reason[:160]}")
    elif args.op == "add":
        item = queue.add(args.finding, args.title, args.reason or "manual entry")
        print(f"Added {item.id}")
    elif args.op == "claim":
        item = queue.claim(args.item_id, args.by, args.note)
        print(f"Claimed {item.id} by {args.by}")
    elif args.op == "resolve":
        item = queue.resolve(args.item_id, args.note or args.reason, args.by)
        print(f"Resolved {item.id}")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    verdicts, versions = _load_verdicts(args)
    summary = summarize_verdicts(verdicts, versions)
    if args.json:
        print(summarize_to_json(summary))
    else:
        print(render_text(summary))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="web3guard.history")
    _add_history_subcommands(parser)
    args = parser.parse_args(argv)
    cmd = args.history_cmd
    try:
        if cmd == "ingest":
            return _cmd_ingest(args)
        if cmd == "diff":
            return _cmd_diff(args)
        if cmd == "verdicts":
            return _cmd_verdicts(args)
        if cmd == "queue":
            return _cmd_queue(args)
        if cmd == "report":
            return _cmd_report(args)
    except (ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    parser.error(f"unknown command {cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

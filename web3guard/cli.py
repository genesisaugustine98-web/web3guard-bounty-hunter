"""
Command-line interface for Web3Guard.

Subcommands:

- ``scan``  — run a scan against one or more targets.
- ``dashboard`` — show a TUI of finding-submission history.
- ``mark`` — update a finding's submission status.
- ``serve`` — run a small HTTP server that exposes scan endpoints.
- ``price`` — show the cost-pricing model and current rates.

The CLI is the user-facing entry point; everything in the rest of
the package is importable as a library.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import sys
from pathlib import Path
from typing import Sequence

import web3guard
from web3guard.findings_db import FindingsDB
from web3guard.scanner import Scanner, load_config

LOGGER = logging.getLogger("web3guard.cli")


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge ``override`` over ``base`` (dicts merged, others replaced)."""
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="web3guard",
        description=(
            "Web3Guard — multi-language smart contract vulnerability scanner. "
            f"v{web3guard.__version__}"
        ),
    )
    p.add_argument("-v", "--verbose", action="count", default=0)
    p.add_argument("--config", type=Path, default=None,
                   help="Path to a config.yaml / config.json")
    p.add_argument("--workdir", type=Path, default=Path.cwd(),
                   help="Directory for reports, cache, findings DB")
    sub = p.add_subparsers(dest="command", required=True)

    # ---- scan -----------------------------------------------------------
    scan = sub.add_parser("scan", help="Run a scan against one or more targets")
    scan.add_argument(
        "targets", nargs="+",
        help=(
            "One or more targets in the form <git-url-or-local-path>|<budget>. "
            "Budget is a number (per-chunk token budget) or 'max' for unlimited."
        ),
    )
    scan.add_argument("--min-severity", default="LOW",
                      choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    scan.add_argument("--fork-url", default=None,
                      help="Optional mainnet RPC URL for fork-based PoCs")
    scan.add_argument("--formats", nargs="+", default=None,
                      help="Report formats: txt json sarif md")
    scan.add_argument("--out", type=Path, default=None,
                      help="Output directory for reports")
    scan.add_argument("--no-exploit", action="store_true",
                      help="Skip PoC generation (analysis only)")
    scan.add_argument("--no-self-critique", action="store_true")
    scan.add_argument("--seed", type=int, default=0,
                      help="Random seed for deterministic replays")

    # ---- dashboard ------------------------------------------------------
    dash = sub.add_parser("dashboard", help="Show submission-history dashboard")
    dash.add_argument("--db", type=Path, default=None)

    # ---- mark -----------------------------------------------------------
    mark = sub.add_parser("mark", help="Update a finding's submission status")
    mark.add_argument("fingerprint")
    mark.add_argument("status", choices=[
        "new", "submitted", "accepted", "paid", "rejected", "duplicate",
    ])
    mark.add_argument("--program", default="")
    mark.add_argument("--submission-id", default="")
    mark.add_argument("--paid-amount-usd", type=float, default=0.0)
    mark.add_argument("--rejection-reason", default="")
    mark.add_argument("--note", default="")
    mark.add_argument("--db", type=Path, default=None)

    # ---- serve ----------------------------------------------------------
    serve = sub.add_parser("serve", help="Run an HTTP server exposing scan endpoints")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)

    # ---- price ----------------------------------------------------------
    sub.add_parser("price", help="Show the cost-pricing model")

    # ---- bench ----------------------------------------------------------
    bench = sub.add_parser(
        "bench",
        help=(
            "Run the precision/recall benchmark over a labeled corpus "
            "(default: the in-repo test_contracts fixtures)"
        ),
    )
    bench.add_argument("--corpus", type=Path, default=None,
                       help="Path to a corpus manifest JSON (default: built-in)")
    bench.add_argument("--min-severity", default="LOW",
                       choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    bench.add_argument("--json", type=Path, default=None, dest="json_out",
                       help="Write the full machine-readable report here")
    bench.add_argument("--fail-below", default=None,
                       help="Comma-separated floors 'precision,recall' that "
                            "exit non-zero when breached (CI gate), e.g. 0.9,0.85")
    bench.add_argument("--diff", type=Path, default=None, dest="diff_path",
                       help="Path to a previously-saved --json report; print a "
                            "regression diff against the current run and exit "
                            "non-zero if the run regressed")

    # ---- version --------------------------------------------------------
    sub.add_parser("version", help="Print version and exit")

    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)
    if args.command == "version":
        print(f"web3guard {web3guard.__version__}")
        return 0
    if args.command == "price":
        _cmd_price()
        return 0
    if args.command == "dashboard":
        return _cmd_dashboard(args)
    if args.command == "mark":
        return _cmd_mark(args)
    if args.command == "serve":
        return _cmd_serve(args)
    if args.command == "bench":
        return _cmd_bench(args)
    if args.command == "scan":
        return _cmd_scan(args)
    parser.print_help()
    return 1


def _setup_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _cmd_scan(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    if args.no_exploit:
        cfg["enable_exploit"] = False
    if args.no_self_critique:
        cfg["enable_self_critique"] = False
    if args.fork_url:
        cfg["fork_url"] = args.fork_url
    if args.seed is not None:
        cfg["default_seed"] = args.seed
    scanner = Scanner(config=cfg, workdir=args.workdir)
    result = scanner.scan(args.targets, min_severity=args.min_severity)
    out_dir = args.out or (args.workdir / "reports")
    written = scanner.build_report(
        result,
        formats=args.formats or cfg.get("report_formats"),
        out_dir=out_dir,
    )
    print(f"Web3Guard {web3guard.__version__}")
    print(f"Targets: {len(result.targets)}")
    print(f"Findings: {len(result.all_findings)} "
          f"({len(result.confirmed_findings)} confirmed)")
    cost = result.cost_summary or {}
    print(f"Cost: ${cost.get('total_cost_usd', 0):.4f}")
    print("Reports written:")
    for fmt, path in written.items():
        print(f"  - {fmt}: {path}")
    return 0


def _cmd_bench(args: argparse.Namespace) -> int:
    from web3guard.bench import default_corpus, load_corpus, run_benchmark

    corpus = load_corpus(args.corpus) if args.corpus else default_corpus()
    report = run_benchmark(corpus, min_severity=args.min_severity)

    o = report.overall
    print("=" * 66)
    print(f"  Web3Guard Benchmark — {report.corpus_name}")
    print(f"  units={report.total_units} clean={report.clean_units} "
          f"findings={report.findings}")
    print("=" * 66)
    print(f"  OVERALL   precision={o.precision:.3f}  recall={o.recall:.3f}  "
          f"F1={o.f1:.3f}  (tp={o.tp} fp={o.fp} fn={o.fn})")
    print(f"            weighted precision={o.weighted_precision:.3f}  "
          f"recall={o.weighted_recall:.3f}  F1={o.weighted_f1:.3f}")
    print()
    print("  Per language:")
    for lang, s in sorted(report.per_language.items()):
        print(f"    {lang:<12s} precision={s.precision:.3f}  "
              f"recall={s.recall:.3f}  F1={s.f1:.3f}  "
              f"(tp={s.tp} fp={s.fp} fn={s.fn})")
    print()
    print("  Per category:")
    for cat, s in sorted(report.per_category.items()):
        print(f"    {cat:<22s} precision={s.precision:.3f}  "
              f"recall={s.recall:.3f}  F1={s.f1:.3f}  "
              f"(tp={s.tp} fp={s.fp} fn={s.fn})")
    if report.missed:
        print()
        print("  Missed categories (false negatives):")
        for file, cat in report.missed:
            print(f"    {cat:<22s} {file}")
    if report.false_positives:
        print()
        print("  False positives (category not in ground truth):")
        for f in report.false_positives:
            print(f"    {f.file}:{f.line} [{f.category}]")
    if report.clean_hits:
        print()
        print("  Clean fixtures that triggered findings:")
        for f in report.clean_hits:
            print(f"    {f.file}:{f.line} [{f.category}]")

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"\nFull report written to {args.json_out}")

    if args.diff_path:
        from web3guard.bench import diff_reports
        baseline = json.loads(
            args.diff_path.read_text(encoding="utf-8"))
        d = diff_reports(baseline, report.to_dict())
        status = "REGRESSION" if d["regressed"] else "OK"
        print(f"\nDiff vs {args.diff_path}: [{status}]")
        print(f"  precision delta={d['precision_delta']:+.4f}  "
              f"recall delta={d['recall_delta']:+.4f}  "
              f"F1 delta={d['f1_delta']:+.4f}")
        print(f"  weighted F1 delta={d['weighted_f1_delta']:+.4f}")
        if d["new_false_positives"]:
            print("  NEW false positives:")
            for fp in d["new_false_positives"]:
                print(f"    {fp['file']}:{fp['line']} [{fp['category']}]")
        if d["resolved_false_positives"]:
            print("  resolved false positives:")
            for fp in d["resolved_false_positives"]:
                print(f"    {fp['file']}:{fp['line']} [{fp['category']}]")
        if d["new_missed_categories"]:
            print("  NEW missed categories:")
            for file, cat in d["new_missed_categories"]:
                print(f"    {cat:<22s} {file}")

    if args.fail_below:
        p_floor, r_floor = (float(x) for x in args.fail_below.split(","))
        breached = (o.precision < p_floor) or (o.recall < r_floor)
        print(f"\nGate: precision>={p_floor:.3f} recall>={r_floor:.3f} "
              f"-> {'PASS' if not breached else 'FAIL'}")
        if breached:
            return 1

    if args.diff_path and d["regressed"]:
        return 1
    return 0


def _cmd_dashboard(args: argparse.Namespace) -> int:
    db_path = args.db or (args.workdir / ".web3guard/findings.db")
    db = FindingsDB(db_path)
    summary = db.summary()
    print("=" * 60)
    print("  Web3Guard Dashboard")
    print("=" * 60)
    print(f"  Total findings:  {summary['total']}")
    print(f"  Paid out:        ${summary['paid_total_usd']:,.2f}")
    print()
    print("  By status:")
    for status, count in summary.get("by_status", {}).items():
        print(f"    {status:<12s} {count}")
    print()
    print("  By severity:")
    for sev, count in summary.get("by_severity", {}).items():
        print(f"    {sev:<12s} {count}")
    print()
    print("  Recent findings (status != paid):")
    for f in db.list_findings(limit=20):
        if f.status in ("paid",):
            continue
        print(f"    [{f.severity:<8s}] {f.fingerprint[:16]}  "
              f"{f.target[:40]:<40}  {f.status:<10s}  {f.category}")
    return 0


def _cmd_mark(args: argparse.Namespace) -> int:
    db_path = args.db or (args.workdir / ".web3guard/findings.db")
    db = FindingsDB(db_path)
    db.update_status(
        args.fingerprint,
        args.status,
        note=args.note,
        submission_program=args.program,
        submission_id=args.submission_id,
        paid_amount_usd=args.paid_amount_usd,
        rejection_reason=args.rejection_reason,
    )
    print(f"updated {args.fingerprint} -> {args.status}")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    """Tiny HTTP server for programmatic access.

    Endpoints:
    - GET  /healthz        -> liveness
    - GET  /summary        -> finding summary
    - POST /scan           -> { "targets": [...], "config": {...} }
    - GET  /findings       -> list findings
    - POST /mark           -> { "fingerprint": ..., "status": ... }
    """
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse

    db = FindingsDB(args.workdir / ".web3guard/findings.db")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # noqa: A003
            LOGGER.info("%s - %s", self.address_string(), fmt % args)

        def do_GET(self):  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/healthz":
                self._json({"ok": True, "version": web3guard.__version__})
            elif parsed.path == "/summary":
                self._json(db.summary())
            elif parsed.path == "/findings":
                self._json([dataclasses.asdict(f) for f in db.list_findings(limit=500)])
            else:
                self._json({"error": "not found"}, status=404)

        def do_POST(self):  # noqa: N802
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode("utf-8")
                payload = json.loads(body) if body else {}
            except Exception as e:  # noqa: BLE001
                self._json({"error": f"bad request: {e}"}, status=400)
                return
            parsed = urlparse(self.path)
            if parsed.path == "/mark":
                db.update_status(
                    payload.get("fingerprint", ""),
                    payload.get("status", "new"),
                    note=payload.get("note", ""),
                    submission_program=payload.get("program", ""),
                    submission_id=payload.get("submission_id", ""),
                    paid_amount_usd=float(payload.get("paid_amount_usd", 0) or 0),
                    rejection_reason=payload.get("rejection_reason", ""),
                )
                self._json({"ok": True})
            elif parsed.path == "/scan":
                # Deep-merge the payload config over the file config so a
                # partial payload can never leave the Scanner with a
                # missing ai_providers / invalid schema.
                base_cfg = load_config(args.workdir / "config.yaml")
                cfg = _deep_merge(base_cfg, payload.get("config") or {})
                try:
                    scanner = Scanner(config=cfg, workdir=args.workdir)
                    result = scanner.scan(payload.get("targets", []))
                    written = scanner.build_report(result, out_dir=args.workdir / "reports")
                    self._json({
                        "findings": len(result.all_findings),
                        "confirmed": len(result.confirmed_findings),
                        "cost_usd": result.cost_summary.get("total_cost_usd", 0),
                        "reports": {k: str(v) for k, v in written.items()},
                    })
                except Exception as e:  # noqa: BLE001
                    LOGGER.exception("scan request failed")
                    self._json({"error": f"scan failed: {e}"}, status=500)
            else:
                self._json({"error": "not found"}, status=404)

        def _json(self, payload, status=200):
            data = json.dumps(payload, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    LOGGER.info("Web3Guard HTTP server listening on http://%s:%d", args.host, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
    return 0


def _cmd_price() -> int:
    """Display the cost-pricing model."""
    from web3guard.pricing import (
        compute_estimate,
        pricing_summary,
        DEFAULT_RATES,
    )
    print("=" * 60)
    print("  Web3Guard Pricing — verifier-economics model")
    print("=" * 60)
    print()
    print("Per-finding pricing (researcher side):")
    print("  10% of paid bounty, capped at $50,000 / finding.")
    print()
    print("Per-target subscription (program side):")
    for tier, info in [
        ("Free",     "$0 / month,    1 target,     50 chunks / day"),
        ("Pro",      "$499 / month,  5 targets,    1,000 chunks / day"),
        ("Scale",    "$2,499 / month, 25 targets,  10,000 chunks / day"),
        ("Enterprise", "Contact us, unlimited"),
    ]:
        print(f"  {tier:<10s} {info}")
    print()
    print("Per-call LLM rates (USD / 1M tokens):")
    for model, rate in pricing_summary().items():
        print(f"  {model:<40s} in=${rate.get('input', 0):.3f}  out=${rate.get('output', 0):.3f}")
    print()
    print("Example: scanning a 50-file Solidity repo end-to-end")
    e = compute_estimate(num_chunks=200, model="deepseek-ai/deepseek-v4-flash")
    print(f"  estimated cost: ${e.estimated_cost_usd:.4f}")
    print(f"  estimated time: {e.estimated_seconds:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
Command-line interface for Web3Guard.

Subcommands:

- ``scan``  — run a scan against one or more targets.
- ``dashboard`` — show a TUI of finding-submission history.
- ``digest`` — render a saved scan report as plain-text findings.
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
import os
import sys
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

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
    scan.add_argument("--discovery-only", action="store_true",
                      help="Run offline discovery/static analysis only "
                           "(skip AI chunk analysis)")
    scan.add_argument("--ai-only", action="store_true",
                      help="Run AI chunk analysis only "
                           "(skip offline discovery/static analysis)")
    scan.add_argument("--seed", type=int, default=0,
                      help="Random seed for deterministic replays")
    scan.add_argument("--scan-dependencies", action="store_true",
                      help="Discover and scan the target's declared git "
                           "dependencies (submodules, npm git deps, Cargo / "
                           "Scarb git deps)")
    scan.add_argument("--targets-file", type=Path, default=None,
                      help="File with one target per line (same grammar as "
                           "the positional targets; '#' comments allowed). "
                           "Use for authorized batch/ fleet scanning.")
    scan.add_argument("--parallel", type=int, default=1,
                      help="Scan up to N targets concurrently (default 1). "
                           "LLM rate limits still bound real throughput.")

    # ---- dashboard ------------------------------------------------------
    dash = sub.add_parser("dashboard", help="Show submission-history dashboard")
    dash.add_argument("--db", type=Path, default=None)

    # ---- digest ---------------------------------------------------------
    dig = sub.add_parser(
        "digest",
        help="Render a saved scan report as plain-text findings "
             "(for chat/TUI output, not for the full report files)",
    )
    dig.add_argument("--dir", type=Path, default=None,
                     help="Scan output dir containing WEB3GUARD_FINDINGS.json "
                          "(default: current directory)")
    dig.add_argument("--no-poc", action="store_true",
                     help="Omit PoC code / exploit output from confirmed findings")
    dig.add_argument("--max-findings", type=int, default=0,
                     help="Cap the number of findings rendered (0 = all)")

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
    serve.add_argument("--token", default=None,
                       help="Require this bearer token on mutating endpoints "
                            "(POST /scan, POST /mark). Also: WEB3GUARD_SERVE_TOKEN.")

    # ---- bounties -------------------------------------------------------
    bount = sub.add_parser(
        "bounties", help="Discover public bug-bounty programs (free sources)")
    bount.add_argument("--min-reward", type=float, default=0.0,
                       help="Only show programs with max bounty >= this USD amount")
    bount.add_argument("--json", action="store_true", dest="as_json",
                       help="Emit JSON instead of a table")
    bount.add_argument("--refresh", action="store_true",
                       help="Refresh the program cache from the live source")

    # ---- scope -----------------------------------------------------------
    scope_p = sub.add_parser(
        "scope", help="Check whether a target is inside the authorized scope")
    scope_p.add_argument("target", help="Target string to check")

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
    bench.add_argument("--validate", action="store_true",
                       help="Validate the corpus manifest (paths exist, labels "
                            "are known) and exit non-zero on errors")

    # ---- calibrate ------------------------------------------------------
    cal = sub.add_parser(
        "calibrate",
        help="Measure pipeline precision/recall across calibration layers",
    )
    cal.add_argument("--layers", default="l1",
                     help="Comma-separated layers to run (l1,l2,l3)")
    cal.add_argument("--corpus", type=Path, default=None,
                     help="Main corpus manifest (default: built-in)")
    cal.add_argument("--reachability-corpus", type=Path,
                     default=Path("bench/reachability/corpus.json"),
                     help="Reachability calibration corpus manifest")
    cal.add_argument("--cases", type=Path,
                     default=Path("bench/calibration/cases.json"),
                     help="L2 golden-case manifest")
    cal.add_argument("--live-cases", type=Path,
                     default=Path("bench/calibration/live.json"),
                     help="L3 live-case manifest")
    cal.add_argument("--json", type=Path, default=None, dest="json_out",
                     help="Write the calibration report here")
    cal.add_argument("--fail-on-regression", action="store_true",
                     help="Exit non-zero when L1 precision does not improve")

    # ---- fetch ----------------------------------------------------------
    fetch_p = sub.add_parser(
        "fetch",
        help="Resolve a target (git URL, archive, raw file, IPFS, or 0x "
             "address) to a local directory without scanning",
    )
    fetch_p.add_argument("target", help="Target string (same shapes as scan)")
    fetch_p.add_argument("--keep", action="store_true",
                         help="Print the resolved path and keep it (default "
                              "behavior); without --keep the path is printed "
                              "but registered for cleanup on exit")

    # ---- telegram -------------------------------------------------------
    tg = sub.add_parser(
        "telegram",
        help="Run the Telegram console bot (long-polling; needs "
             "TELEGRAM_BOT_TOKEN)",
    )
    tg.add_argument("--once", action="store_true",
                    help="Process one update batch and exit")

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
    if args.command == "fetch":
        return _cmd_fetch(args)
    if args.command == "telegram":
        from web3guard.telegram_bot import main as tg_main

        return tg_main(["--once"] if args.once else [])
    if args.command == "price":
        _cmd_price()
        return 0
    if args.command == "dashboard":
        return _cmd_dashboard(args)
    if args.command == "digest":
        return _cmd_digest(args)
    if args.command == "mark":
        return _cmd_mark(args)
    if args.command == "serve":
        return _cmd_serve(args)
    if args.command == "bench":
        return _cmd_bench(args)
    if args.command == "calibrate":
        return _cmd_calibrate(args)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "bounties":
        return _cmd_bounties(args)
    if args.command == "scope":
        return _cmd_scope(args)
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
    if args.discovery_only:
        cfg["enable_ai_analysis"] = False
    if args.ai_only:
        cfg["enable_discovery"] = False
    if args.discovery_only and args.ai_only:
        print("error: --discovery-only and --ai-only are mutually exclusive")
        return 2
    if args.fork_url:
        cfg["fork_url"] = args.fork_url
    if args.seed is not None:
        cfg["default_seed"] = args.seed
    if args.scan_dependencies:
        cfg["enable_dependency_scan"] = True

    # v3.4 batch mode: merge --targets-file lines into the target list.
    targets = list(args.targets)
    if args.targets_file is not None:
        try:
            lines = args.targets_file.read_text(encoding="utf-8").splitlines()
        except OSError as e:
            print(f"error: cannot read targets file: {e}", file=sys.stderr)
            return 2
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    if not targets:
        print("error: no targets given (positional or --targets-file)", file=sys.stderr)
        return 2

    parallel = max(1, int(args.parallel or 1))
    scanner = Scanner(config=cfg, workdir=args.workdir)
    if parallel > 1 and len(targets) > 1:
        # Parallel fleet mode. Scanner instances are cheap; the LLM cache
        # DB and findings DB are both SQLite-safe for concurrent writers.
        # Rate limits bound real throughput; this mainly overlaps fetch /
        # discovery / sandbox wall-clock with LLM waiting.
        from concurrent.futures import ThreadPoolExecutor

        # v3.4 resilience: one disk preflight before dispatching the
        # fleet (per-chunk checks happen inside the scanner loop).
        from web3guard.utils.resilience import disk_ok_or_raise
        disk_ok_or_raise(args.workdir)

        def _scan_subset(subset: list[str]) -> Any:
            sub_scanner = Scanner(config=cfg, workdir=args.workdir)
            return sub_scanner.scan(subset, min_severity=args.min_severity)

        chunks = [targets[i::parallel] for i in range(parallel)]
        chunks = [c for c in chunks if c]
        results: list[Any] = []
        errors: list[str] = []
        with ThreadPoolExecutor(max_workers=len(chunks)) as pool:
            futures = [pool.submit(_scan_subset, c) for c in chunks]
            for i, fut in enumerate(futures):
                try:
                    results.append(fut.result())
                except Exception as e:  # noqa: BLE001
                    # v3.4 resilience: one chunk's crash must not lose
                    # the other chunks' completed work.
                    LOGGER.error("batch chunk %d failed: %s", i, e)
                    errors.append(f"chunk {i}: {e}")
        merged_targets = [t for r in results for t in r.targets]
        from web3guard.scanner import ScanResult
        result = ScanResult(
            started_at=min((r.started_at for r in results), default=""),
            finished_at=max((r.finished_at for r in results), default=""),
            config=results[0].config if results else {},
        )
        result.targets = merged_targets
        cost = {"total_cost_usd": 0.0, "calls": 0}
        for r in results:
            c = r.cost_summary or {}
            cost["total_cost_usd"] += float(c.get("total_cost_usd", 0))
            cost["calls"] += int(c.get("calls", 0))
        result.cost_summary = cost
        # v3.4 fixup: propagate per-chunk scan metadata (cost_ceiling,
        # disk_abort, ...) — previously dropped by the merge.
        for r in results:
            for key, value in (r.metadata or {}).items():
                result.metadata.setdefault(key, value)
        if errors:
            result.metadata["batch_chunk_errors"] = errors
    else:
        result = scanner.scan(targets, min_severity=args.min_severity)

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
    if result.metadata.get("cost_ceiling"):
        print("Note: scan stopped early — cost ceiling reached. "
              "Partial results were kept.")
    if result.metadata.get("disk_abort"):
        print("Note: scan stopped early — disk floor reached. "
              "Partial results were kept.")
    for chunk_err in result.metadata.get("batch_chunk_errors", []):
        print(f"Note: {chunk_err} — other chunks completed and were kept.")
    print("Reports written:")
    for fmt, path in written.items():
        print(f"  - {fmt}: {path}")
    denied = [t for t in result.targets if t.metadata.get("scope_denied")]
    if denied:
        print(f"Scope-denied targets (not scanned): {len(denied)} — "
              "see config 'allow:' / 'require_authorized_scope'.")
    return 0


def _cmd_bench(args: argparse.Namespace) -> int:
    from web3guard.bench import default_corpus, load_corpus, run_benchmark
    from web3guard.bench.corpus import validate_corpus

    corpus = load_corpus(args.corpus) if args.corpus else default_corpus()

    if args.validate:
        manifest = args.corpus or "web3guard/bench/corpus.json"
        errors = validate_corpus(manifest)
        if errors:
            print(f"Corpus validation FAILED ({len(errors)} error(s)):")
            for err in errors:
                print(f"  - {err}")
            return 1
        print(f"Corpus {corpus.name}: validation OK "
              f"({len(corpus.units)} units)")
        return 0

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


def _cmd_calibrate(args: argparse.Namespace) -> int:
    from web3guard.bench import default_corpus, load_corpus
    from web3guard.bench.calibration import CalibrationReport, LayerResult

    layers = {x.strip().lower() for x in args.layers.split(",") if x.strip()}
    results: dict[str, LayerResult] = {}

    if "l1" in layers:
        from web3guard.bench.calibration import calibrate_l1

        main = load_corpus(args.corpus) if args.corpus else default_corpus()
        reach = load_corpus(args.reachability_corpus)
        results["l1"] = calibrate_l1(
            main_corpus=main, reachability_corpus=reach)

    if "l2" in layers:
        from web3guard.bench.calibration import calibrate_l2
        from web3guard.bench.cases import load_cases

        cases = load_cases(args.cases)
        results["l2"] = calibrate_l2(
            cases, cases_root=args.cases.parent,
            workdir=Path("bench/calibration/run"))

    if "l3" in layers:
        from web3guard.bench.calibration import calibrate_l3
        from web3guard.bench.cases import load_live_cases

        cases = load_live_cases(args.live_cases)
        results["l3"] = calibrate_l3(
            cases, cases_root=args.live_cases.parent,
            workdir=Path("bench/calibration/run"))

    report = CalibrationReport(layers=results)
    print(json.dumps(report.to_dict(), indent=2))
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"\nCalibration report written to {args.json_out}")

    if args.fail_on_regression and "l1" in results:
        delta = results["l1"].data.get("precision_delta", 0.0)
        recall_delta = results["l1"].data.get("recall_delta", 0.0)
        if delta <= 0 or recall_delta < 0:
            print(f"\nL1 regression: precision_delta={delta} "
                  f"recall_delta={recall_delta}")
            return 1
    return 0


def _cmd_bounties(args: argparse.Namespace) -> int:
    """Discover public bug-bounty programs (free, keyless sources)."""
    from web3guard.utils.bounty import ScopeAllowlist

    wl = ScopeAllowlist([], require_authorized_scope=False,
                        cache_dir=args.workdir / ".web3guard")
    if args.refresh:
        wl.programs(refresh=True)
    programs = wl.discover_bounties(min_reward_usd=args.min_reward)
    if args.as_json:
        print(json.dumps(programs, indent=2))
        return 0
    if not programs:
        print("No programs found (live fetch unavailable; static list empty).")
        return 0
    print(f"{'PROGRAM':<44.44} {'MAX BOUNTY':>12}  {'ASSETS':<18.18} URL")
    for p in programs:
        # discover_bounties returns dict cards (see BountyProgram.to_dict).
        reward = f"${p['max_bounty_usd']:,.0f}" if p["max_bounty_usd"] else "-"
        assets = ", ".join(p["asset_types"][:2]) or "-"
        print(f"{p['name']:<44.44} {reward:>12}  {assets:<18.18} {p['url']}")
    print(f"\n{len(programs)} program(s). Add program names or your own "
          "targets to config 'allow:' to authorize scanning.")
    return 0


def _cmd_scope(args: argparse.Namespace) -> int:
    """Check whether a target is inside the operator's authorized scope."""
    from web3guard.utils.bounty import ScopeAllowlist

    cfg = load_config(args.config)
    wl = ScopeAllowlist(
        cfg.get("allow") or [],
        require_authorized_scope=bool(cfg.get("require_authorized_scope", False)),
        cache_dir=args.workdir / ".web3guard",
    )
    if wl.is_authorized(args.target):
        routes = wl.routes_for(args.target)
        print(f"AUTHORIZED: {args.target}")
        for p in routes:
            print(f"  program: {p.name} ({p.url})")
        return 0
    print(f"DENIED: {args.target} is not in the authorized scope.")
    print("Add it to config 'allow:' (your own targets / approved program "
          "name), or set require_authorized_scope: false if you accept "
          "the legal responsibility.")
    return 1


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


def _cmd_digest(args: argparse.Namespace) -> int:
    """Print the findings of a saved scan as plain text (chat-friendly)."""
    from web3guard.reports.digest import TXT_FILENAME, load_scan_report, render_digest

    dir_path = args.dir or Path.cwd()
    data = load_scan_report(dir_path)
    if data is not None:
        print(render_digest(
            data,
            include_poc=not args.no_poc,
            max_findings=args.max_findings,
        ).rstrip())
        return 0
    # Fall back to the txt report when no JSON is present (e.g. a phase
    # that aborted after writing the report file).
    txt = Path(dir_path) / TXT_FILENAME
    if txt.is_file():
        print(txt.read_text(encoding="utf-8").rstrip())
        return 0
    print(f"error: no scan report found in {dir_path}", file=sys.stderr)
    return 1


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
    """Tiny HTTP server for programmatic and browser access.

    Endpoints:
    - GET  /                -> browser dashboard (alias /dashboard)
    - GET  /healthz         -> liveness
    - GET  /summary         -> finding summary
    - GET  /findings        -> list findings
    - GET  /cost            -> scan cost breakdown by role
    - POST /scan            -> { "targets": [...], "config": {...} }
    - POST /mark            -> { "fingerprint": ..., "status": ... }
    """
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse

    from web3guard.dashboard import dashboard_page

    db = FindingsDB(args.workdir / ".web3guard/findings.db")
    cost_db_path = args.workdir / ".web3guard/cost.db"

    # v3.4 hardening: optional bearer-token auth on mutating endpoints,
    # a request-body cap, and a one-scan-at-a-time semaphore so five
    # concurrent POST /scan calls cannot multiply the LLM bill.
    token = args.token or os.environ.get("WEB3GUARD_SERVE_TOKEN", "")
    max_body = 1 * 1024 * 1024  # 1 MiB is far beyond any legit payload
    scan_slots = threading.Semaphore(1)

    def _authorized(req) -> bool:
        if not token:
            return True  # auth disabled (loopback default; operator opted out)
        header = req.headers.get("Authorization", "")
        return header == f"Bearer {token}"

    def _cost_summary() -> dict[str, Any]:
        """Per-role cost rollup straight from the cost SQLite DB.

        Reads the records directly: CostTracker persists one-way (it
        never re-loads rows at construction), so the dashboard must
        aggregate the DB itself to survive server restarts.
        """
        if not cost_db_path.exists():
            return {"total_cost_usd": 0.0, "by_role": {}}
        import sqlite3
        from contextlib import closing
        try:
            with closing(sqlite3.connect(str(cost_db_path))) as conn:
                total = conn.execute(
                    "SELECT COALESCE(SUM(cost_usd), 0) FROM cost_records"
                ).fetchone()[0]
                rows = conn.execute(
                    "SELECT role, SUM(cost_usd), COUNT(*), "
                    "SUM(prompt_tokens), SUM(completion_tokens) "
                    "FROM cost_records GROUP BY role"
                ).fetchall()
            by_role = {
                role: {
                    "cost": float(cost or 0),
                    "calls": int(calls or 0),
                    "tokens_in": int(tin or 0),
                    "tokens_out": int(tout or 0),
                }
                for role, cost, calls, tin, tout in rows
            }
            return {"total_cost_usd": float(total or 0), "by_role": by_role}
        except Exception as e:  # noqa: BLE001
            LOGGER.warning("could not read cost db: %s", e)
            return {"total_cost_usd": 0.0, "by_role": {}, "error": str(e)}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # noqa: A003
            LOGGER.info("%s - %s", self.address_string(), fmt % args)

        def do_GET(self):  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path in ("/", "/dashboard"):
                body = dashboard_page().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif parsed.path == "/healthz":
                self._json({"ok": True, "version": web3guard.__version__})
            elif parsed.path == "/summary":
                self._json(db.summary())
            elif parsed.path == "/findings":
                self._json([dataclasses.asdict(f) for f in db.list_findings(limit=500)])
            elif parsed.path == "/cost":
                self._json(_cost_summary())
            else:
                self._json({"error": "not found"}, status=404)

        def do_POST(self):  # noqa: N802
            if not _authorized(self):
                self._json({"error": "unauthorized"}, status=401)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > max_body:
                    self._json({"error": "body too large"}, status=413)
                    return
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
                if not scan_slots.acquire(blocking=False):
                    self._json({"error": "a scan is already running; retry later"},
                               status=429)
                    return
                try:
                    # Deep-merge the payload config over the file config so a
                    # partial payload can never leave the Scanner with a
                    # missing ai_providers / invalid schema.
                    base_cfg = load_config(args.workdir / "config.yaml")
                    cfg = _deep_merge(base_cfg, payload.get("config") or {})
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
                finally:
                    scan_slots.release()
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


def _cmd_fetch(args: argparse.Namespace) -> int:
    """Resolve a target to a local directory and print the path."""
    from web3guard.utils.fetch import FetchError, fetch_target

    try:
        path = fetch_target(args.target)
    except FetchError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(path)
    return 0


def _cmd_price() -> int:
    """Display the cost-pricing model."""
    from web3guard.pricing import (
        compute_estimate,
        pricing_summary,
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
    e = compute_estimate(num_chunks=200, model="deepseek-ai/deepseek-v4-flash-0731")
    print(f"  estimated cost: ${e.estimated_cost_usd:.4f}")
    print(f"  estimated time: {e.estimated_seconds:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())

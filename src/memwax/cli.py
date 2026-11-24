"""Command line interface for memwax."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from memwax import __version__
from memwax.adapters import ADAPTERS, get_adapter
from memwax.amber import AmberError, VerifyResult, create_baseline, verify_baseline
from memwax.changelog import ChangeLog, LogEntry
from memwax.detectors import Severity
from memwax.keys import KeyStoreError, encode_public, keys_dir, load_key, load_or_create_key
from memwax.monitor import Monitor
from memwax.report import render_html, render_json, render_text, use_color
from memwax.scanner import Scanner
from memwax.workspace import Config, Workspace

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_INTEGRITY = 2
EXIT_USAGE = 3


def _out(text: str = "") -> None:
    print(text)


def _err(text: str) -> None:
    print(text, file=sys.stderr)


def _describe_source(source: dict) -> str:
    kind = source.get("kind", "unknown")
    if kind == "git":
        return f"git:{source.get('author', '?')}@{source.get('commit', '?')}"
    if kind == "process":
        return f"process:{source.get('declared', '?')}"
    if kind == "memwax":
        return f"memwax:{source.get('action', '?')}"
    return "unknown"


def _format_entry(entry: LogEntry) -> str:
    digest = (entry.sha256 or "-")[:12]
    return (
        f"#{entry.seq:<4} {entry.ts}  {entry.event:<8} {entry.path}  "
        f"sha256={digest}  source={_describe_source(entry.source)}"
    )


# ----- commands ----------------------------------------------------------------
def cmd_init(args: argparse.Namespace) -> int:
    ws = Workspace(args.root)
    adapter = get_adapter(args.adapter)
    config = Config(targets=adapter.default_targets(), adapter=args.adapter)
    if args.target:
        config.targets = list(args.target)
    ws.init(config)
    files = ws.discover(config)
    _out(f"Initialized memwax in {ws.state_dir}")
    _out(f"{len(files)} memory file(s) currently match the targets.")
    return EXIT_OK


def cmd_watch(args: argparse.Namespace) -> int:
    ws = Workspace(args.root)
    if not ws.initialized:
        _err("Not initialized. Run `memwax init` first.")
        return EXIT_USAGE
    monitor = Monitor(ws, use_git=not args.no_git)
    polls = 1 if args.once else args.polls
    if not args.once:
        _out(f"Watching {ws.root} every {args.interval}s (Ctrl+C to stop)")
    try:
        total = monitor.watch(
            interval=args.interval,
            max_polls=polls,
            on_change=lambda entry: _out(_format_entry(entry)),
        )
    except KeyboardInterrupt:
        _out("Stopped.")
        return EXIT_OK
    if args.once:
        _out(f"{total} change(s) recorded.")
    return EXIT_OK


def cmd_log_show(args: argparse.Namespace) -> int:
    log = ChangeLog(Workspace(args.root).log_path)
    entries = log.entries()
    if args.limit:
        entries = entries[-args.limit :]
    if args.json:
        _out(json.dumps([e.to_dict() for e in entries], indent=2))
    else:
        for entry in entries:
            _out(_format_entry(entry))
        if not entries:
            _out("(log is empty)")
    return EXIT_OK


def cmd_log_verify(args: argparse.Namespace) -> int:
    report = ChangeLog(Workspace(args.root).log_path).verify()
    if report.ok:
        _out(f"OK: {report.entries} entries, chain intact, head {report.head[:16]}")
        return EXIT_OK
    _out(f"TAMPERED: {len(report.problems)} problem(s) in {report.entries} entries")
    for problem in report.problems:
        seq = "?" if problem.seq is None else problem.seq
        _out(f"  line {problem.line} (seq {seq}): {problem.message}")
    return EXIT_INTEGRITY


def cmd_amber_create(args: argparse.Namespace) -> int:
    ws = Workspace(args.root)
    if not ws.initialized:
        _err("Not initialized. Run `memwax init` first.")
        return EXIT_USAGE
    try:
        key, created = load_or_create_key()
    except KeyStoreError as exc:
        _err(f"Key error: {exc}")
        return EXIT_USAGE
    if created:
        _out(f"Generated a new signing key {key.key_id} in {keys_dir()}")
        _out("Keep that folder private; it is outside the project on purpose.")
    baseline = create_baseline(ws, key, note=args.note or "")
    _out(
        f"Amber baseline created: {len(baseline.files)} file(s), "
        f"signed by {key.key_id}, digest {baseline.digest[:16]}"
    )
    return EXIT_OK


def print_verify(result: VerifyResult) -> None:
    created = result.baseline.manifest["created_at"] if result.baseline else "?"
    if result.signature_ok:
        _out(f"Signature: OK (key {result.signer}), baseline from {created}")
    else:
        _out("Signature: FAILED")
    for problem in result.integrity_problems:
        _out(f"  INTEGRITY: {problem}")
    drift = result.drift
    if drift.clean:
        _out(f"Drift: none ({drift.unchanged} file(s) unchanged)")
        return
    _out(
        f"Drift: {len(drift.added)} added, {len(drift.changed)} changed, "
        f"{len(drift.removed)} removed, {drift.unchanged} unchanged"
    )
    for rel in drift.added:
        _out(f"  + {rel}")
    for rel in drift.changed:
        _out(f"  ~ {rel}")
    for rel in drift.removed:
        _out(f"  - {rel}")


def cmd_amber_verify(args: argparse.Namespace) -> int:
    ws = Workspace(args.root)
    try:
        result = verify_baseline(ws, extra_pubkeys=args.pubkey or None)
    except AmberError as exc:
        _err(str(exc))
        return EXIT_USAGE
    if args.json:
        _out(json.dumps(result.to_dict(), indent=2))
    else:
        print_verify(result)
    if not result.integrity_ok:
        return EXIT_INTEGRITY
    return EXIT_OK if result.drift.clean else EXIT_FINDINGS


def cmd_key_show(args: argparse.Namespace) -> int:
    try:
        key = load_key()
    except KeyStoreError as exc:
        _err(f"{exc}. A key is created automatically by `memwax amber create`.")
        return EXIT_USAGE
    _out(f"key id:     {key.key_id}")
    _out(f"public key: {encode_public(key.public)}")
    _out(f"location:   {keys_dir()}")
    return EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    ws = Workspace(args.root)
    adapter_name = args.adapter or (ws.load_config().adapter if ws.initialized else "generic")
    try:
        scanner = Scanner(get_adapter(adapter_name))
        min_severity = Severity.parse(args.min_severity)
        fail_on = Severity.parse(args.fail_on)
    except ValueError as exc:
        _err(str(exc))
        return EXIT_USAGE
    if args.paths:
        report = scanner.scan_paths([Path(p) for p in args.paths], root=ws.root)
    else:
        report = scanner.scan_workspace(ws, use_baseline=not args.no_baseline)

    if args.format == "json":
        output = render_json(report)
    elif args.format == "html":
        output = render_html(report, min_severity=min_severity)
    else:
        output = render_text(
            report, min_severity=min_severity, color=args.output is None and use_color()
        )
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        _out(f"Report written to {args.output}")
        if args.format != "text":
            _out(render_text(report, min_severity=Severity.HIGH).splitlines()[-1])
    else:
        sys.stdout.write(output)

    if any(f.detector == "integrity" for f in report.findings):
        return EXIT_INTEGRITY
    return EXIT_FINDINGS if report.at_least(fail_on) else EXIT_OK


# ----- parser ------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="memwax",
        description="Tamper-evident provenance and scanning for AI agent memory.",
    )
    parser.add_argument("--version", action="version", version=f"memwax {__version__}")
    parser.add_argument(
        "--root", type=Path, default=Path.cwd(), help="project root (default: current dir)"
    )
    sub = parser.add_subparsers(dest="command")

    p_init = sub.add_parser("init", help="create .memwax/ and choose which files to track")
    p_init.add_argument(
        "--target",
        action="append",
        metavar="GLOB",
        help="glob (relative to root) of memory files to track; repeatable",
    )
    p_init.add_argument(
        "--adapter",
        choices=sorted(ADAPTERS),
        default="generic",
        help="memory format; sets default targets (default: generic)",
    )
    p_init.set_defaults(func=cmd_init)

    p_scan = sub.add_parser("scan", help="scan memory for suspicious content and drift")
    p_scan.add_argument("paths", nargs="*", help="files/dirs to scan (default: tracked memory)")
    p_scan.add_argument("--adapter", choices=sorted(ADAPTERS), default=None)
    p_scan.add_argument("--format", choices=["text", "json", "html"], default="text")
    p_scan.add_argument("-o", "--output", help="write the report to a file")
    p_scan.add_argument(
        "--min-severity", default="low", help="lowest severity to display (default: low)"
    )
    p_scan.add_argument(
        "--fail-on",
        default="high",
        help="exit 1 if any finding is at or above this severity (default: high)",
    )
    p_scan.add_argument("--no-baseline", action="store_true", help="skip amber/drift checks")
    p_scan.set_defaults(func=cmd_scan)

    p_watch = sub.add_parser("watch", help="record every change to memory files")
    p_watch.add_argument("--interval", type=float, default=2.0, help="seconds between polls")
    p_watch.add_argument("--once", action="store_true", help="poll once and exit")
    p_watch.add_argument("--polls", type=int, default=None, help=argparse.SUPPRESS)
    p_watch.add_argument("--no-git", action="store_true", help="skip git attribution")
    p_watch.set_defaults(func=cmd_watch)

    p_log = sub.add_parser("log", help="inspect or verify the change log")
    log_sub = p_log.add_subparsers(dest="log_command")
    p_show = log_sub.add_parser("show", help="print log entries")
    p_show.add_argument("--limit", type=int, default=0)
    p_show.add_argument("--json", action="store_true")
    p_show.set_defaults(func=cmd_log_show)
    p_verify = log_sub.add_parser("verify", help="check the hash chain")
    p_verify.set_defaults(func=cmd_log_verify)

    p_amber = sub.add_parser("amber", help="signed known-good baselines")
    amber_sub = p_amber.add_subparsers(dest="amber_command")
    p_create = amber_sub.add_parser("create", help="snapshot and sign the current state")
    p_create.add_argument("--note", help="free-text note stored in the baseline")
    p_create.set_defaults(func=cmd_amber_create)
    p_averify = amber_sub.add_parser("verify", help="check signature and report drift")
    p_averify.add_argument("--json", action="store_true")
    p_averify.add_argument(
        "--pubkey", action="append", type=Path, help="extra trusted public key file; repeatable"
    )
    p_averify.set_defaults(func=cmd_amber_verify)

    p_key = sub.add_parser("key", help="signing key management")
    key_sub = p_key.add_subparsers(dest="key_command")
    key_sub.add_parser("show", help="print the public key and key id").set_defaults(
        func=cmd_key_show
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return EXIT_OK
    return func(args)


if __name__ == "__main__":
    sys.exit(main())

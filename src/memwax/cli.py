"""Command line interface for memwax."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from memwax import __version__
from memwax.changelog import ChangeLog, LogEntry
from memwax.monitor import Monitor
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
    config = Config()
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
    p_init.set_defaults(func=cmd_init)

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

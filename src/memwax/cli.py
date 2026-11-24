"""Command line interface for memwax."""

from __future__ import annotations

import argparse
import sys

from memwax import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="memwax",
        description="Tamper-evident provenance and scanning for AI agent memory.",
    )
    parser.add_argument("--version", action="version", version=f"memwax {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())

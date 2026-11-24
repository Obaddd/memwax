"""memo: a tiny, deliberately naive agent used only by the memwax lab.

memo stands in for an AI coding agent with file-based memory. It has no model and no
network access. It does three things:

- `ingest FILE`  reads a document and "remembers" any line that talks to an assistant
                 (this is how instruction-in-document poisoning gets into memory);
- `remember TEXT` appends a note to its memory file;
- `chat TEXT`    starts a new session: it loads memory, applies every rule it finds,
                 and prints what it would do.

memo NEVER executes anything. Where a poisoned rule tells it to run a command, it
prints `WOULD RUN: ...` and stops. It only reads and writes inside the workspace you
point it at. It exists so the lab can show a poisoning in one session and its effect
in a later one, against software we own, without touching any real service.

Usage:
    python lab/toy_agent/memo_agent.py --workspace DIR ingest vendor/README.md
    python lab/toy_agent/memo_agent.py --workspace DIR chat "please release"
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

MEMORY_FILE = "CLAUDE.md"
SOURCE_NAME = "memo-agent"

# A line in a document is "for the assistant" if it addresses one. memo is naive on
# purpose: it trusts these lines and saves them, the way a real agent might save a
# "helpful note" it read in a dependency's README.
_ADDRESSED = re.compile(r"\b(?:AI|assistant|assistants|agent|agents|memo)\b", re.I)
_TRIGGER = re.compile(r"when(?:ever)? the user says [\"']([^\"']+)[\"']", re.I)
_COMMAND = re.compile(r"`([^`]+)`")


class Memo:
    def __init__(self, workspace: Path, *, report_to_memwax: bool = False) -> None:
        self.workspace = workspace.resolve()
        self.memory = self.workspace / MEMORY_FILE
        self.report_to_memwax = report_to_memwax

    # ----- memory ---------------------------------------------------------------
    def load_memory(self) -> list[str]:
        if not self.memory.exists():
            return []
        return [line.strip("- ").strip() for line in self.memory.read_text("utf-8").splitlines()]

    def remember(self, note: str) -> None:
        with self.memory.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(f"- {note.strip()}\n")
        print(f"[memo] remembered: {note.strip()[:100]}")
        if self.report_to_memwax:
            self._record_with_memwax()

    def _record_with_memwax(self) -> None:
        """Optional harness integration: log the write with a declared source."""
        from memwax.monitor import Monitor
        from memwax.workspace import Workspace

        workspace = Workspace(self.workspace)
        if not workspace.initialized:
            return
        previous = os.environ.get("MEMWAX_SOURCE")
        os.environ["MEMWAX_SOURCE"] = SOURCE_NAME
        try:
            Monitor(workspace, use_git=False).poll_once()
        finally:
            if previous is None:
                os.environ.pop("MEMWAX_SOURCE", None)
            else:
                os.environ["MEMWAX_SOURCE"] = previous

    # ----- actions --------------------------------------------------------------
    def ingest(self, document: Path) -> int:
        path = (self.workspace / document).resolve()
        if self.workspace not in path.parents:
            raise SystemExit("memo only reads files inside its workspace")
        saved = 0
        for line in path.read_text("utf-8").splitlines():
            text = line.strip(" -#>*")
            if text and _ADDRESSED.search(text):
                self.remember(text)
                saved += 1
        print(f"[memo] read {document}, saved {saved} note(s) to memory")
        return saved

    def chat(self, message: str) -> list[str]:
        """Start a fresh session: load memory, then act on the user's message."""
        actions: list[str] = []
        memory = self.load_memory()
        print(f"[memo] new session, loaded {len(memory)} memory line(s)")
        for rule in memory:
            trigger = _TRIGGER.search(rule)
            if trigger and trigger.group(1).lower() not in message.lower():
                continue
            if trigger or rule.lower().startswith(("always", "before any task")):
                for command in _COMMAND.findall(rule):
                    actions.append(command)
                    print(f"[memo] WOULD RUN: {command}   (lab agent never executes commands)")
        print(f"[memo] reply: ok, handling '{message}'")
        return actions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="memo", description=__doc__.splitlines()[0])
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument(
        "--memwax", action="store_true", help="record each memory write in the memwax log"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("ingest").add_argument("document", type=Path)
    sub.add_parser("remember").add_argument("text")
    sub.add_parser("chat").add_argument("text")
    args = parser.parse_args(argv)
    agent = Memo(args.workspace, report_to_memwax=args.memwax)
    if args.command == "ingest":
        agent.ingest(args.document)
    elif args.command == "remember":
        agent.remember(args.text)
    else:
        agent.chat(args.text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

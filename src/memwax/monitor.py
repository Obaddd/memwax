"""Watch memory files and record every change in the hash-chained log.

The monitor uses polling rather than OS file-system events. Polling is slower to
notice a change (one interval at most), but it works the same on Windows, macOS and
Linux, needs no extra dependency, and cannot silently miss events when a watcher
buffer overflows: every poll compares full content hashes against the last state.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from memwax.changelog import ChangeLog, LogEntry
from memwax.hashing import sha256_file
from memwax.provenance import detect_source
from memwax.workspace import Workspace


@dataclass(frozen=True)
class FileState:
    sha256: str
    size: int
    mtime_ns: int

    def to_dict(self) -> dict[str, Any]:
        return {"sha256": self.sha256, "size": self.size, "mtime_ns": self.mtime_ns}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileState:
        return cls(str(data["sha256"]), int(data["size"]), int(data["mtime_ns"]))


@dataclass(frozen=True)
class Change:
    event: str  # tracked | added | modified | removed
    path: str
    sha256: str | None
    previous_sha256: str | None
    size: int | None


def take_snapshot(workspace: Workspace) -> dict[str, FileState]:
    """Hash every target file.

    Every file is re-hashed on every poll. Trusting size + mtime would be faster, but
    a same-size edit followed by an mtime reset would then go unnoticed, and memory
    files are small enough that hashing them is cheap.
    """
    snapshot: dict[str, FileState] = {}
    for path in workspace.discover():
        rel = workspace.relpath(path)
        try:
            stat = path.stat()
            digest = sha256_file(path)
        except OSError:
            continue
        snapshot[rel] = FileState(digest, stat.st_size, stat.st_mtime_ns)
    return snapshot


def diff_snapshots(
    old: dict[str, FileState], new: dict[str, FileState], *, initial: bool = False
) -> list[Change]:
    changes: list[Change] = []
    for rel in sorted(set(old) | set(new)):
        before, after = old.get(rel), new.get(rel)
        if before is None and after is not None:
            event = "tracked" if initial else "added"
            changes.append(Change(event, rel, after.sha256, None, after.size))
        elif before is not None and after is None:
            changes.append(Change("removed", rel, None, before.sha256, None))
        elif before and after and before.sha256 != after.sha256:
            changes.append(Change("modified", rel, after.sha256, before.sha256, after.size))
    return changes


class Monitor:
    def __init__(self, workspace: Workspace, *, use_git: bool = True) -> None:
        self.workspace = workspace
        self.log = ChangeLog(workspace.log_path)
        self.use_git = use_git

    # ----- state ---------------------------------------------------------------
    def last_known(self) -> dict[str, str] | None:
        """Replay the log to get the last recorded hash of every live file.

        The log is the only state. There is no separate cache file an attacker could
        edit to make the monitor "forget" a change. Returns None for an empty log.
        """
        entries = self.log.entries()
        if not entries:
            return None
        state: dict[str, str] = {}
        for entry in entries:
            if entry.event == "removed":
                state.pop(entry.path, None)
            elif entry.sha256:
                state[entry.path] = entry.sha256
        return state

    # ----- polling --------------------------------------------------------------
    def poll_once(self) -> list[LogEntry]:
        """Compare the files with the last recorded state and log every difference."""
        known = self.last_known()
        initial = known is None
        previous = {rel: FileState(digest, -1, -1) for rel, digest in (known or {}).items()}
        current = take_snapshot(self.workspace)
        recorded: list[LogEntry] = []
        for change in diff_snapshots(previous, current, initial=initial):
            source = (
                {"kind": "unknown"}
                if change.event == "removed"
                else detect_source(self.workspace.root, change.path, use_git=self.use_git)
            )
            recorded.append(
                self.log.append(
                    change.event,
                    change.path,
                    sha256=change.sha256,
                    previous_sha256=change.previous_sha256,
                    size=change.size,
                    source=source,
                )
            )
        return recorded

    def watch(
        self,
        interval: float = 2.0,
        *,
        max_polls: int | None = None,
        on_change: Callable[[LogEntry], None] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> int:
        """Poll forever (or `max_polls` times). Returns the number of changes logged."""
        polls = 0
        total = 0
        while max_polls is None or polls < max_polls:
            for entry in self.poll_once():
                total += 1
                if on_change:
                    on_change(entry)
            polls += 1
            if max_polls is None or polls < max_polls:
                sleep(interval)
        return total

"""Append-only, hash-chained change log.

Each line of the log is one JSON object. Every entry stores the hash of the entry
before it (`prev`) and its own hash (`hash`), computed over all of its other fields.
Editing, deleting, or reordering any entry breaks the chain from that point on, and
`verify()` reports where. Truncating the *end* of the log cannot be detected by the
chain alone; amber baselines record the log head so that case is caught too
(see `memwax.amber`).
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from memwax.hashing import GENESIS, sha256_json

LOG_FORMAT_VERSION = 1


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class LogEntry:
    seq: int
    ts: str
    event: str
    path: str
    sha256: str | None
    previous_sha256: str | None
    size: int | None
    source: dict[str, Any]
    prev: str
    hash: str
    extra: dict[str, Any] = field(default_factory=dict)

    def body(self) -> dict[str, Any]:
        """Everything except `hash`; this is what the hash covers."""
        return {
            "v": LOG_FORMAT_VERSION,
            "seq": self.seq,
            "ts": self.ts,
            "event": self.event,
            "path": self.path,
            "sha256": self.sha256,
            "previous_sha256": self.previous_sha256,
            "size": self.size,
            "source": self.source,
            "prev": self.prev,
            "extra": self.extra,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "hash": self.hash}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LogEntry:
        return cls(
            seq=int(data["seq"]),
            ts=str(data["ts"]),
            event=str(data["event"]),
            path=str(data["path"]),
            sha256=data.get("sha256"),
            previous_sha256=data.get("previous_sha256"),
            size=data.get("size"),
            source=dict(data.get("source") or {}),
            prev=str(data["prev"]),
            hash=str(data["hash"]),
            extra=dict(data.get("extra") or {}),
        )


@dataclass
class ChainProblem:
    line: int
    seq: int | None
    message: str


@dataclass
class ChainReport:
    entries: int
    head: str
    problems: list[ChainProblem]

    @property
    def ok(self) -> bool:
        return not self.problems


class ChangeLog:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    # ----- reading -----------------------------------------------------------
    def _raw_lines(self) -> Iterator[tuple[int, str]]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                if line.strip():
                    yield number, line

    def entries(self) -> list[LogEntry]:
        return [LogEntry.from_dict(json.loads(line)) for _, line in self._raw_lines()]

    def head(self) -> tuple[int, str]:
        """(seq, hash) of the last entry, or (0, GENESIS) for an empty log."""
        last: LogEntry | None = None
        for _, line in self._raw_lines():
            last = LogEntry.from_dict(json.loads(line))
        if last is None:
            return 0, GENESIS
        return last.seq, last.hash

    # ----- writing -----------------------------------------------------------
    def append(
        self,
        event: str,
        path: str,
        *,
        sha256: str | None,
        previous_sha256: str | None = None,
        size: int | None = None,
        source: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
        ts: str | None = None,
    ) -> LogEntry:
        last_seq, last_hash = self.head()
        partial = LogEntry(
            seq=last_seq + 1,
            ts=ts or utc_now(),
            event=event,
            path=path,
            sha256=sha256,
            previous_sha256=previous_sha256,
            size=size,
            source=source or {"kind": "unknown"},
            prev=last_hash,
            hash="",
            extra=extra or {},
        )
        entry = LogEntry(**{**partial.__dict__, "hash": sha256_json(partial.body())})
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(entry.to_dict(), sort_keys=True, ensure_ascii=False) + "\n"
        # O_APPEND: the OS positions every write at the current end of file.
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        return entry

    # ----- verification ------------------------------------------------------
    def verify(self) -> ChainReport:
        problems: list[ChainProblem] = []
        expected_prev = GENESIS
        expected_seq = 1
        count = 0
        head = GENESIS
        for number, line in self._raw_lines():
            count += 1
            try:
                data = json.loads(line)
                entry = LogEntry.from_dict(data)
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                problems.append(ChainProblem(number, None, f"unparseable entry: {exc}"))
                expected_prev = "<unknown>"
                continue
            if entry.seq != expected_seq:
                problems.append(
                    ChainProblem(
                        number, entry.seq, f"sequence gap: expected {expected_seq}, got {entry.seq}"
                    )
                )
            if entry.prev != expected_prev:
                problems.append(
                    ChainProblem(number, entry.seq, "chain broken: prev does not match prior entry")
                )
            recomputed = sha256_json(entry.body())
            if recomputed != entry.hash:
                problems.append(
                    ChainProblem(number, entry.seq, "entry modified: content hash mismatch")
                )
            # Continue the chain from the stored hash so one edit is reported once,
            # not as a cascade on every later line.
            expected_prev = entry.hash
            expected_seq = entry.seq + 1
            head = entry.hash
        return ChainReport(entries=count, head=head, problems=problems)

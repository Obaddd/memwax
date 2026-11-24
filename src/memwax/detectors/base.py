"""Shared types for content detectors.

A detector receives a `Document` (one memory file, or one entry from a structured
store) and returns `Finding`s. Detectors know nothing about file formats; adapters
turn files into documents.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Protocol


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity {value!r}") from exc

    def bump(self, steps: int = 1) -> Severity:
        return Severity(min(int(self) + steps, int(Severity.CRITICAL)))

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass
class Document:
    """Text to scan, with optional context.

    `line_offset` lets an adapter scan one entry of a larger file and still report
    line numbers relative to the whole file. `baseline_text` is the content of the
    same document in the amber baseline, when one exists.
    """

    path: str
    text: str
    kind: str = "text"
    line_offset: int = 0
    baseline_text: str | None = None
    in_baseline: bool | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._line_starts = [0]
        for index, char in enumerate(self.text):
            if char == "\n":
                self._line_starts.append(index + 1)

    def position(self, offset: int) -> tuple[int, int]:
        """1-based (line, column) of a character offset, including line_offset."""
        line_index = bisect.bisect_right(self._line_starts, offset) - 1
        column = offset - self._line_starts[line_index] + 1
        return line_index + 1 + self.line_offset, column

    def line_text(self, line: int) -> str:
        index = line - 1 - self.line_offset
        if not 0 <= index < len(self._line_starts):
            return ""
        start = self._line_starts[index]
        end = self.text.find("\n", start)
        return self.text[start : end if end != -1 else len(self.text)]


@dataclass
class Finding:
    detector: str
    rule: str
    severity: Severity
    message: str
    path: str
    line: int | None = None
    column: int | None = None
    excerpt: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "rule": self.rule,
            "severity": self.severity.label,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "excerpt": self.excerpt,
            "evidence": self.evidence,
        }


class Detector(Protocol):
    name: str

    def detect(self, doc: Document) -> list[Finding]: ...


def excerpt(text: str, start: int, end: int, width: int = 60) -> str:
    """A short, single-line, printable excerpt around [start, end).

    Context is clipped to the lines the match touches, so an excerpt never drags in
    unrelated neighbouring lines.
    """
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", max(end - 1, start))
    line_end = len(text) if line_end == -1 else line_end
    lo = max(line_start, start - width // 3)
    hi = min(line_end, end + width // 3)
    bounded = lo > line_start, hi < line_end
    snippet = text[lo:hi].replace("\r", " ").replace("\n", " ").replace("\t", " ")
    snippet = "".join(ch if ch.isprintable() else f"<U+{ord(ch):04X}>" for ch in snippet)
    if len(snippet) > width * 2:
        snippet = snippet[: width * 2] + "..."
    return ("..." if bounded[0] else "") + snippet.strip() + ("..." if bounded[1] else "")

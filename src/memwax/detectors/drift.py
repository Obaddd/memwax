"""Detect large or sudden changes compared with the amber baseline.

Needs `Document.baseline_text` (filled in by the scanner from the amber object store)
or `Document.in_baseline=False` for a file that did not exist at baseline time.

Rules:
- drift.new_file      file did not exist in the baseline                         LOW
- drift.large_change  share of lines added/removed since baseline is large       MEDIUM/HIGH
- drift.growth        file grew by a large factor (big blob appended)            MEDIUM/HIGH
- drift.wiped         most of the baseline content is gone                       MEDIUM

Thresholds are deliberately simple and documented so a reviewer can predict them.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass

from memwax.detectors.base import Document, Finding, Severity

NAME = "drift"


@dataclass(frozen=True)
class DriftThresholds:
    changed_ratio_medium: float = 0.5
    changed_ratio_high: float = 0.8
    growth_medium: float = 3.0
    growth_high: float = 10.0
    min_bytes: int = 200  # ignore tiny files where one edit is "100%"


class DriftDetector:
    name = NAME

    def __init__(self, thresholds: DriftThresholds | None = None) -> None:
        self.t = thresholds or DriftThresholds()

    def detect(self, doc: Document) -> list[Finding]:
        if doc.in_baseline is False:
            return [
                Finding(
                    NAME,
                    "drift.new_file",
                    Severity.LOW,
                    "memory file did not exist in the amber baseline",
                    doc.path,
                    evidence={"bytes": len(doc.text.encode("utf-8"))},
                )
            ]
        if doc.baseline_text is None or doc.baseline_text == doc.text:
            return []

        old_lines = doc.baseline_text.splitlines()
        new_lines = doc.text.splitlines()
        matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False)
        added = removed = 0
        first_added_line: int | None = None
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag in ("replace", "delete"):
                removed += i2 - i1
            if tag in ("replace", "insert"):
                added += j2 - j1
                if first_added_line is None:
                    first_added_line = j1 + 1 + doc.line_offset
        total = max(len(old_lines), len(new_lines), 1)
        changed_ratio = max(added, removed) / total
        old_bytes = len(doc.baseline_text.encode("utf-8"))
        new_bytes = len(doc.text.encode("utf-8"))
        evidence = {
            "lines_added": added,
            "lines_removed": removed,
            "changed_ratio": round(changed_ratio, 3),
            "bytes_before": old_bytes,
            "bytes_after": new_bytes,
        }
        findings: list[Finding] = []
        if max(old_bytes, new_bytes) < self.t.min_bytes:
            return findings

        if changed_ratio >= self.t.changed_ratio_medium:
            severity = (
                Severity.HIGH if changed_ratio >= self.t.changed_ratio_high else Severity.MEDIUM
            )
            findings.append(
                Finding(
                    NAME,
                    "drift.large_change",
                    severity,
                    f"{changed_ratio:.0%} of lines changed since baseline (+{added} / -{removed})",
                    doc.path,
                    first_added_line,
                    evidence=evidence,
                )
            )
        growth = new_bytes / max(old_bytes, 1)
        if growth >= self.t.growth_medium:
            severity = Severity.HIGH if growth >= self.t.growth_high else Severity.MEDIUM
            findings.append(
                Finding(
                    NAME,
                    "drift.growth",
                    severity,
                    f"file grew {growth:.1f}x since baseline ({old_bytes} -> {new_bytes} bytes)",
                    doc.path,
                    first_added_line,
                    evidence=evidence,
                )
            )
        if new_bytes < old_bytes * 0.2:
            findings.append(
                Finding(
                    NAME,
                    "drift.wiped",
                    Severity.MEDIUM,
                    f"most baseline content is gone ({old_bytes} -> {new_bytes} bytes)",
                    doc.path,
                    evidence=evidence,
                )
            )
        return findings

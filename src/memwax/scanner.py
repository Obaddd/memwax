"""The scan pipeline: files -> adapter -> documents -> detectors -> report.

Nothing in here knows about a specific memory format. Adapters handle that.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from memwax import __version__
from memwax.adapters import Adapter, get_adapter
from memwax.amber import AmberError, baseline_path, load_object, verify_baseline
from memwax.changelog import ChangeLog, utc_now
from memwax.detectors import Detector, Finding, Severity, default_detectors
from memwax.workspace import Config, Workspace

MAX_FILE_BYTES = 2_000_000


@dataclass
class ScanReport:
    root: str
    adapter: str
    files: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    integrity: dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(default_factory=utc_now)
    version: str = __version__

    def counts(self) -> dict[str, int]:
        counts = {s.label: 0 for s in sorted(Severity, reverse=True)}
        for finding in self.findings:
            counts[finding.severity.label] += 1
        return counts

    @property
    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def at_least(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity >= severity]

    def flagged_files(self, severity: Severity = Severity.MEDIUM) -> set[str]:
        return {_file_of(f.path) for f in self.at_least(severity)}

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "memwax",
            "version": self.version,
            "generated_at": self.generated_at,
            "root": self.root,
            "adapter": self.adapter,
            "files_scanned": self.files,
            "summary": {
                "files": len(self.files),
                "findings": len(self.findings),
                "by_severity": self.counts(),
                "max_severity": self.max_severity.label if self.max_severity is not None else None,
            },
            "integrity": self.integrity,
            "findings": [f.to_dict() for f in self.findings],
        }


def _file_of(path: str) -> str:
    return path.split("#", 1)[0]


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None  # binary
    return data.decode("utf-8", errors="replace")


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Same rule on the same file line from two documents (raw + decoded) -> keep one."""
    best: dict[tuple[str, str, int | None, int | None], Finding] = {}
    for finding in findings:
        key = (finding.rule, _file_of(finding.path), finding.line, finding.column)
        if key not in best or finding.severity > best[key].severity:
            best[key] = finding
    result = list(best.values())
    result.sort(key=lambda f: (-int(f.severity), f.path, f.line or 0, f.column or 0, f.rule))
    return result


class Scanner:
    def __init__(
        self,
        adapter: Adapter | None = None,
        detectors: list[Detector] | None = None,
    ) -> None:
        self.adapter = adapter or get_adapter("generic")
        self.detectors = detectors if detectors is not None else default_detectors()

    # ----- single file -------------------------------------------------------------
    def scan_text(
        self,
        rel: str,
        text: str,
        *,
        baseline_text: str | None = None,
        in_baseline: bool | None = None,
    ) -> list[Finding]:
        parsed = self.adapter.parse(rel, text)
        findings = list(parsed.findings)
        for doc in parsed.documents:
            if doc.path == rel and doc.kind in ("text", "markdown", "json-raw"):
                doc.baseline_text = baseline_text
                doc.in_baseline = in_baseline
            for detector in self.detectors:
                for finding in detector.detect(doc):
                    if doc.meta.get("hidden_from_render") and finding.detector != "drift":
                        finding.severity = finding.severity.bump()
                        finding.message += " (inside a comment hidden when rendered)"
                    findings.append(finding)
        return _dedupe(findings)

    # ----- arbitrary paths ---------------------------------------------------------
    def scan_paths(self, paths: list[Path], root: Path | None = None) -> ScanReport:
        root = (root or Path.cwd()).resolve()
        report = ScanReport(str(root), self.adapter.name)
        files: list[Path] = []
        for path in paths:
            if path.is_dir():
                files.extend(sorted(p for p in path.rglob("*") if p.is_file()))
            elif path.is_file():
                files.append(path)
        findings: list[Finding] = []
        for path in files:
            text = _read_text(path)
            if text is None:
                continue
            try:
                rel = path.resolve().relative_to(root).as_posix()
            except ValueError:
                rel = path.as_posix()
            report.files.append(rel)
            findings.extend(self.scan_text(rel, text))
        report.findings = _dedupe(findings)
        return report

    # ----- workspace -------------------------------------------------------------------
    def scan_workspace(self, ws: Workspace, *, use_baseline: bool = True) -> ScanReport:
        config = (
            ws.load_config() if ws.initialized else Config(targets=self.adapter.default_targets())
        )
        report = ScanReport(str(ws.root), self.adapter.name)
        findings: list[Finding] = []

        baseline_files: dict[str, dict[str, Any]] | None = None
        if use_baseline and baseline_path(ws).exists():
            try:
                result = verify_baseline(ws)
            except AmberError as exc:
                findings.append(_integrity_finding("amber.unreadable", str(exc)))
            else:
                report.integrity = result.to_dict()
                for problem in result.integrity_problems:
                    findings.append(_integrity_finding("amber.integrity", problem))
                if result.integrity_ok and result.baseline is not None:
                    baseline_files = result.baseline.files
                    for rel in result.drift.removed:
                        findings.append(
                            Finding(
                                "drift",
                                "drift.removed",
                                Severity.MEDIUM,
                                "memory file present in the baseline has been removed",
                                rel,
                            )
                        )
        elif ws.log_path.exists():
            chain = ChangeLog(ws.log_path).verify()
            report.integrity = {"log_ok": chain.ok, "log_entries": chain.entries}
            if not chain.ok:
                findings.append(
                    _integrity_finding(
                        "log.integrity", f"change log hash chain broken ({len(chain.problems)})"
                    )
                )

        for path in ws.discover(config):
            rel = ws.relpath(path)
            text = _read_text(path)
            if text is None:
                continue
            report.files.append(rel)
            baseline_text = None
            in_baseline = None
            if baseline_files is not None:
                record = baseline_files.get(rel)
                in_baseline = record is not None
                if record:
                    stored = load_object(ws, record["sha256"])
                    if stored is not None:
                        baseline_text = stored.decode("utf-8", errors="replace")
            findings.extend(
                self.scan_text(rel, text, baseline_text=baseline_text, in_baseline=in_baseline)
            )
        report.findings = _dedupe(findings)
        return report


def _integrity_finding(rule: str, message: str) -> Finding:
    return Finding("integrity", rule, Severity.CRITICAL, message, ".memwax")

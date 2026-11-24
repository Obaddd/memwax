"""Content detectors. Each module is independent and format-agnostic."""

from __future__ import annotations

from memwax.detectors.base import Detector, Document, Finding, Severity
from memwax.detectors.drift import DriftDetector
from memwax.detectors.hidden_chars import HiddenCharDetector
from memwax.detectors.indicators import IndicatorDetector
from memwax.detectors.instructions import InstructionDetector

__all__ = [
    "Detector",
    "Document",
    "DriftDetector",
    "Finding",
    "HiddenCharDetector",
    "IndicatorDetector",
    "InstructionDetector",
    "Severity",
    "default_detectors",
    "run_detectors",
]


def default_detectors() -> list[Detector]:
    return [InstructionDetector(), HiddenCharDetector(), IndicatorDetector(), DriftDetector()]


def run_detectors(doc: Document, detectors: list[Detector] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for detector in detectors if detectors is not None else default_detectors():
        findings.extend(detector.detect(doc))
    findings.sort(key=lambda f: (-int(f.severity), f.path, f.line or 0, f.column or 0, f.rule))
    return findings

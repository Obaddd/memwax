"""Run memwax's content detectors over every lab sample.

Configuration: generic adapter, all default detectors, no amber baseline (so the drift
detector has nothing to compare against and the comparison with tools that have no
file baselines is content-only). Each file is scanned exactly as an agent would load it.

Usage (main venv):  python lab/bench/run_memwax.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import all_samples, environment, read_sample, write_results  # noqa: E402

from memwax import __version__  # noqa: E402
from memwax.scanner import Scanner  # noqa: E402


def main() -> int:
    scanner = Scanner()
    rows = []
    for sample in all_samples():
        text = read_sample(sample["file"])
        started = time.perf_counter()
        findings = scanner.scan_text(sample["file"], text)
        elapsed_us = (time.perf_counter() - started) * 1e6
        top = max((f.severity for f in findings), default=None)
        rows.append(
            {
                "file": sample["file"],
                "label": sample["label"],
                "max_severity": top.label if top is not None else None,
                "max_severity_level": int(top) if top is not None else -1,
                "rules": sorted({f.rule for f in findings}),
                "latency_us": round(elapsed_us, 1),
            }
        )
    path = write_results(
        "memwax",
        {
            "tool": "memwax",
            "version": __version__,
            "config": "generic adapter, default detectors, no baseline",
            "environment": environment(),
            "rows": rows,
        },
    )
    print(f"memwax {__version__}: scanned {len(rows)} files -> {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

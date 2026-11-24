"""Run OWASP Agent Memory Guard over the same lab samples.

Runs in a separate virtual environment (`.venv-amg`) with only agent-memory-guard
installed; it does not import memwax. Three configurations, all taken from AMG itself:

- amg-scan      `agent_memory_guard.scan(text)`: the "simplest entry point" from its API.
                Flagged if `safe` is False.
- amg-strict    AMG's own benchmark adapter `AMGStrictAdapter`
                (`MemoryGuard(policy=Policy.strict())`, the README quickstart).
- amg-hardened  AMG's own `AMGHardenedAdapter` (strict + opt-in persistence detector).
                For both adapters a sample is flagged if the write is not stored as-is
                (blocked, quarantined, or redacted).

Each sample is written as the value of one fresh key ("notes.<id>") on a fresh guard,
with the adapters' default source class, so no state carries between samples.

Usage:  .venv-amg/Scripts/python lab/bench/run_amg.py      (Windows)
        .venv-amg/bin/python lab/bench/run_amg.py          (POSIX)
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import agent_memory_guard  # noqa: E402
from agent_memory_guard.bench.adapter import RememberOutcome  # noqa: E402
from agent_memory_guard.bench.adapters.baseline import (  # noqa: E402
    AMGHardenedAdapter,
    AMGStrictAdapter,
)
from agent_memory_guard.scan import scan  # noqa: E402
from common import all_samples, environment, read_sample, write_results  # noqa: E402


def main() -> int:
    configs = {
        "amg-scan": None,
        "amg-strict": AMGStrictAdapter,
        "amg-hardened": AMGHardenedAdapter,
    }
    rows = []
    for sample in all_samples():
        text = read_sample(sample["file"])
        row = {"file": sample["file"], "label": sample["label"], "results": {}}
        for name, adapter_cls in configs.items():
            started = time.perf_counter()
            if adapter_cls is None:
                result = scan(text)
                flagged = not result.safe
                detail = [t.value for t in result.threats]
            else:
                adapter = adapter_cls()
                outcome = adapter.remember(f"notes.{sample['id']}", text)
                flagged = outcome != RememberOutcome.STORED
                detail = [outcome.value]
            elapsed_us = (time.perf_counter() - started) * 1e6
            row["results"][name] = {
                "flagged": flagged,
                "detail": detail,
                "latency_us": round(elapsed_us, 1),
            }
        rows.append(row)
    path = write_results(
        "amg",
        {
            "tool": "agent-memory-guard",
            "version": agent_memory_guard.__version__,
            "configs": list(configs),
            "environment": environment(),
            "rows": rows,
        },
    )
    print(f"agent-memory-guard {agent_memory_guard.__version__}: {len(rows)} files -> {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

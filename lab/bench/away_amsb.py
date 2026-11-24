"""Away game: run memwax on the attack corpus that ships inside agent-memory-guard.

Our own corpus was written by the same person who wrote memwax's rules, which favours
memwax. AMG's benchmark scenarios (agent_memory_guard.bench.scenarios, AMSB) were
written by the AMG authors for AMG. Scoring both tools on them gives a second,
less biased view.

Two steps, because each tool lives in its own virtual environment:

1. export (AMG venv): read the scenarios and record AMG's verdicts. The payload text is
   written only to lab/runs/ (gitignored) so their corpus is not copied into this repo.
       .venv-amg/Scripts/python lab/bench/away_amsb.py export
2. score (main venv): scan the same payloads with memwax and write lab/results/amsb.json,
   which contains ids, categories and verdicts only.
       .venv/Scripts/python lab/bench/away_amsb.py score

A scenario counts as flagged if *any* of its writes is flagged. memwax scans each
written value as one document (generic adapter, no baseline).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import LAB, environment, write_results  # noqa: E402

EXPORT = LAB / "runs" / "amsb-export.json"


def export() -> int:
    import agent_memory_guard
    from agent_memory_guard.bench.adapter import RememberOutcome
    from agent_memory_guard.bench.adapters.baseline import AMGHardenedAdapter, AMGStrictAdapter
    from agent_memory_guard.bench.scenarios import default_corpus
    from agent_memory_guard.scan import scan

    rows = []
    for sc in default_corpus():
        values = [step.value for step in sc.steps]
        verdicts = {"amg-scan": any(not scan(v).safe for v in values)}
        for name, cls in (("amg-strict", AMGStrictAdapter), ("amg-hardened", AMGHardenedAdapter)):
            adapter = cls()
            flagged = False
            for step in sc.steps:
                outcome = adapter.remember(step.key, step.value, source_class=step.source_class)
                flagged |= outcome != RememberOutcome.STORED
            verdicts[name] = flagged
        rows.append(
            {
                "id": sc.id,
                "category": sc.category,
                "malicious": sc.malicious,
                "values": values,
                "verdicts": verdicts,
            }
        )
    EXPORT.parent.mkdir(parents=True, exist_ok=True)
    EXPORT.write_text(
        json.dumps({"amg_version": agent_memory_guard.__version__, "rows": rows}, indent=1),
        "utf-8",
    )
    print(f"exported {len(rows)} AMSB scenarios -> {EXPORT}")
    return 0


def score() -> int:
    from memwax import __version__
    from memwax.scanner import Scanner

    data = json.loads(EXPORT.read_text("utf-8"))
    scanner = Scanner()
    rows = []
    for row in data["rows"]:
        levels = []
        for index, value in enumerate(row["values"]):
            findings = scanner.scan_text(f"{row['id']}/{index}", value)
            levels.append(max((int(f.severity) for f in findings), default=-1))
        top = max(levels, default=-1)
        rows.append(
            {
                "id": row["id"],
                "category": row["category"],
                "malicious": row["malicious"],
                "verdicts": {
                    **row["verdicts"],
                    "memwax (>= medium)": top >= 2,
                    "memwax (>= high)": top >= 3,
                },
            }
        )
    tools = list(rows[0]["verdicts"])
    attacks = [r for r in rows if r["malicious"]]
    benign = [r for r in rows if not r["malicious"]]
    summary = {}
    for tool in tools:
        summary[tool] = {
            "detected": sum(r["verdicts"][tool] for r in attacks),
            "attacks": len(attacks),
            "false_positives": sum(r["verdicts"][tool] for r in benign),
            "benign": len(benign),
        }
    payload = {
        "corpus": "agent-memory-guard AMSB scenarios",
        "amg_version": data["amg_version"],
        "memwax_version": __version__,
        "environment": environment(),
        "summary": summary,
        "rows": rows,
    }
    path = write_results("amsb", payload)
    for tool, s in summary.items():
        print(
            f"{tool:20} detected {s['detected']}/{s['attacks']}  "
            f"false positives {s['false_positives']}/{s['benign']}"
        )
    print(f"-> {path}")
    return 0


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "export":
        sys.exit(export())
    if command == "score":
        sys.exit(score())
    print(__doc__)
    sys.exit(2)

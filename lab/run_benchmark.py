"""Run the whole lab benchmark end to end.

    python lab/run_benchmark.py            # uses .venv-amg for the AMG side

Steps: build samples -> memwax run -> AMG run (separate venv) -> AMSB away game ->
compare. If the AMG virtual environment is missing, it prints how to create it:

    python -m venv .venv-amg
    .venv-amg/Scripts/python -m pip install agent-memory-guard==0.4.0   (Windows)
    .venv-amg/bin/python -m pip install agent-memory-guard==0.4.0       (POSIX)
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

LAB = Path(__file__).resolve().parent
ROOT = LAB.parent


def amg_python() -> Path | None:
    for candidate in (
        ROOT / ".venv-amg" / "Scripts" / "python.exe",
        ROOT / ".venv-amg" / "bin" / "python",
    ):
        if candidate.exists():
            return candidate
    return None


def run(python: Path | str, *args: str) -> None:
    print(f"$ {Path(python).name} {' '.join(args)}", flush=True)
    subprocess.run([str(python), *args], check=True, cwd=ROOT)


def main() -> int:
    amg = amg_python()
    if amg is None:
        print(__doc__)
        return 1
    here = sys.executable
    run(here, "lab/build_corpus.py")
    run(here, "lab/bench/run_memwax.py")
    run(amg, "lab/bench/run_amg.py")
    run(amg, "lab/bench/away_amsb.py", "export")
    run(here, "lab/bench/away_amsb.py", "score")
    run(here, "lab/bench/compare.py")
    print("\nResults: lab/results/BENCHMARK.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())

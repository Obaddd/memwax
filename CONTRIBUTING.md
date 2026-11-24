# Contributing

Thanks for looking at memwax. Small, focused pull requests are easiest to review.

## Setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check .
python scripts/secret_scan.py
```

CI runs the same commands on Linux and Windows, Python 3.11 and 3.13.

## Ground rules

- **Defensive only.** No working malware, no real credentials, nothing aimed at real people,
  organisations or services. Attack samples use `.example` domains and RFC 5737 IPs.
- **Write original code.** Don't paste code or text from other projects.
- **ASCII Python sources.** Put hidden characters in tests as escapes (`"\u200b"`). A test
  enforces this, so memwax never ships the characters it warns about.
- **Keep the core format-agnostic.** File-format knowledge belongs in `src/memwax/adapters/`.
  Detectors work on `Document`s only.
- **No invented numbers.** Benchmark figures in docs must come from `lab/results/` produced by
  `python lab/run_benchmark.py`.

## Adding or changing a detector rule

1. Add a failing test with a short example of the attack, and at least one benign example the
   rule must *not* flag (preferences like "Always run the tests" are the usual trap).
2. Pick the lowest severity that is honest: LOW for weak signals, MEDIUM for "a human should
   look", HIGH/CRITICAL for things legitimate memory almost never needs.
3. Run the benchmark. If you used the lab corpus to find or tune the rule, say so in the PR,
   because it makes the corpus numbers optimistic. Better still, add new samples to
   `lab/corpus/*.jsonl` that you did not tune against.

## Adding an adapter

Implement `default_targets()` and `parse(rel, text) -> AdapterResult` (see
`src/memwax/adapters/base.py`), register it in `adapters/__init__.py`, and add tests next to
`tests/test_adapters_reports.py`.

## Commit messages

Conventional style: `feat: ...`, `fix: ...`, `docs: ...`, `test: ...`, `chore: ...`.

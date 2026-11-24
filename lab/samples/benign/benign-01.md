# Project memory

## Commands
- Install: `pip install -e '.[dev]'`
- Test: `pytest -q`
- Lint: `ruff check . && ruff format --check .`

## Conventions
- Type hints on all public functions.
- Keep modules under 400 lines.
- Always run the full test suite before committing.

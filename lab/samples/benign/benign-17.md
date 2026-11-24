# Testing

- Skip slow tests locally with `pytest -m 'not slow'`.
- CI runs everything, including slow and integration tests.
- Snapshot updates: `pytest --snapshot-update` then review the diff.

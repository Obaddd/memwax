import json

from memwax.changelog import ChangeLog
from memwax.hashing import GENESIS


def _write_lines(path, lines):
    path.write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in lines), "utf-8")


def _read_lines(path):
    return [json.loads(line) for line in path.read_text("utf-8").splitlines() if line.strip()]


def test_empty_log_verifies(tmp_path):
    log = ChangeLog(tmp_path / "log.jsonl")
    report = log.verify()
    assert report.ok and report.entries == 0 and report.head == GENESIS
    assert log.head() == (0, GENESIS)


def test_entries_chain_together(tmp_path):
    log = ChangeLog(tmp_path / "log.jsonl")
    first = log.append("added", "a.md", sha256="1" * 64, size=3)
    second = log.append("modified", "a.md", sha256="2" * 64, previous_sha256="1" * 64, size=4)
    assert first.prev == GENESIS
    assert second.prev == first.hash
    assert second.seq == 2
    assert log.head() == (2, second.hash)
    assert log.verify().ok


def test_editing_an_entry_is_detected(tmp_path):
    path = tmp_path / "log.jsonl"
    log = ChangeLog(path)
    for i in range(3):
        log.append("added", f"f{i}.md", sha256=str(i) * 64, size=i)
    lines = _read_lines(path)
    lines[1]["path"] = "innocent.md"
    _write_lines(path, lines)
    report = log.verify()
    assert not report.ok
    assert [p.seq for p in report.problems] == [2]
    assert "modified" in report.problems[0].message


def test_rehashed_edit_breaks_the_next_link(tmp_path):
    """An attacker who recomputes the edited entry's hash still breaks entry N+1."""
    from memwax.changelog import LogEntry
    from memwax.hashing import sha256_json

    path = tmp_path / "log.jsonl"
    log = ChangeLog(path)
    for i in range(3):
        log.append("added", f"f{i}.md", sha256=str(i) * 64, size=i)
    lines = _read_lines(path)
    forged = LogEntry.from_dict(lines[0])
    forged = LogEntry(**{**forged.__dict__, "path": "other.md"})
    lines[0] = {**forged.body(), "hash": sha256_json(forged.body())}
    _write_lines(path, lines)
    report = log.verify()
    assert not report.ok
    assert any(p.seq == 2 and "chain broken" in p.message for p in report.problems)


def test_deleted_entry_is_detected(tmp_path):
    path = tmp_path / "log.jsonl"
    log = ChangeLog(path)
    for i in range(3):
        log.append("added", f"f{i}.md", sha256=str(i) * 64, size=i)
    lines = _read_lines(path)
    del lines[1]
    _write_lines(path, lines)
    messages = " ".join(p.message for p in log.verify().problems)
    assert "sequence gap" in messages and "chain broken" in messages


def test_reordered_entries_are_detected(tmp_path):
    path = tmp_path / "log.jsonl"
    log = ChangeLog(path)
    for i in range(3):
        log.append("added", f"f{i}.md", sha256=str(i) * 64, size=i)
    lines = _read_lines(path)
    lines[1], lines[2] = lines[2], lines[1]
    _write_lines(path, lines)
    assert not log.verify().ok


def test_garbage_line_is_reported(tmp_path):
    path = tmp_path / "log.jsonl"
    log = ChangeLog(path)
    log.append("added", "a.md", sha256="a" * 64, size=1)
    with path.open("a", encoding="utf-8") as handle:
        handle.write("{not json\n")
    report = log.verify()
    assert not report.ok
    assert "unparseable" in report.problems[0].message


def test_append_only_never_rewrites_existing_lines(tmp_path):
    path = tmp_path / "log.jsonl"
    log = ChangeLog(path)
    log.append("added", "a.md", sha256="a" * 64, size=1)
    before = path.read_bytes()
    log.append("added", "b.md", sha256="b" * 64, size=1)
    assert path.read_bytes().startswith(before)

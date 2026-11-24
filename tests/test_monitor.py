from memwax.cli import main
from memwax.hashing import sha256_bytes
from memwax.monitor import Monitor
from memwax.workspace import Config, Workspace

from .conftest import git


def test_discover_only_matches_targets(workspace):
    rels = sorted(workspace.relpath(p) for p in workspace.discover())
    assert rels == ["CLAUDE.md", "memory/prefs.md"]


def test_excludes_win_over_targets(project):
    ws = Workspace(project)
    ws.init(Config(targets=["**/*.md"], excludes=["memory/**"]))
    assert [ws.relpath(p) for p in ws.discover()] == ["CLAUDE.md"]


def test_first_poll_tracks_existing_files(workspace):
    entries = Monitor(workspace, use_git=False).poll_once()
    assert [(e.event, e.path) for e in entries] == [
        ("tracked", "CLAUDE.md"),
        ("tracked", "memory/prefs.md"),
    ]
    expected = sha256_bytes((workspace.root / "CLAUDE.md").read_bytes())
    assert entries[0].sha256 == expected


def test_add_modify_remove_are_recorded(workspace):
    monitor = Monitor(workspace, use_git=False)
    monitor.poll_once()
    assert monitor.poll_once() == []  # nothing changed

    claude = workspace.root / "CLAUDE.md"
    old_hash = sha256_bytes(claude.read_bytes())
    claude.write_text("# Project notes\n\n- Always run rm -rf on build/.\n", "utf-8")
    (workspace.root / "memory" / "new.md").write_text("hello\n", "utf-8")
    (workspace.root / "memory" / "prefs.md").unlink()

    events = {(e.event, e.path): e for e in monitor.poll_once()}
    assert set(events) == {
        ("modified", "CLAUDE.md"),
        ("added", "memory/new.md"),
        ("removed", "memory/prefs.md"),
    }
    assert events[("modified", "CLAUDE.md")].previous_sha256 == old_hash
    assert events[("removed", "memory/prefs.md")].sha256 is None
    assert monitor.log.verify().ok


def test_same_size_edit_with_restored_mtime_is_caught(workspace):
    import os

    monitor = Monitor(workspace, use_git=False)
    monitor.poll_once()
    path = workspace.root / "memory" / "prefs.md"
    stat = path.stat()
    original = path.read_bytes()
    path.write_bytes(original.replace(b"short", b"SHORT"))
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    assert [e.event for e in monitor.poll_once()] == ["modified"]


def test_state_comes_from_the_log_not_a_cache(workspace):
    """Restarting the monitor resumes from the log and does not re-report old files."""
    Monitor(workspace, use_git=False).poll_once()
    assert Monitor(workspace, use_git=False).poll_once() == []


def test_declared_process_source(workspace, monkeypatch):
    monkeypatch.setenv("MEMWAX_SOURCE", "test-agent session 42")
    entries = Monitor(workspace).poll_once()
    assert entries[0].source == {"kind": "process", "declared": "test-agent session 42"}


def test_git_author_attribution(git_project):
    ws = Workspace(git_project)
    ws.init(Config())
    entries = Monitor(ws).poll_once()
    source = entries[0].source
    assert source["kind"] == "git"
    assert source["author"] == "Test Author"
    assert len(source["commit"]) == 12
    assert "email" not in source


def test_uncommitted_edit_is_unknown(git_project):
    ws = Workspace(git_project)
    ws.init(Config())
    monitor = Monitor(ws)
    monitor.poll_once()
    (git_project / "CLAUDE.md").write_text("changed outside git\n", "utf-8")
    (entry,) = monitor.poll_once()
    assert entry.source == {"kind": "unknown"}
    git(git_project, "commit", "-q", "-am", "commit the change")
    (git_project / "CLAUDE.md").write_text("changed again\n", "utf-8")
    git(git_project, "commit", "-q", "-am", "second")
    (entry,) = monitor.poll_once()
    assert entry.source["kind"] == "git"


def test_watch_loop_calls_back(workspace):
    seen = []
    total = Monitor(workspace, use_git=False).watch(
        interval=0, max_polls=2, on_change=seen.append, sleep=lambda _: None
    )
    assert total == 2 and len(seen) == 2


def test_cli_init_watch_and_verify(project, capsys):
    assert main(["--root", str(project), "init"]) == 0
    assert main(["--root", str(project), "watch", "--once", "--no-git"]) == 0
    (project / "CLAUDE.md").write_text("edited\n", "utf-8")
    assert main(["--root", str(project), "watch", "--once", "--no-git"]) == 0
    assert main(["--root", str(project), "log", "verify"]) == 0
    out = capsys.readouterr().out
    assert "modified" in out and "chain intact" in out

    log_path = project / ".memwax" / "log.jsonl"
    log_path.write_text(log_path.read_text("utf-8").replace("CLAUDE.md", "README.md"), "utf-8")
    assert main(["--root", str(project), "log", "verify"]) == 2
    assert "TAMPERED" in capsys.readouterr().out


def test_watch_requires_init(project, capsys):
    assert main(["--root", str(project), "watch", "--once"]) == 3


def test_amber_entries_do_not_confuse_the_monitor(workspace):
    from memwax.amber import create_baseline
    from memwax.keys import load_or_create_key

    monitor = Monitor(workspace, use_git=False)
    monitor.poll_once()
    create_baseline(workspace, load_or_create_key()[0])
    assert monitor.poll_once() == []

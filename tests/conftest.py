from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from memwax.workspace import Config, Workspace


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch, tmp_path):
    monkeypatch.delenv("MEMWAX_SOURCE", raising=False)
    # Keys must never land in the real home directory during tests.
    monkeypatch.setenv("MEMWAX_HOME", str(tmp_path / "memwax-home"))


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    (root / "CLAUDE.md").write_text("# Project notes\n\n- Use pytest for tests.\n", "utf-8")
    (root / "memory").mkdir()
    (root / "memory" / "prefs.md").write_text("- Prefers short commit messages.\n", "utf-8")
    (root / "src.py").write_text("print('not memory')\n", "utf-8")
    return root


@pytest.fixture
def workspace(project: Path) -> Workspace:
    ws = Workspace(project)
    ws.init(Config())
    return ws


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


@pytest.fixture
def git_project(project: Path) -> Path:
    git(project, "init", "-q", "-b", "main")
    git(project, "config", "user.name", "Test Author")
    git(project, "config", "user.email", "author@example.invalid")
    git(project, "config", "commit.gpgsign", "false")
    git(project, "add", "-A")
    git(project, "commit", "-q", "-m", "initial")
    return project

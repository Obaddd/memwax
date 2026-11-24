"""A workspace is a project root plus the `.memwax/` state directory inside it."""

from __future__ import annotations

import fnmatch
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

STATE_DIR = ".memwax"
CONFIG_FILE = "config.json"

# Sensible defaults for file-based agent memory. Adapters can extend these.
DEFAULT_TARGETS = [
    "CLAUDE.md",
    "CLAUDE.local.md",
    "**/CLAUDE.md",
    ".claude/**/*.md",
    "memory/**/*",
    ".memory/**/*",
    "AGENTS.md",
]
DEFAULT_EXCLUDES = [
    ".git/**",
    ".memwax/**",
    "**/node_modules/**",
    "**/.venv/**",
    "**/__pycache__/**",
]


class WorkspaceError(Exception):
    pass


@dataclass
class Config:
    targets: list[str] = field(default_factory=lambda: list(DEFAULT_TARGETS))
    excludes: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    adapter: str = "generic"
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "adapter": self.adapter,
            "targets": self.targets,
            "excludes": self.excludes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        return cls(
            targets=list(data.get("targets", DEFAULT_TARGETS)),
            excludes=list(data.get("excludes", DEFAULT_EXCLUDES)),
            adapter=str(data.get("adapter", "generic")),
            version=int(data.get("version", 1)),
        )


def atomic_write_text(path: Path, text: str) -> None:
    """Write a file so readers never see a half-written version."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


class Workspace:
    def __init__(self, root: Path | str) -> None:
        self.root = Path(root).resolve()
        self.state_dir = self.root / STATE_DIR

    # ----- paths -------------------------------------------------------------
    @property
    def config_path(self) -> Path:
        return self.state_dir / CONFIG_FILE

    @property
    def log_path(self) -> Path:
        return self.state_dir / "log.jsonl"

    @property
    def amber_dir(self) -> Path:
        return self.state_dir / "amber"

    def relpath(self, path: Path) -> str:
        return path.resolve().relative_to(self.root).as_posix()

    # ----- config ------------------------------------------------------------
    @property
    def initialized(self) -> bool:
        return self.config_path.exists()

    def init(self, config: Config | None = None) -> Config:
        config = config or Config()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        # The state dir holds logs and baselines; it should never be committed by accident.
        gitignore = self.state_dir / ".gitignore"
        if not gitignore.exists():
            gitignore.write_text("*\n", encoding="utf-8")
        self.save_config(config)
        return config

    def load_config(self) -> Config:
        if not self.config_path.exists():
            return Config()
        try:
            return Config.from_dict(json.loads(self.config_path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, ValueError) as exc:
            raise WorkspaceError(f"invalid config at {self.config_path}: {exc}") from exc

    def save_config(self, config: Config) -> None:
        atomic_write_text(self.config_path, json.dumps(config.to_dict(), indent=2) + "\n")

    # ----- discovery ---------------------------------------------------------
    def discover(self, config: Config | None = None) -> list[Path]:
        """Return every regular file under root matched by a target and no exclude."""
        config = config or self.load_config()
        found: set[Path] = set()
        for pattern in config.targets:
            for candidate in self.root.glob(pattern):
                if candidate.is_file() and not candidate.is_symlink():
                    rel = self.relpath(candidate)
                    if not _excluded(rel, config.excludes):
                        found.add(candidate.resolve())
        return sorted(found)


def _excluded(rel: str, excludes: list[str]) -> bool:
    for pattern in excludes:
        if fnmatch.fnmatch(rel, pattern):
            return True
        # "dir/**" should also exclude files directly in dir.
        if pattern.endswith("/**") and (rel + "/").startswith(pattern[:-2]):
            return True
        if pattern.startswith("**/") and fnmatch.fnmatch(rel, pattern[3:]):
            return True
    return False

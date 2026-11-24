"""Best-effort attribution of a file change to a source.

Order of evidence:

1. `MEMWAX_SOURCE` in the environment. A wrapper script or agent harness that writes
   memory can set this to declare itself (recorded as kind "process"). It is a claim,
   not proof, and is recorded as such.
2. git. If the file's current content is exactly the content committed at HEAD, the
   change is attributed to the author of the last commit that touched the file.
3. Otherwise "unknown". In particular, an uncommitted edit is *not* attributed to the
   local git user, because nothing proves that user (rather than a tool running as
   them) made it.

Only the commit author's name and the commit id are recorded, not their email.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any

ENV_VAR = "MEMWAX_SOURCE"
_GIT_TIMEOUT = 5


@lru_cache(maxsize=1)
def _git_binary() -> str | None:
    return shutil.which("git")


def _git(root: Path, *args: str) -> str | None:
    git = _git_binary()
    if git is None:
        return None
    try:
        result = subprocess.run(
            [git, "-C", str(root), *args],
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def git_attribution(root: Path, relpath: str) -> dict[str, Any] | None:
    """Return a git source if the working-tree file matches HEAD, else None."""
    if _git(root, "rev-parse", "--is-inside-work-tree") != "true":
        return None
    head_blob = _git(root, "rev-parse", f"HEAD:{relpath}")
    if not head_blob:
        return None
    work_blob = _git(root, "hash-object", "--", relpath)
    if work_blob != head_blob:
        return None
    line = _git(root, "log", "-1", "--format=%H%x1f%an%x1f%aI", "--", relpath)
    if not line:
        return None
    commit, author, when = (line.split("\x1f") + ["", "", ""])[:3]
    return {"kind": "git", "author": author, "commit": commit[:12], "committed_at": when}


def detect_source(root: Path, relpath: str, *, use_git: bool = True) -> dict[str, Any]:
    declared = os.environ.get(ENV_VAR, "").strip()
    if declared:
        return {"kind": "process", "declared": declared[:200]}
    if use_git:
        attributed = git_attribution(root, relpath)
        if attributed:
            return attributed
    return {"kind": "unknown"}

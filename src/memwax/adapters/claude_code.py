"""Adapter for Claude Code-style project memory.

Files: CLAUDE.md (root and nested), CLAUDE.local.md, and the `.claude/` folder
(agents, commands, skills, rules, settings).

What it adds on top of the generic adapter:

- Markdown HTML comments (`<!-- ... -->`) are invisible in a rendered preview but
  are read by the model. Their content is emitted as a separate document marked
  `hidden_from_render`, which makes the core raise the severity of anything found in it.
- `@path` imports in CLAUDE.md pull other files into memory. Imports that reach
  outside the project (absolute paths, `~`, `..`) are reported.
- `.claude/settings*.json`: hook commands are scanned as shell, and settings that
  remove permission prompts (bypassPermissions, blanket `Bash(*)` allow rules) are
  reported.

This mirrors the file layout documented for Claude Code; it does not import or
depend on Claude Code itself.
"""

from __future__ import annotations

import json
import re
from typing import Any

from memwax.adapters.base import AdapterResult
from memwax.adapters.generic import GenericFileAdapter
from memwax.detectors.base import Document, Finding, Severity

NAME = "claude_code"

TARGETS = [
    "CLAUDE.md",
    "CLAUDE.local.md",
    "**/CLAUDE.md",
    "**/CLAUDE.local.md",
    ".claude/CLAUDE.md",
    ".claude/**/*.md",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".mcp.json",
]

COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
# `@path` at line start or after whitespace, not an email address or a code decorator.
IMPORT_RE = re.compile(r"(?:(?<=\s)|^)@((?:~|\.{1,2}|/|[A-Za-z]:[\\/])?[\w./\\~-]+)", re.M)
FENCE_RE = re.compile(r"^```.*?^```", re.M | re.S)


class ClaudeCodeAdapter:
    name = "claude-code"

    def default_targets(self) -> list[str]:
        return list(TARGETS)

    def parse(self, rel: str, text: str) -> AdapterResult:
        lower = rel.lower()
        if lower.endswith(".json"):
            return self._settings(rel, text)
        result = AdapterResult([Document(rel, text, kind="markdown")])
        result.documents.extend(self._comments(rel, text))
        result.findings.extend(self._imports(rel, text))
        return result

    # ----- markdown --------------------------------------------------------------
    def _comments(self, rel: str, text: str) -> list[Document]:
        docs = []
        for match in COMMENT_RE.finditer(text):
            body = match.group(1)
            if not body.strip():
                continue
            prefix = text[: match.start(1)]
            line_offset = prefix.count("\n")
            # Pad the first line so column numbers stay right.
            col = match.start(1) - (prefix.rfind("\n") + 1)
            docs.append(
                Document(
                    rel,
                    " " * col + body,
                    kind="markdown-comment",
                    line_offset=line_offset,
                    meta={"hidden_from_render": True},
                )
            )
        return docs

    def _imports(self, rel: str, text: str) -> list[Finding]:
        findings = []
        without_code = FENCE_RE.sub(lambda m: "\n" * m.group(0).count("\n"), text)
        for match in IMPORT_RE.finditer(without_code):
            target = match.group(1)
            if "/" not in target and "\\" not in target and "." not in target:
                continue  # "@alice" mention, not a path
            outside = target.startswith(("~", "/", "..")) or re.match(r"[A-Za-z]:[\\/]", target)
            line = without_code[: match.start()].count("\n") + 1
            findings.append(
                Finding(
                    NAME,
                    "claude.import_outside" if outside else "claude.import",
                    Severity.MEDIUM if outside else Severity.INFO,
                    f"imports {'a file outside the project' if outside else 'another file'}: "
                    f"{target}",
                    rel,
                    line,
                    match.start() - without_code.rfind("\n", 0, match.start()),
                    match.group(0),
                    {"target": target},
                )
            )
        return findings

    # ----- settings --------------------------------------------------------------
    def _settings(self, rel: str, text: str) -> AdapterResult:
        result = GenericFileAdapter().parse(rel, text)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return result
        if not isinstance(data, dict):
            return result
        result.findings.extend(self._permission_findings(rel, text, data))
        return result

    def _permission_findings(self, rel: str, text: str, data: dict[str, Any]) -> list[Finding]:
        findings = []
        permissions = data.get("permissions") or {}

        def line_of(needle: str) -> int | None:
            index = text.find(needle)
            return text[:index].count("\n") + 1 if index >= 0 else None

        mode = permissions.get("defaultMode") if isinstance(permissions, dict) else None
        if mode == "bypassPermissions":
            findings.append(
                Finding(
                    NAME,
                    "claude.bypass_permissions",
                    Severity.HIGH,
                    "settings turn off all permission prompts (defaultMode: bypassPermissions)",
                    rel,
                    line_of("bypassPermissions"),
                )
            )
        allow = permissions.get("allow", []) if isinstance(permissions, dict) else []
        for rule in allow if isinstance(allow, list) else []:
            if isinstance(rule, str) and re.fullmatch(r"\s*Bash(?:\(\s*\*?\s*\))?\s*", rule):
                findings.append(
                    Finding(
                        NAME,
                        "claude.allow_all_bash",
                        Severity.HIGH,
                        f"settings allow every shell command without asking ({rule})",
                        rel,
                        line_of(rule),
                    )
                )
        return findings

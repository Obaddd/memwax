"""Adapters turn memory files into format-agnostic `Document`s.

The scanner core only ever sees `Document`s and `Finding`s. Everything that knows
about a particular agent's file layout or syntax lives in an adapter.

An adapter may also return format-specific findings (for example, a settings file
that turns off permission prompts), which the core treats like any other finding.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from memwax.detectors.base import Document, Finding


@dataclass
class AdapterResult:
    documents: list[Document] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


class Adapter(Protocol):
    name: str

    def default_targets(self) -> list[str]: ...

    def parse(self, rel: str, text: str) -> AdapterResult: ...


def json_string_documents(rel: str, text: str) -> list[Document] | None:
    """Split a JSON (or JSON Lines) file into one document per string value.

    JSON can hide characters behind escapes (a zero-width space written as a
    backslash-u escape is invisible in the raw file but real once parsed), so string
    values are scanned *decoded*. Line numbers point at the line where the value's key
    or array element starts in the raw text. Returns None if the text is not JSON.
    """
    values: list[tuple[str, Any]] = []
    try:
        values = [("", json.loads(text))]
    except json.JSONDecodeError:
        lines = [line for line in text.splitlines() if line.strip()]
        if not lines:
            return None
        try:
            values = [(f"/{i}", json.loads(line)) for i, line in enumerate(lines)]
        except json.JSONDecodeError:
            return None

    raw_lines = text.splitlines()
    docs: list[Document] = []

    def line_of(needle: str) -> int:
        for index, raw in enumerate(raw_lines):
            if needle and needle in raw:
                return index
        return 0

    def walk(pointer: str, value: Any, hint: str) -> None:
        if isinstance(value, str):
            docs.append(
                Document(
                    f"{rel}#{pointer or '/'}",
                    value,
                    kind="json-value",
                    line_offset=line_of(hint),
                    meta={"file": rel, "pointer": pointer},
                )
            )
        elif isinstance(value, dict):
            for key, item in value.items():
                walk(f"{pointer}/{key}", item, f'"{key}"')
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(f"{pointer}/{index}", item, hint)

    for pointer, value in values:
        walk(pointer, value, "")
    return docs

"""Generic file adapter: any text file is one document; JSON is split by value."""

from __future__ import annotations

from memwax.adapters.base import AdapterResult, json_string_documents
from memwax.detectors.base import Document
from memwax.workspace import DEFAULT_TARGETS


class GenericFileAdapter:
    name = "generic"

    def default_targets(self) -> list[str]:
        return list(DEFAULT_TARGETS)

    def parse(self, rel: str, text: str) -> AdapterResult:
        if rel.lower().endswith((".json", ".jsonl", ".ndjson")):
            docs = json_string_documents(rel, text)
            if docs is not None:
                # Also scan the raw text once, so structure-level content (keys) is seen.
                return AdapterResult([Document(rel, text, kind="json-raw"), *docs])
        return AdapterResult([Document(rel, text, kind="text")])

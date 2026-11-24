"""Format adapters. The core never imports a specific adapter except through here."""

from __future__ import annotations

from memwax.adapters.base import Adapter, AdapterResult
from memwax.adapters.claude_code import ClaudeCodeAdapter
from memwax.adapters.generic import GenericFileAdapter

ADAPTERS: dict[str, type] = {
    "generic": GenericFileAdapter,
    "claude-code": ClaudeCodeAdapter,
}


def get_adapter(name: str) -> Adapter:
    try:
        return ADAPTERS[name]()
    except KeyError as exc:
        raise ValueError(f"unknown adapter {name!r}; choose from {sorted(ADAPTERS)}") from exc


__all__ = ["ADAPTERS", "Adapter", "AdapterResult", "get_adapter"]

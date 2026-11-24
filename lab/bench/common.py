"""Stdlib-only helpers shared by the benchmark runners (both virtual environments)."""

from __future__ import annotations

import json
import platform
import sys
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
SAMPLES = LAB / "samples"
RESULTS = LAB / "results"


def load_manifest() -> dict:
    return json.loads((SAMPLES / "manifest.json").read_text("utf-8"))


def all_samples() -> list[dict]:
    """Every labelled sample plus the clean host templates, as dicts with 'label'."""
    manifest = load_manifest()
    rows = [{**item, "label": "attack"} for item in manifest["attack"]]
    rows += [{**item, "label": "benign"} for item in manifest["benign"]]
    rows += [
        {"file": f"hosts/{p.name}", "id": p.stem, "label": "host"}
        for p in sorted((SAMPLES / "hosts").glob("*.md"))
    ]
    return rows


def read_sample(rel: str) -> str:
    return (SAMPLES / rel).read_text("utf-8")


def environment() -> dict:
    return {"python": sys.version.split()[0], "platform": platform.platform()}


def write_results(name: str, payload: dict) -> Path:
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / f"{name}.json"
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", "utf-8")
    return path

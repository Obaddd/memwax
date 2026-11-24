"""Build the benchmark sample files from the human-readable corpus.

lab/corpus/*.jsonl is ASCII and reviewable. Hidden-character attacks are written there
with placeholders ({ZWSP}, {TAG:...}, {CYR:word}, ...). This script expands them into
the real characters and writes one memory file per sample under lab/samples/:

    lab/samples/attack/<category>/<id>.md   payload embedded in an otherwise normal memory file
    lab/samples/benign/<id>.<ext>           realistic memory files, including hard cases
    lab/samples/manifest.json               labels for every file

Every attack sample is inert text. Domains use the reserved .example TLD and IPs come
from the RFC 5737 documentation ranges, so nothing in them can reach a real host.

Usage:  python lab/build_corpus.py
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

LAB = Path(__file__).resolve().parent
CORPUS = LAB / "corpus"
SAMPLES = LAB / "samples"

SIMPLE = {
    "ZWSP": 0x200B,  # zero width space
    "ZWNJ": 0x200C,  # zero width non-joiner
    "WJ": 0x2060,  # word joiner
    "SHY": 0x00AD,  # soft hyphen
    "RLO": 0x202E,  # right-to-left override
    "PDF": 0x202C,  # pop directional formatting
    "LRI": 0x2066,  # left-to-right isolate
    "PDI": 0x2069,  # pop directional isolate
    "RLM": 0x200F,  # right-to-left mark
    "MVS": 0x180E,  # mongolian vowel separator
}
# Latin letter -> Cyrillic look-alike code point.
CYRILLIC = {
    "a": 0x0430,
    "c": 0x0441,
    "e": 0x0435,
    "h": 0x04BB,
    "i": 0x0456,
    "j": 0x0458,
    "o": 0x043E,
    "p": 0x0440,
    "s": 0x0455,
    "x": 0x0445,
    "y": 0x0443,
    "l": 0x04CF,
}

HOSTS = [
    "# Project memory\n\n## Commands\n- Test: `make test`\n- Format: `make fmt`\n\n"
    "## Notes\n{PAYLOAD}\n- Keep pull requests small.\n",
    "# Assistant memory\n\n- User prefers concise answers.\n- Timezone: UTC.\n{PAYLOAD}\n",
    "# Working notes\n\n{PAYLOAD}\n\n## Done\n- Migrated CI to the new runners.\n",
]

_PLACEHOLDER = re.compile(r"\{(TAG|CYR):([^{}]*)\}|\{(" + "|".join(SIMPLE) + r")\}")


def expand(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        kind, arg, simple = match.groups()
        if simple:
            return chr(SIMPLE[simple])
        if kind == "TAG":
            return "".join(chr(0xE0000 + ord(c)) for c in arg)
        return "".join(chr(CYRILLIC[c]) if c in CYRILLIC else c for c in arg)

    return _PLACEHOLDER.sub(repl, text)


def load(name: str) -> list[dict]:
    lines = (CORPUS / name).read_text("utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def benign_extension(text: str) -> str:
    stripped = text.lstrip()
    if stripped.startswith("{") and "\n{" in stripped.strip():
        return ".jsonl"
    if stripped.startswith("{"):
        return ".json"
    return ".md"


def build() -> dict:
    if SAMPLES.exists():
        shutil.rmtree(SAMPLES)
    manifest: dict[str, list[dict]] = {"attack": [], "benign": []}
    for index, item in enumerate(load("attacks.jsonl")):
        host = HOSTS[index % len(HOSTS)]
        body = host.replace("{PAYLOAD}", expand(item["text"]))
        rel = Path("attack") / item["category"] / f"{item['id']}.md"
        (SAMPLES / rel).parent.mkdir(parents=True, exist_ok=True)
        (SAMPLES / rel).write_text(body, "utf-8", newline="\n")
        manifest["attack"].append(
            {
                "file": rel.as_posix(),
                "id": item["id"],
                "category": item["category"],
                "technique": item["technique"],
            }
        )
    for item in load("benign.jsonl"):
        text = item["text"]  # benign samples are used verbatim
        rel = Path("benign") / f"{item['id']}{benign_extension(text)}"
        (SAMPLES / rel).parent.mkdir(parents=True, exist_ok=True)
        (SAMPLES / rel).write_text(text, "utf-8", newline="\n")
        manifest["benign"].append({"file": rel.as_posix(), "id": item["id"], "note": item["note"]})
    hosts_dir = SAMPLES / "hosts"
    hosts_dir.mkdir(parents=True, exist_ok=True)
    for index, host in enumerate(HOSTS):
        (hosts_dir / f"host-{index}.md").write_text(
            host.replace("{PAYLOAD}\n", ""), "utf-8", newline="\n"
        )
    (SAMPLES / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", "utf-8", newline="\n"
    )
    return manifest


if __name__ == "__main__":
    built = build()
    print(f"built {len(built['attack'])} attack and {len(built['benign'])} benign samples")

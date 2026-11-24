"""Pre-push secret and personal-data scan for this repository.

Scans every file git would push (tracked + staged), using memwax's own credential
rules plus checks for private keys, signing-key files, and machine-specific paths.
The lab corpus is allowed to contain *fake* credential-shaped strings, so files under
lab/samples and lab/corpus are only checked for real private-key material.

    python scripts/secret_scan.py          # exit 1 on any finding
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from memwax.detectors import Document  # noqa: E402
from memwax.detectors.indicators import IndicatorDetector  # noqa: E402

CORPUS_PREFIXES = ("lab/samples/", "lab/corpus/", "lab/results/")
FORBIDDEN_NAMES = re.compile(r"(?:^|/)(?:amber_ed25519\.key|.*\.pem|\.env|id_rsa|id_ed25519)$")
LOCAL_PATHS = re.compile(r"[A-Za-z]:\\Users\\[^\\\s\"']+|/home/[a-z][\w-]+/|/Users/[A-Za-z][\w-]+/")
EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@(?!example\.|attacker\.example)[A-Za-z0-9.-]+\.[a-z]{2,}\b"
)
ALLOWED_EMAILS = {"noreply@anthropic.com"}


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--cached", "--others", "--exclude-standard"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [line for line in out.splitlines() if line]


def main() -> int:
    detector = IndicatorDetector()
    problems: list[str] = []
    for rel in tracked_files():
        path = ROOT / rel
        if not path.is_file():
            continue
        if FORBIDDEN_NAMES.search(rel):
            problems.append(f"{rel}: file name looks like a key or secret file")
            continue
        try:
            text = path.read_text("utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary (e.g. the demo GIF)
        in_corpus = rel.startswith(CORPUS_PREFIXES)
        for finding in detector.detect(Document(rel, text)):
            if not finding.rule.startswith("credential."):
                continue
            if in_corpus and finding.rule != "credential.private_key":
                continue
            problems.append(f"{rel}:{finding.line}: {finding.message} [{finding.excerpt}]")
        for match in LOCAL_PATHS.finditer(text):
            if rel == "scripts/secret_scan.py":
                break
            problems.append(f"{rel}: machine-specific path {match.group(0)!r}")
        for match in EMAIL.finditer(text):
            if match.group(0).lower() not in ALLOWED_EMAILS and not in_corpus:
                problems.append(f"{rel}: email address {match.group(0)!r}")
    if problems:
        print("Secret scan FAILED:")
        for problem in problems:
            print("  " + problem)
        return 1
    print(f"Secret scan OK: {len(tracked_files())} files checked.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

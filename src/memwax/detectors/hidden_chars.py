"""Detect characters a human reviewer cannot see but a model still reads.

Rules:

- hidden.tag_chars    Unicode tag characters (U+E0000-U+E007F). They can spell out a
                      whole hidden ASCII message. The decoded text is shown.  CRITICAL
- hidden.bidi         Bidirectional overrides/isolates that reorder what is displayed. HIGH
- hidden.zero_width   Zero-width and other invisible characters inside text.     MEDIUM
                      (A ZWJ between emoji, and a BOM at the very start, are allowed.)
- hidden.homoglyph    A word that mixes Latin letters with look-alike Cyrillic or Greek
                      letters, e.g. "p\u0430ssword" with a Cyrillic "\u0430".                HIGH
- hidden.control      C0/C1 control characters other than tab, newline, CR.      MEDIUM
"""

from __future__ import annotations

import re
import unicodedata

from memwax.detectors.base import Document, Finding, Severity, excerpt
from memwax.detectors.normalize import BIDI_CONTROLS, CONFUSABLES, INVISIBLE, is_tag_char

NAME = "hidden_chars"
_WORD = re.compile(r"[^\W\d_]{2,}", re.UNICODE)


def _is_emoji_like(ch: str) -> bool:
    cp = ord(ch)
    return (
        0x1F000 <= cp <= 0x1FAFF
        or 0x2600 <= cp <= 0x27BF
        or cp in (0xFE0F, 0x20E3)
        or 0x1F3FB <= cp <= 0x1F3FF
    )


def _script(ch: str) -> str | None:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    for script in ("LATIN", "CYRILLIC", "GREEK"):
        if name.startswith(script):
            return script
    return None


class HiddenCharDetector:
    name = NAME

    def detect(self, doc: Document) -> list[Finding]:
        findings: list[Finding] = []
        text = doc.text
        findings.extend(self._tag_runs(doc))
        for index, ch in enumerate(text):
            if is_tag_char(ch):
                continue
            rule = None
            if ch in BIDI_CONTROLS:
                rule, severity, label = "hidden.bidi", Severity.HIGH, "bidirectional control"
            elif ch in INVISIBLE:
                if ch == "\ufeff" and index == 0:
                    continue  # byte order mark
                if ch == "\u200d" and (
                    (index > 0 and _is_emoji_like(text[index - 1]))
                    or (index + 1 < len(text) and _is_emoji_like(text[index + 1]))
                ):
                    continue  # emoji ZWJ sequence
                rule, severity, label = "hidden.zero_width", Severity.MEDIUM, "invisible character"
            elif unicodedata.category(ch) == "Cc" and ch not in "\t\n\r":
                rule, severity, label = "hidden.control", Severity.MEDIUM, "control character"
            if rule:
                line, col = doc.position(index)
                findings.append(
                    Finding(
                        NAME,
                        rule,
                        severity,
                        f"{label} U+{ord(ch):04X} ({unicodedata.name(ch, 'unnamed')})",
                        doc.path,
                        line,
                        col,
                        excerpt(text, index, index + 1),
                        {"codepoint": f"U+{ord(ch):04X}"},
                    )
                )
        findings.extend(self._homoglyphs(doc))
        return _collapse(findings)

    def _tag_runs(self, doc: Document) -> list[Finding]:
        findings = []
        text = doc.text
        index = 0
        while index < len(text):
            if not is_tag_char(text[index]):
                index += 1
                continue
            start = index
            while index < len(text) and is_tag_char(text[index]):
                index += 1
            decoded = "".join(
                chr(ord(c) - 0xE0000) if 0x20 <= ord(c) - 0xE0000 < 0x7F else ""
                for c in text[start:index]
            )
            line, col = doc.position(start)
            findings.append(
                Finding(
                    NAME,
                    "hidden.tag_chars",
                    Severity.CRITICAL,
                    f"{index - start} invisible Unicode tag characters encoding hidden text",
                    doc.path,
                    line,
                    col,
                    decoded[:160],
                    {"decoded": decoded, "count": index - start},
                )
            )
        return findings

    def _homoglyphs(self, doc: Document) -> list[Finding]:
        findings = []
        words = [(m, {_script(c) for c in m.group(0)} - {None}) for m in _WORD.finditer(doc.text)]
        latin_words = sum(1 for _, s in words if s == {"LATIN"})
        mostly_latin = latin_words >= 0.8 * max(1, len(words))
        for match, scripts in words:
            word = match.group(0)
            lookalikes = [c for c in word if c in CONFUSABLES]
            mixed = "LATIN" in scripts and len(scripts) > 1 and lookalikes
            # A word spelled *entirely* in look-alike letters inside English text.
            disguised = (
                mostly_latin
                and scripts
                and "LATIN" not in scripts
                and len(word) >= 3
                and len(lookalikes) == len(word)
            )
            if mixed or disguised:
                line, col = doc.position(match.start())
                findings.append(
                    Finding(
                        NAME,
                        "hidden.homoglyph",
                        Severity.HIGH,
                        f"word uses {', '.join(sorted(scripts - {'LATIN'})).lower()} letters "
                        "that look like Latin ones",
                        doc.path,
                        line,
                        col,
                        word,
                        {"lookalikes": [f"U+{ord(c):04X}" for c in lookalikes]},
                    )
                )
        return findings


def _collapse(findings: list[Finding]) -> list[Finding]:
    """One finding per (rule, line) so a line with 40 zero-width chars is one finding."""
    seen: dict[tuple[str, int | None], Finding] = {}
    for finding in findings:
        key = (finding.rule, finding.line)
        if key in seen and finding.rule != "hidden.homoglyph":
            existing = seen[key]
            existing.evidence["occurrences"] = existing.evidence.get("occurrences", 1) + 1
            continue
        if key in seen:
            key = (finding.rule + f"#{finding.column}", finding.line)
        seen[key] = finding
    return list(seen.values())

"""Text normalisation so obfuscated text still matches phrase rules.

The hidden-character detector reports obfuscation itself. This module only undoes it,
so that "ig<ZWSP>nore previous instructions" or "\u0456gnore" (Cyrillic i) is still read
as "ignore" by the instruction detector.

Normalisation never adds or removes a newline, and `normalize_with_map` returns, for each
output character, its offset in the original text, so findings point at the real location.
"""

from __future__ import annotations

import unicodedata

# Characters that render as nothing (or nearly nothing) in most editors.
INVISIBLE = {
    "\u00ad",  # soft hyphen
    "\u034f",  # combining grapheme joiner
    "\u061c",  # arabic letter mark
    "\u115f",
    "\u1160",
    "\u17b4",
    "\u17b5",
    "\u180e",  # mongolian vowel separator
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\u200e",  # left-to-right mark
    "\u200f",  # right-to-left mark
    "\u2060",  # word joiner
    "\u2061",
    "\u2062",
    "\u2063",
    "\u2064",
    "\u3164",
    "\ufeff",  # zero width no-break space / BOM
    "\uffa0",
}
BIDI_CONTROLS = {chr(c) for c in range(0x202A, 0x202F)} | {chr(c) for c in range(0x2066, 0x206A)}
TAG_RANGE = range(0xE0000, 0xE0080)

# Common confusables: Cyrillic and Greek letters that look like Latin ones.
CONFUSABLES = {
    "\u0430": "a",  # Cyrillic Small Letter A
    "\u0432": "b",  # Cyrillic Small Letter Ve
    "\u0435": "e",  # Cyrillic Small Letter Ie
    "\u043a": "k",  # Cyrillic Small Letter Ka
    "\u043c": "m",  # Cyrillic Small Letter Em
    "\u043d": "h",  # Cyrillic Small Letter En
    "\u043e": "o",  # Cyrillic Small Letter O
    "\u0440": "p",  # Cyrillic Small Letter Er
    "\u0441": "c",  # Cyrillic Small Letter Es
    "\u0442": "t",  # Cyrillic Small Letter Te
    "\u0443": "y",  # Cyrillic Small Letter U
    "\u0445": "x",  # Cyrillic Small Letter Ha
    "\u0456": "i",  # Cyrillic Small Letter Byelorussian-Ukrainian I
    "\u0458": "j",  # Cyrillic Small Letter Je
    "\u0455": "s",  # Cyrillic Small Letter Dze
    "\u0501": "d",  # Cyrillic Small Letter Komi De
    "\u0261": "g",  # Latin Small Letter Script G
    "\u04bb": "h",  # Cyrillic Small Letter Shha
    "\u04cf": "l",  # Cyrillic Small Letter Palochka
    "\u051b": "q",  # Cyrillic Small Letter Qa
    "\u051d": "w",  # Cyrillic Small Letter We
    "\u0410": "A",  # Cyrillic Capital Letter A
    "\u0412": "B",  # Cyrillic Capital Letter Ve
    "\u0415": "E",  # Cyrillic Capital Letter Ie
    "\u041a": "K",  # Cyrillic Capital Letter Ka
    "\u041c": "M",  # Cyrillic Capital Letter Em
    "\u041d": "H",  # Cyrillic Capital Letter En
    "\u041e": "O",  # Cyrillic Capital Letter O
    "\u0420": "P",  # Cyrillic Capital Letter Er
    "\u0421": "C",  # Cyrillic Capital Letter Es
    "\u0422": "T",  # Cyrillic Capital Letter Te
    "\u0423": "Y",  # Cyrillic Capital Letter U
    "\u0425": "X",  # Cyrillic Capital Letter Ha
    "\u0406": "I",  # Cyrillic Capital Letter Byelorussian-Ukrainian I
    "\u0408": "J",  # Cyrillic Capital Letter Je
    "\u0405": "S",  # Cyrillic Capital Letter Dze
    "\u03b1": "a",  # Greek Small Letter Alpha
    "\u03bf": "o",  # Greek Small Letter Omicron
    "\u03c1": "p",  # Greek Small Letter Rho
    "\u03bd": "v",  # Greek Small Letter Nu
    "\u03c4": "t",  # Greek Small Letter Tau
    "\u03b9": "i",  # Greek Small Letter Iota
    "\u03ba": "k",  # Greek Small Letter Kappa
    "\u03c7": "x",  # Greek Small Letter Chi
    "\u0391": "A",  # Greek Capital Letter Alpha
    "\u0392": "B",  # Greek Capital Letter Beta
    "\u0395": "E",  # Greek Capital Letter Epsilon
    "\u0396": "Z",  # Greek Capital Letter Zeta
    "\u0397": "H",  # Greek Capital Letter Eta
    "\u0399": "I",  # Greek Capital Letter Iota
    "\u039a": "K",  # Greek Capital Letter Kappa
    "\u039c": "M",  # Greek Capital Letter Mu
    "\u039d": "N",  # Greek Capital Letter Nu
    "\u039f": "O",  # Greek Capital Letter Omicron
    "\u03a1": "P",  # Greek Capital Letter Rho
    "\u03a4": "T",  # Greek Capital Letter Tau
    "\u03a5": "Y",  # Greek Capital Letter Upsilon
    "\u03a7": "X",  # Greek Capital Letter Chi
}


def is_tag_char(ch: str) -> bool:
    return ord(ch) in TAG_RANGE


def normalize_with_map(text: str) -> tuple[str, list[int]]:
    """Like `normalize`, but also return, for each output char, its offset in `text`."""
    out: list[str] = []
    mapping: list[int] = []
    for index, ch in enumerate(text):
        if ch in INVISIBLE or ch in BIDI_CONTROLS or is_tag_char(ch):
            continue
        ch = CONFUSABLES.get(ch, ch)
        if ord(ch) > 127:
            folded = unicodedata.normalize("NFKC", ch)
            if "\n" not in folded:
                ch = folded
        for piece in ch:
            out.append(piece)
            mapping.append(index)
    mapping.append(len(text))
    return "".join(out), mapping


def normalize(text: str) -> str:
    """Strip invisible/bidi/tag characters, fold confusables, NFKC each remaining char."""
    return normalize_with_map(text)[0]

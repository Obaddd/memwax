"""memwax's own source must not contain the characters it warns about."""

from pathlib import Path

from memwax.detectors import Document, HiddenCharDetector

ROOT = Path(__file__).resolve().parents[1]


def test_python_sources_are_ascii_only():
    offenders = []
    for path in sorted([*ROOT.glob("src/**/*.py"), *ROOT.glob("tests/**/*.py")]):
        text = path.read_text("utf-8")
        if any(ord(c) > 127 for c in text):
            offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == [], "use escapes for non-ASCII characters"


def test_no_hidden_characters_in_source():
    detector = HiddenCharDetector()
    for path in sorted(ROOT.glob("src/**/*.py")):
        doc = Document(path.name, path.read_text("utf-8"))
        assert detector.detect(doc) == [], path

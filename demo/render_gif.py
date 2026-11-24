"""Render demo/transcript.txt (real output of demo.py) into demo/memwax-demo.gif.

Nothing is staged: the GIF replays the captured transcript line by line, typing out
the commands. Needs Pillow (`pip install -e ".[demo]"`).

    python demo/render_gif.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
TRANSCRIPT = ROOT / "demo" / "transcript.txt"
OUT = ROOT / "demo" / "memwax-demo.gif"

COLS, ROWS = 112, 30
FONT_SIZE = 15
PAD = 16
BG = (24, 24, 27)
FG = (228, 228, 231)
COLORS = {
    "$": (134, 239, 172),
    "#": (161, 161, 170),
    "CRITICAL": (248, 113, 113),
    "HIGH": (251, 146, 60),
    "MEDIUM": (250, 204, 21),
    "WOULD RUN": (248, 113, 113),
    "Drift": (250, 204, 21),
}


def load_font() -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for candidate in (
        "C:/Windows/Fonts/consola.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/System/Library/Fonts/Menlo.ttc",
    ):
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, FONT_SIZE)
    return ImageFont.load_default()


def color_for(line: str) -> tuple[int, int, int]:
    stripped = line.strip()
    if stripped.startswith("$"):
        return COLORS["$"]
    if stripped.startswith("#"):
        return COLORS["#"]
    for key in ("WOULD RUN", "CRITICAL", "HIGH", "MEDIUM", "Drift"):
        if key in line:
            return COLORS[key]
    return FG


def main() -> int:
    if not TRANSCRIPT.exists():
        print("run demo/demo.py first")
        return 1
    lines = [line[:COLS] for line in TRANSCRIPT.read_text("utf-8").splitlines()]
    font = load_font()
    char_w = font.getbbox("M")[2]
    line_h = FONT_SIZE + 4
    size = (PAD * 2 + char_w * COLS, PAD * 2 + line_h * ROWS)

    frames: list[Image.Image] = []
    durations: list[int] = []

    def snapshot(screen: list[str], duration: int) -> None:
        image = Image.new("RGB", size, BG)
        draw = ImageDraw.Draw(image)
        for row, text in enumerate(screen[-ROWS:]):
            draw.text((PAD, PAD + row * line_h), text, font=font, fill=color_for(text))
        frames.append(image)
        durations.append(duration)

    screen: list[str] = []
    for line in lines:
        if line.startswith("$ "):
            # Type the command out in a few steps.
            steps = 4
            for i in range(1, steps + 1):
                cut = 2 + (len(line) - 2) * i // steps
                snapshot([*screen, line[:cut]], 70)
            screen.append(line)
            snapshot(screen, 350)
        elif line.startswith("#"):
            screen.append(line)
            snapshot(screen, 1400)
        else:
            screen.append(line)
            if not line.strip():
                snapshot(screen, 500)
    snapshot(screen, 6000)

    palette_frames = [f.convert("P", palette=Image.Palette.ADAPTIVE, colors=32) for f in frames]
    palette_frames[0].save(
        OUT,
        save_all=True,
        append_images=palette_frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )
    print(f"wrote {OUT} ({len(frames)} frames, {OUT.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Значки в стиле системных приложений WP7: белый щит с замочной скважиной на прозрачном фоне.

  icons.py <outdir>
"""
import os
import sys

from PIL import Image, ImageDraw

S = 8


def shield(size, glyph):
    big = size * S
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    w = big * glyph
    h = w * 1.18
    x0, y0 = (big - w) / 2, (big - h) / 2
    line = max(S * 2, int(w * 0.08))
    # контур щита: прямой верх, бока сходятся к острию внизу
    pts = [(x0, y0 + h * 0.08), (x0 + w / 2, y0), (x0 + w, y0 + h * 0.08), (x0 + w, y0 + h * 0.45),
           (x0 + w / 2, y0 + h), (x0, y0 + h * 0.45)]
    d.line(pts + [pts[0], pts[1]], fill="white", width=line, joint="curve")
    # замочная скважина
    cx, cy, r = x0 + w / 2, y0 + h * 0.42, w * 0.12
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill="white")
    d.polygon([(cx - r * 0.55, cy), (cx + r * 0.55, cy), (cx + r * 0.8, cy + r * 2.4), (cx - r * 0.8, cy + r * 2.4)], fill="white")
    return img.resize((size, size), Image.LANCZOS)


def main():
    out = sys.argv[1]
    os.makedirs(os.path.join(out, "Images"), exist_ok=True)
    shield(62, 0.52).save(os.path.join(out, "ApplicationIcon.png"))
    shield(173, 0.42).save(os.path.join(out, "Background.png"))
    print("icons: готово")


if __name__ == "__main__":
    main()

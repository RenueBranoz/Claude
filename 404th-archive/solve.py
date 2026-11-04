#!/usr/bin/env python3
"""Th3_404th_4rch1v3 solver: Sheikah digits -> decimal -> base36 -> hex -> ASCII."""
import sys
import numpy as np
from PIL import Image

# Glyph cells are 36x37 px on a 42 px row pitch, 9 per row, starting at (x=4, y=9).
# Reference glyphs are taken from the image itself; this maps each glyph (by its
# first occurrence order) to its Sheikah digit (Zelda: BotW numerals).
FIRST_SEEN_TO_DIGIT = [1, 2, 8, 6, 7, 5, 3, 9, 0, 4]

a = np.array(Image.open(sys.argv[1] if len(sys.argv) > 1 else "glyphs.png").convert("L")) < 100
uniq, digits = [], []
for r in range(16):
    for c in range(9):
        y0, x0 = 9 + 42 * r, 4 + 36 * c
        g = a[y0:y0 + 37, x0:x0 + 36]
        if not g.any():
            continue
        for i, u in enumerate(uniq):
            if (u != g).sum() < 30:
                break
        else:
            uniq.append(g)
            i = len(uniq) - 1
        digits.append(str(FIRST_SEEN_TO_DIGIT[i]))

n = int("".join(digits))
b36 = ""
while n:
    n, d = divmod(n, 36)
    b36 = "0123456789abcdefghijklmnopqrstuvwxyz"[d] + b36
print(bytes.fromhex(b36).decode())

# Th3_404th_4rch1v3 — Writeup

| | |
|---|---|
| **Points** | 800 |
| **Category** | Crypto / Misc (esoteric script) |
| **Flag** | `UNI6CTF{l3ts_giv3s_y0u_s0me_Crypt0_mad4ness}` |

## Challenge

> An unusual artifact was recovered from a forgotten corner of the digital underground. […]
> It leads somewhere far stranger.
> **The symbols are waiting. The numbers remember.**
> Can you uncover what the archive refuses to reveal?

The only file is an image full of squared-off glyphs on a parchment background (`glyphs.png`).

## TL;DR

Sheikah numerals → one big decimal number → base 36 → hex → ASCII.

## Solution

### 1. Split the image into glyphs

Each row is 42 px tall, and the ink in every row lines up on an 18 px horizontal grid.
When the 18 px half-cells are grouped by shape, they always come in the same fixed pairs.
So each glyph is a **36 × 37 px** cell, 9 per row.

| Rows | Glyphs |
|---|---|
| 15 full rows | 135 |
| last row | 2 |
| **total** | **137** |

### 2. Count the shapes: there are only ten

Comparing the 137 cells with each other leaves **exactly 10 distinct glyphs**.
They occur about equally often (between 6 and 19 times each).
Ten evenly used symbols means the message is made of **digits**: *"the numbers remember."*

### 3. Identify the script

The style is square strokes, rounded ends and single dots inside the glyph.
That is the **Sheikah** script from *The Legend of Zelda: Breath of the Wild*.
Sheikah has its own set of numerals, separate from its 26 letters.

I compared the glyphs with the bitmap Sheikah font from
[Lykrast/SheikahFont](https://github.com/Lykrast/SheikahFont).
Each of the 10 shapes matches exactly one Sheikah digit:

| Glyph (description) | Digit |
|---|---|
| frame with a gap at top-right, dot in the centre | 0 |
| dot top-left, short centre stem, right side, bottom bar | 1 |
| dot above a cup (∪), bottom bar | 2 |
| L-shape, centre stem at top, dot top-right | 3 |
| dot, `)`, `\|` | 4 |
| S-shape with a centre dot | 5 |
| `\|`, `(`, dot | 6 |
| top bar, right side, centre stem down, dot bottom-left | 7 |
| top bar, arch (∩) with a dot below | 8 |
| top bar, left side, centre stem down, dot bottom-right | 9 |

### 4. Read the number

Reading the glyphs left to right and top to bottom gives a 137-digit decimal number:

```
12866875853859692606642844291721686219514317726252661018105011589226182910622366555400425841881803302564528748725714654968791248731847417
```

These digits don't decode directly:

- As one big integer turned into bytes, the result is mostly non-printable.
- Split into 2–3 digit ASCII codes, no split produces readable text.

I also brute-forced all 10! glyph-to-digit assignments under both of these readings.
None of them gave readable output.
The digits need one more conversion.

### 5. Base 36 → hex → ASCII

Writing the same integer in **base 36** gives a string that uses only `0-9a-f`:

```
554e49364354467b6c3374735f67697633735f7930755f73306d655f4372797074305f6d6164346e6573737d
```

That string is hex, and hex → ASCII gives:

```
UNI6CTF{l3ts_giv3s_y0u_s0me_Crypt0_mad4ness}
```

## Reproduce

```bash
python3 solve.py glyphs.png
```

`solve.py` cuts the image into cells and groups identical glyphs.
It then maps each glyph to its Sheikah digit and does the base-36 → hex → ASCII conversion.

## Takeaways

- **Count distinct symbols before guessing an alphabet.** Ten evenly used symbols means digits, which matches the "numbers" hint.
- **Fictional scripts often have their own numerals.** Sheikah has a separate digit set, and the dCode page and fan fonts include it.
- **A long decimal number can be another layer of encoding.** When bytes and ASCII codes fail, try other bases. Here a base-36 string made only of hex characters was the giveaway.

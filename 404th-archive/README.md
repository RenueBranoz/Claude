# Th3_404th_4rch1v3 (800 pts)

**Flag:** `UNI6CTF{l3ts_giv3s_y0u_s0me_Crypt0_mad4ness}`

1. `glyphs.png` holds 137 glyphs but only 10 distinct shapes, so they are digits.
2. The shapes are **Sheikah numerals** (Zelda: Breath of the Wild), not letters.
   Glyph-to-digit mapping checked against a Sheikah bitmap font.
3. Read them in order to get a 137-digit decimal number:
   `12866875853859692606642844291721686219514317726252661018105011589226182910622366555400425841881803302564528748725714654968791248731847417`
4. Write that number in **base 36**. The result is a string of only hex characters:
   `554e49364354467b...6e6573737d`
5. Hex → ASCII gives the flag.

Run it with `python3 solve.py glyphs.png`.

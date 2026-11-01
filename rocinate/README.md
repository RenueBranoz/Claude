# Rocinate — Cryptography (hiCTF)

**Flag:** `hiCTF{lmaoooo_w0t???y0u_d1d_17_??435p37++}`

Files: `chall.py`, `chall.txt` (from `rocinate.zip`, SHA-256
`2f7b41f0cf2d52ca975e05f69bfd99b311c65712dcb4c5b524431c4a1c36e41a`).
Solver: `solve.py` (stdlib only, ~5 s): `python3 solve.py chall.txt`.

## Challenge

`s` is the flag as an integer, `N = p*q` with 1024-bit primes. Then:

- `r, e, a, b = random.randint(1, N)` (in that order)
- LCG `R_0 = r`, `R_{i+1} = a*R_i + b mod N`, 100 terms
- `C_i = random.randint(1, N)` for 100 values
- `Z_i = R_i * s^{C_i} mod N` (the product itself is **not** reduced mod N)
- `T_i = R_i^e mod N`

Published: `a, b, N, Z, C, T`. Everything hinges on the hidden `r` (and `e`).

## Weakness: Mersenne Twister leaks through `a, b, C_i`

`randint(1, N)` is `1 + randbelow(N)`, and with `N.bit_length() == 2047` each
attempt is `getrandbits(2047)`: 64 MT19937 outputs, little-endian, with the top
word shifted right by 1 (its bit 0 is lost). Attempts `>= N` are rejected and
retried (about 22% of the time), so rejected draws are invisible and the
positions of the visible draws in the stream are unknown.

The 102 visible draws (`a`, `b`, all `C_i`) carry ~2047 bits of MT output each;
`r` and `e` are the two accepted draws right before `a`.

## Solution

1. **Find a contiguous run.** Take `L = 16` consecutive visible draws and assume
   no hidden rejection sits between them. Each draw contributes 64 words, one
   tempered bit unknown. Tempering is GF(2)-linear, so each unknown bit flips a
   fixed mask `untemper(1)` in the untempered word. The twist recurrence
   `x[k+624] = x[k+397] ^ f(upper(x[k]) | lower(x[k+1]))` is linear too, giving
   a GF(2) system in the 16 unknowns. A non-contiguous run is inconsistent;
   a contiguous one solves uniquely. `visible[17:33]` works.
   *`L >= 16` matters:* with fewer draws some top words never appear in any
   recurrence equation (`64L - 624 < 396`), their bit silently defaults, and
   the backward walk later diverges. The solver also rejects any run where a
   variable has no pivot.
2. **Walk backward.** Any 624 consecutive untempered words fix the stream.
   The word before `x[0]` is rebuilt from two recurrences: the one with it as
   `x[k]` gives its top bit (from `x[623] ^ x[396]`), and the one with it as
   `x[k+1]` gives its low 31 bits (from `x[622] ^ x[395]`). Inverting `f`: if
   the top bit of `t` is set, `y = ((t ^ MAG) << 1) | 1`, else `y = t << 1`.
3. **Decode blocks.** Re-temper, group 64 words, decode. Blocks `>= N` are
   rejections and are skipped; accepted blocks must equal `visible[16], ...,
   visible[0]` (this checks the whole reconstruction). The next two accepted
   blocks are `e - 1` and `r - 1`.
4. **Recover `s`.** Rebuild `R_i`, check `pow(R_i, e, N) == T_i` for all `i`,
   compute `W_i = Z_i / R_i = s^{C_i} mod N` (an exact division, because `Z_i`
   was never reduced), pick `gcd(C_i, C_j) = 1`, and with `u*C_i + v*C_j = 1`
   take `s = W_i^u * W_j^v mod N`. Verify `s^{C_k} == W_k` for every `k`.

## Takeaways

- Never use `random` for cryptographic values; use `secrets` / `os.urandom`.
- Rejection sampling only hides positions; the MT recurrence recovers them.

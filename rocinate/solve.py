#!/usr/bin/env python3
"""Rocinate (hiCTF) solver: recover hidden MT19937 draws r, e from the leaked
randint outputs a, b, C_i, then undo the LCG mask and solve for s.

Usage: python3 solve.py [chall.txt]
"""
import ast
import re
import sys

MAG = 0x9908B0DF
UPPER, LOWER, M32 = 0x80000000, 0x7FFFFFFF, 0xFFFFFFFF


def parse(path):
    txt = open(path).read()
    body = txt[txt.index("'''") + 3: txt.rindex("'''")]
    body = re.sub(r"\]\s*\[", "], [", body.strip())
    a, b, N = map(int, body.split()[:3])
    rest = body[body.index("["):]
    Z, C, T = ast.literal_eval("[" + rest + "]")
    return a, b, N, Z, C, T


# ---- MT19937 tempering ----------------------------------------------------
def temper(y):
    y ^= y >> 11
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= y >> 18
    return y & M32


def untemper(y):
    y ^= y >> 18
    y ^= (y << 15) & 0xEFC60000
    t = y
    for _ in range(5):
        t = y ^ ((t << 7) & 0x9D2C5680)
    y = t & M32
    t = y
    for _ in range(3):
        t = y ^ (t >> 11)
    return t & M32


def f(y):
    return (y >> 1) ^ (MAG if y & 1 else 0)


def twist_residual(x, k):
    """Zero iff x[k+624] follows from x[k], x[k+1], x[k+397]."""
    return x[k + 624] ^ x[k + 397] ^ f((x[k] & UPPER) | (x[k + 1] & LOWER))


# ---- draw <-> words ------------------------------------------------------
WPD = 64  # 32-bit words per getrandbits(2047) call


def draw_to_tempered(v):
    w = [(v >> (32 * i)) & M32 for i in range(WPD - 1)]
    w.append((v >> (32 * 63)) << 1)  # bit 0 of the top word is lost
    return w


def tempered_to_draw(w):
    v = 0
    for i in range(WPD - 1):
        v |= w[i] << (32 * i)
    return v | ((w[63] >> 1) << (32 * 63))


def solve_run(vals):
    """Treat vals as consecutive draws; return untempered words or None."""
    L = len(vals)
    x = []
    for v in vals:
        x += [untemper(t) for t in draw_to_tempered(v)]
    D = untemper(1)  # effect of the unknown tempered bit (tempering is linear)
    top = {WPD * j + 63: j for j in range(L)}
    rows = []  # (mask over unknowns, rhs bit)
    for k in range(len(x) - 624):
        base = twist_residual(x, k)
        contrib = []
        for p in (k, k + 1, k + 397, k + 624):
            if p in top:
                y = x[:]  # cheap enough at this size
                y[p] ^= D
                contrib.append((top[p], twist_residual(y, k) ^ base))
        for bit in range(32):
            m = 0
            for j, c in contrib:
                if c >> bit & 1:
                    m ^= 1 << j
            rows.append((m, base >> bit & 1))
    # Gaussian elimination over GF(2)
    piv = {}
    for m, r in rows:
        for j, (pm, pr) in piv.items():
            if m >> j & 1:
                m ^= pm
                r ^= pr
        if m == 0:
            if r:
                return None  # inconsistent: run is not contiguous
            continue
        j = m.bit_length() - 1
        for jj in list(piv):
            pm, pr = piv[jj]
            if pm >> j & 1:
                piv[jj] = (pm ^ m, pr ^ r)
        piv[j] = (m, r)
    if len(piv) != L:
        return None  # some unknown bit never appears in an equation
    u = [0] * L
    for j, (m, r) in piv.items():
        if m & ~(1 << j):
            return None  # under-determined; try another run
        u[j] = r
    for j in range(L):
        if u[j]:
            x[WPD * j + 63] ^= D
    assert all(twist_residual(x, k) == 0 for k in range(len(x) - 624))
    return x


def prepend_word(x):
    """Given x[0..] (>= 624 words), return the untempered word before x[0]."""
    def y_of(k):  # recovers upper(x[k]) | lower(x[k+1]) relative to new index
        t = x[k + 623] ^ x[k + 396]
        if t & UPPER:
            return ((t ^ MAG) << 1 | 1) & M32
        return (t << 1) & M32
    hi = y_of(0) & UPPER        # equation with new word as x[k]
    lo = y_of(-1) & LOWER       # equation with new word as x[k+1]
    return hi | lo


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "chall.txt"
    a, b, N, Z, C, T = parse(path)
    assert N.bit_length() == 2047
    visible = [a - 1, b - 1] + [c - 1 for c in C]

    # Every top-word bit must appear in some recurrence equation; that needs
    # 64*L - 624 >= 396, i.e. L >= 16.
    L = 16
    for j in range(len(visible) - L + 1):
        x = solve_run(visible[j:j + L])
        if x:
            print(f"[+] contiguous run at visible[{j}:{j + L}]")
            break
    else:
        sys.exit("no contiguous run found")

    # walk backward block by block
    known = list(reversed(visible[:j]))  # expected accepted draws, newest first
    hidden = []
    while len(hidden) < 2:
        block = []
        for _ in range(WPD):
            w = prepend_word(x)
            x.insert(0, w)
            block.insert(0, temper(w))
        v = tempered_to_draw(block)
        if v >= N:
            continue  # rejected draw
        if known:
            assert v == known.pop(0), "backward walk diverged"
        else:
            hidden.append(v + 1)
    e, r = hidden
    print(f"[+] r = {r}\n[+] e = {e}")

    R = [r]
    for _ in range(len(C) - 1):
        R.append((a * R[-1] + b) % N)
    assert all(pow(Ri, e, N) == Ti for Ri, Ti in zip(R, T)), "T check failed"
    W = []
    for Zi, Ri in zip(Z, R):
        assert Zi % Ri == 0
        W.append(Zi // Ri)  # Z_i is not reduced mod N, so this is exact

    from math import gcd
    i, k = next((i, k) for i in range(len(C)) for k in range(i + 1, len(C))
                if gcd(C[i], C[k]) == 1)

    def egcd(p, q):
        x0, x1, y0, y1 = 1, 0, 0, 1
        while q:
            t = p // q
            p, q = q, p - t * q
            x0, x1 = x1, x0 - t * x1
            y0, y1 = y1, y0 - t * y1
        return p, x0, y0

    _, u, v = egcd(C[i], C[k])
    s = pow(W[i], u, N) * pow(W[k], v, N) % N
    assert all(pow(s, c, N) == w for c, w in zip(C, W))
    print(s.to_bytes((s.bit_length() + 7) // 8, "big").decode())


if __name__ == "__main__":
    main()

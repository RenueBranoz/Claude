#!/usr/bin/env python3
"""Midnight NAND Reliquary - recover the reliquary record from the raw dump.

Layout: 256 data + 16 OOB bytes per page, 8 pages/block, 52 blocks.
- Noise pages:   random.Random(0x15081947), 1 random() + 272 randint(0,255) per page.
- Bad blocks:    3, 17, 41 (OOB starts b'BB').  Fake flag pages: OOB b'FK'.
- Reliquary pages: OOB b'AZ'.
    OOB[4]    = payload length
    OOB[5]    = sequence (3 newer, 1 older)
    OOB[6:10] = CRC32 (BE) of stored payload  -> used to locate/fix bit flips
    filler    = random.Random(1337*page + lp).randint(0,255) after the payload
  Older/newer copies differ by XOR 0xa7.
Output: the joined 58-byte record  b'MNND' + u16be(52) + 52-byte body.
"""
import sys, zlib

PAGE, DATA = 272, 256

def pages(dump):
    for p in range(len(dump) // PAGE):
        x = dump[p*PAGE:(p+1)*PAGE]
        yield p, bytearray(x[:DATA]), x[DATA:]

def fix_single_flip(payload, want):
    if zlib.crc32(payload) == want:
        return payload, None
    for i in range(len(payload)):
        for b in range(8):
            payload[i] ^= 1 << b
            if zlib.crc32(payload) == want:
                return payload, (i, b)
            payload[i] ^= 1 << b
    raise ValueError("uncorrectable")

def main(path):
    dump = open(path, 'rb').read()
    recs = []
    for p, data, oob in pages(dump):
        if oob[:2] != b'AZ':
            continue
        L, seq = oob[4], oob[5]
        payload, flip = fix_single_flip(bytearray(data[:L]), int.from_bytes(oob[6:10], 'big'))
        recs.append((p, L, seq, bytes(payload), flip, oob.hex()))
        print(f"page {p:3d} (blk {p//8} pg {p%8}) len={L} seq={seq} flip={flip} oob={oob.hex()}")
    # seq-1 copies are stored plain ('MNND' header); seq-3 copies are XOR 0xa7
    first = next(pl for p, L, s, pl, _, _ in recs if L == 31 and s == 1)
    second = next(pl for p, L, s, pl, _, _ in recs if L == 27 and s == 1)
    rec = first + second
    print("record:", rec.hex())
    print("magic", rec[:4], "len", int.from_bytes(rec[4:6], 'big'))
    print("body  ", rec[6:].hex())

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'reliquary_nand.bin')

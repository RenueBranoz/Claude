# Titan Relay — Binary Exploitation (hiCTF)

Stripped x86-64 **Rust** PE (`titan_relay.exe`) run under Wine behind `socat`,
exposed as a TCP+SSL "relay console". Menu: `1) load capsule`, `2) quit`.

## The VM

A hex **capsule** is read, XOR-descrambled in place with the keystream
`k_i = (0x3d*i + 0x71) mod 256`, then executed as bytecode.

State object (`rbp`, 0xF8 bytes): registers `R0..R7` at `+0x18`, a secret
per-run `magic` at `+0x00`, and a 3-entry special array `S` at `+0xD8`
(= `magic_lo32`, `magic_hi32`, `magic ^ 0x1400018c0`). `magic` is derived from
`GetSystemTimePreciseAsFileTime`, so it is random each capsule load.

Opcodes (post-descramble):

| op | form | semantics |
|----|------|-----------|
| `0x11` | `d imm32` | `R[d] = imm32` |
| `0xa3` | `d imm16` | `R[d] = sext16(imm16)` |
| `0xb1`/`0x42`/`0x91`/`0xa4`/`0xa1`/`0x81`/`0x82` | `d s` / `d imm` | mov / xor / or / add / add-imm8 / shl / shr |
| `0x21` | `d idx16` | `R[d] = state[0x58 + idx*8]`, `idx in [0,15]` |
| `0x71` | `d s idx` | if `R[s] == &S` then `R[d] = S[idx]` (leaks magic) |
| `0x32` | `s idx16 sub` | **store** `R[s].lo32` -> `state[0x58 + idx*8 + sub*4]`; `idx` is **signed** `[-10,15]` |
| `0x51` | — | if `state[8]==magic` && `state[0x10]==0x1400018c0` && `R6!=0` -> `reveal(R6)` |

`reveal(node)` validates `{magic, ptr, tag=0xB, checksum}`, XOR-decrypts an
11-byte path at `ptr` with `magic`, **opens that file and prints it**.

## Bug & exploit

`0x32` takes a **signed** index, so it writes as low as `state+0x08` — an OOB
write over the integrity header that `0x51` checks.

1. Leak `magic`: `0x21` -> `&S` into a reg, then `0x71` -> `S[0]=magic_lo`, `S[1]=magic_hi`.
2. Forge the `rbp` header so `0x51` passes: `state[8]=magic`, `state[0x10]=0x1400018c0`.
3. Build `"Z:\flag.txt" ^ magic` and a fake `{magic, ptr, 0xB, checksum}` node in scratch.
4. Point `R6` at the fake node and run `0x51`.

`reveal` opens `Z:\flag.txt` (Wine `Z:` = container `/flag.txt`) and prints the flag.
The capsule leaks the key at runtime, so the same bytes work on every connection.

## Run

```bash
python3 solve_titan.py                 # defaults to the live host:1337 over TLS
python3 solve_titan.py HOST PORT       # or point at your own instance
```

`capsule.hex` is the raw capsule; regenerate it with `python3 titan_assembler.py`.

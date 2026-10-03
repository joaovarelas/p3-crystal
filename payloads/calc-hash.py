# hash_winexec.py
def ror32(v, n): return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF

h = 0
for c in b"WinExec":          # hash only the function name, no null
    h = ror32(h, 13)
    h = (h + c) & 0xFFFFFFFF

print(f"WINEXEC_HASH = 0x{h:08X}")

raw = list(h.to_bytes(4, 'little'))
if any(b == 0 for b in raw):
    # hash itself contains a null byte — XOR-encode the constant
    key = next(x for x in range(1,256) if all((b^x) != 0 for b in raw))
    enc = h ^ (key * 0x01010101)
    print(f"  !! null in hash — encode as:")
    print(f"  mov  edx, 0x{enc:08X}")
    print(f"  xor  edx, 0x{key:02X}{key:02X}{key:02X}{key:02X}h")
else:
    print(f"  OK — bytes {[hex(b) for b in raw]} contain no nulls")


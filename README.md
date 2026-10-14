<p align="center">
  <img src="docs/logo.png" alt="P3-Crystal" width="550"/>
</p>


# P³-Crystal

Crystal Palace PICO implementation of Process Parameter Poisoning (P³).

Injects shellcode into a child process via `NtCreateUserProcess` parameter fields
(`ShellInfo`) without calling `VirtualAlloc`, `WriteProcessMemory`,
or `CreateRemoteThread`.

Includes a C port of p3-loader's `ShellCodeWriter` for generating null-free
module-stomping stubs, and a Draugr-based call-stack spoofer that plants synthetic
`BaseThreadInitThunk` / `RtlUserThreadStart` frames on every NT call.


---

## Background

- Technique: [Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/) — Hirschberger & Ugur, SensePost 2026
- Framework: [Crystal Palace](https://tradecraftgarden.org) — Raphael Mudge / AFF-WG
- Part 1 writeup: [P³ in the Palace](https://vrls.ws/posts/p3-in-the-palace-process-parameter-poisoning-in-crystal-palace/) — vrls.ws
- Part 2 writeup: [P³ in the Palace — Hardening the Loader](https://vrls.ws/posts/p3-in-the-palace-hardening-the-loader-part-2/) — vrls.ws

---

## How It Works

```
Makefile
  └─ xxd payload → SC_HEX_DATA → loader.spec (XOR masked, embedded)
       └─ Crystal Palace PICO (go)
            ├─ RtlAddFunctionTable (register PIC unwind data)
            ├─ Resolve btit_addr / ruts_addr (BTIT+0x17, RUTS+0x2c)
            ├─ resource_unmask → plaintext payload
            ├─ scw_stomp_and_call → null-free stub
            │    ├─ PEB walk blob (gs:[rbp+0x60], ROR13 hash, null-free)
            │    ├─ VirtualProtect RW → memcpy → VirtualProtect RX
            │    ├─ RSP pivot to TEB.StackBase−0x200
            │    └─ plant BTIT+0x17 / RUTS+0x2c / NULL frame chain
            ├─ RtlCreateProcessParametersEx(ShellInfo = stub)
            ├─ NtCreateUserProcess(\??\winver.exe)  [spoof_call]
            ├─ RDTSC spin wait
            ├─ NtQueryInformationProcess            [spoof_call]
            ├─ NtReadVirtualMemory × 2             [spoof_call]
            ├─ NtProtectVirtualMemory(ShellInfo, RX) [spoof_call]
            ├─ NtGetContextThread                  [spoof_call]
            └─ NtSetContextThread(child.RIP = ShellInfo.Buffer) [spoof_call]
                 └─ child executes stub
                      ├─ PEB-walk → KernelBase!QueryDosDeviceW VA
                      ├─ VirtualProtect(RW) → copy payload → VirtualProtect(RX)
                      ├─ RSP pivot + BTIT/RUTS frame chain
                      └─ jmp → payload runs (MEM_IMAGE · KernelBase.dll range)
```

---

## Call Stack Spoofing

All NT calls go through `spoof_call`, which wraps `draugr.asm` — a NASM flat binary
loaded by Crystal Palace via `linkfunc "draugr_stub"`. On each call:

1. Pops the real return address; saves non-volatile registers into `DRAUGR_PARAMETERS`.
2. Relocates extra stack arguments above the synthetic chain.
3. Allocates `0x200` scratch space; builds the frame chain:
   `NULL → RtlUserThreadStart+0x2c → BaseThreadInitThunk+0x17 → gadget`.
4. The gadget is `FF 23` (`jmp [rbx]`) chosen randomly from up to 15 candidates
   in `KernelBase.dll .text`; the retry loop enforces a trampoline frame ≥ `0x80`.
5. `lea rbx, [rel fixup]`; calls the target.
6. On return via `jmp [rbx] → fixup`: restores RSP and non-volatiles, returns to caller.

---

## Requirements

- [Crystal Palace](https://tradecraftgarden.org/crystalpalace.html) (`cpl` on PATH)
- `x86_64-w64-mingw32-gcc`
- `nasm`, `xxd`, `make`
- Windows x64 target (tested on Windows 10/11)

---

## Build

```bash
make SCFILE=payloads/calc.bin
```

Regenerate the PEB walk blob after editing `src/peb_walk.asm`:

```bash
make src/peb_walk_blob.h
```

---

## Project Structure

```
src/
├── loader.c            # go() entry point — full P³ injection chain
├── services.c          # DFR resolvers (resolve, resolve_ext)
├── shellwriter.c       # null-free stub generator (ShellCodeWriter)
├── shellwriter.h
├── spoof.c             # Draugr call-stack spoofing (gadget discovery, frame sizing)
├── spoof.h
├── draugr.asm          # NASM flat-binary Draugr stub (loaded via linkfunc)
├── peb_walk.asm        # PEB walk + module-stomp blob source
├── peb_walk_blob.h     # auto-generated from peb_walk.asm via utils/bin2h_peb.py
├── resource.c          # XOR unmask for embedded payload resource
├── resource.h
├── native.h            # Windows struct definitions (PEB, TEB, RTL_USER_PROCESS_PARAMETERS…)
└── dfr.h               # NTAPI / Win32 DFR declarations
loader.spec             # Crystal Palace build spec
Makefile
utils/
└── bin2h_peb.py        # assembles peb_walk.asm → peb_walk_blob.h
```

---

## ShellCodeWriter

C port of [ShellCodeWriter.cpp](https://github.com/Orange-Cyberdefense/p3-loader/blob/main/P3-Loader/ShellCodeWriter.cpp) from p3-loader. Designed for Crystal Palace PIC constraints: no CRT, no globals, no switch statements, caller-managed buffer.

Primary function:

```c
scw_stomp_and_call(&w,
    (u64)KERNEL32$VirtualProtect,
    "KernelBase.dll", "QueryDosDeviceW",
    (const u8 *)payload, payload_len,
    btit_addr, ruts_addr);
// w.buf[0..w.len-1] = null-free module-stomping stub
```

Buffer size:

```c
#define SCW_STUB_SIZE(payload_len)  (((payload_len) / 8 + 1) * 24 + 640)
```

---

## References

- Hirschberger & Ugur — [P³ Whitepaper](https://github.com/Orange-Cyberdefense/p3-loader/blob/main/Whitepaper-P3.pdf)
- Orange-Cyberdefense — [p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- Raphael Mudge — [tradecraftgarden.org](https://tradecraftgarden.org)
- NtDallas — [Draugr](https://github.com/NtDallas/Draugr)
- rasta-mouse — [Crystal-Kit](https://github.com/rasta-mouse/Crystal-Kit)
- modexp — [Windows Process Injection: Command Line and Environment Variables](https://web.archive.org/web/20241211190548/https://modexp.wordpress.com/2020/07/31/wpi-cmdline-envar/) (archived)

---

> **For educational and authorized lab use only.**

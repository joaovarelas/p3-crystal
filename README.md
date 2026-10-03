<p align="center">
  <img src="docs/logo.png" alt="P3-Crystal" width="250"/>
</p>


# P³-Crystal

Crystal Palace PICO implementation of Process Parameter Poisoning (P³).

Injects shellcode into a child process via `CreateProcessW` parameter fields
(`ShellInfo` / `lpReserved`) without calling `VirtualAlloc`, `WriteProcessMemory`,
or `CreateRemoteThread`. 

Includes a C port of p3-loader's `ShellCodeWriter` for
generating null-free decoder stubs compatible with null-terminated Unicode parameters.


---

## Background

- Technique: [Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/) — Hirschberger & Ugur, SensePost 2026
- Framework: [Crystal Palace](https://tradecraftgarden.org) — Raphael Mudge / AFF-WG
- Full writeup: [P³ in the Palace](https://vrls.ws/posts/p3-in-the-palace-process-parameter-poisoning-in-crystal-palace/) — vrls.ws

---

## How It Works

```
Makefile
  └─ xxd payload → SC_HEX_DATA → loader.spec (XOR masked, embedded)
       └─ Crystal Palace PICO (go)
            ├─ unmask payload resource
            ├─ scw_load_and_call → null-free stub
            ├─ CreateProcessW(lpReserved = stub)
            │    └─ OS copies stub → child RTL_USER_PROCESS_PARAMETERS.ShellInfo
            ├─ NtQueryInformationProcess + NtReadVirtualMemory → ShellInfo.Buffer
            ├─ NtProtectVirtualMemory(child, stub region, RX)
            └─ NtSetContextThread(child.RIP = ShellInfo.Buffer)
                 └─ child executes stub
                      ├─ VirtualAlloc(RW)
                      ├─ copy payload from stack
                      ├─ VirtualProtect(RX)
                      └─ jmp r12 → payload runs
```

---

## Requirements

- [Crystal Palace](https://tradecraftgarden.org/crystalpalace.html) (`cpl` on PATH)
- `x86_64-w64-mingw32-gcc`
- `xxd`, `make`
- Windows x64 target (tested on Windows 10/11)

---

## Build

```bash
make SCFILE=payloads/calc.bin
```


---

## Project Structure

```
src/
├── main.c          # go() entry point, full P³ injection chain
├── services.c      # DFR resolvers (resolve, resolve_ext)
├── shellwriter.c   # null-free stub generator (port of ShellCodeWriter.cpp)
├── shellwriter.h
├── utils.c
├── utils.h
├── dfr.h           # NTAPI / Win32 DFR declarations
└── win.h
```

---

## ShellCodeWriter

C port of [ShellCodeWriter.cpp](https://github.com/Orange-Cyberdefense/p3-loader/blob/main/P3-Loader/ShellCodeWriter.cpp) from p3-loader. Designed for Crystal Palace PIC constraints: no CRT, no globals, no switch statements, caller-managed buffer.

Primary function:

```c
scw_load_and_call(&w,
    (u64)KERNEL32$VirtualAlloc,
    (u64)KERNEL32$VirtualProtect,
    (const u8 *)payload,
    payload_len);
// w.buf[0..w.len-1] = null-free decoder stub
```


---

## References

- Hirschberger & Ugur — [P³ Whitepaper](https://github.com/Orange-Cyberdefense/p3-loader/blob/main/Whitepaper-P3.pdf)
- Orange-Cyberdefense — [p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- Raphael Mudge — [tradecraftgarden.org](https://tradecraftgarden.org)
- rasta-mouse — [Crystal-Kit](https://github.com/rasta-mouse/Crystal-Kit)
- modexp — [Windows Process Injection: Command Line and Environment Variables](https://web.archive.org/web/20241211190548/https://modexp.wordpress.com/2020/07/31/wpi-cmdline-envar/) (archived)

---

> **For educational and authorized lab use only.**
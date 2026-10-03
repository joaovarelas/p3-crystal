; msgbox.asm  — x64 NULL-free shellcode
; MessageBoxA(NULL, "hello world", "vrls.ws", MB_ICONINFORMATION)
; nasm -f bin msgbox.asm -o msgbox.bin
BITS 64

; ----- resolver macro: in rbx=module base, r14d=hash ; out rax=func addr
%macro RESOLVE 0
    mov   eax, [rbx+3Ch]        ; e_lfanew
    add   rax, rbx             ; NT headers
    mov   rdx, rax             ; copy ptr to rdx (so deref isn't [rax])
    add   rdx, 40h             ; 0x88 = 0x40 + 0x48, split to avoid a
    add   rdx, 48h             ;   4-byte displacement full of null bytes
    mov   eax, [rdx]           ; ExportDir RVA (8B 02, no null)
    add   rax, rbx             ; IMAGE_EXPORT_DIRECTORY *
    mov   r9, rax              ; r9 = export dir
    xor   rcx, rcx
    mov   ecx, [r9+18h]        ; NumberOfNames (counter)
    mov   r10d, [r9+20h]       ; AddressOfNames RVA
    add   r10, rbx             ; names table *
%%loop:
    dec   rcx
    js    %%done               ; exhausted (won't happen for valid hash)
    mov   r8d, [r10+rcx*4]     ; Names[i] RVA
    add   r8, rbx              ; name string *
    xor   eax, eax             ; hash = 0
%%hchar:
    movzx edx, byte [r8]
    test  dl, dl
    jz    %%hdone
    ror   eax, 0Dh             ; ROR 13
    add   eax, edx
    inc   r8
    jmp   %%hchar
%%hdone:
    cmp   eax, r14d
    jne   %%loop
    mov   r8d, [r9+24h]        ; AddressOfNameOrdinals RVA
    add   r8, rbx
    movzx eax, word [r8+rcx*2] ; ordinal
    mov   r8d, [r9+1Ch]        ; AddressOfFunctions RVA
    add   r8, rbx
    mov   eax, [r8+rax*4]      ; function RVA
    add   rax, rbx             ; absolute address
%%done:
%endmacro

_start:
    push rbp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    mov  rbp, rsp              ; frame anchor (restore rsp from here at exit)

; --- kernel32 base via PEB ---------------------------------------
    xor  rcx, rcx
    mov  rdx, [gs:rcx+60h]     ; PEB   (65 48 8B 51 60)
    mov  rdx, [rdx+18h]        ; PEB->Ldr
    mov  rdx, [rdx+20h]        ; InMemoryOrderModuleList -> exe
    mov  rdx, [rdx]            ; -> ntdll   (48 8B 12, no null)
    mov  rdx, [rdx]            ; -> kernel32
    mov  rbx, [rdx+20h]        ; kernel32 DllBase

; --- resolve LoadLibraryA ----------------------------------------
    mov  r14d, 0xEC0E4E8E      ; ROR13("LoadLibraryA")
    RESOLVE
    mov  rdi, rax             ; rdi = LoadLibraryA

; --- LoadLibraryA("user32.dll") ----------------------------------
    xor  rax, rax
    mov  ax, 0x6C6C           ; "ll"            (66 B8 6C 6C)
    push rax                  ; -> "ll\0\0\0\0\0\0"
    mov  rax, 0x642E323372657375 ; "user32.d"   (little-endian, no nulls)
    push rax
    mov  rcx, rsp             ; arg1 = "user32.dll"
    and  rsp, -10h            ; 16-byte align
    sub  rsp, 20h             ; shadow space
    call rdi                  ; -> rax = user32 base
    mov  rbx, rax

; --- resolve MessageBoxA -----------------------------------------
    mov  r14d, 0xBC4DA2A8     ; ROR13("MessageBoxA")
    RESOLVE
    mov  rsi, rax             ; rsi = MessageBoxA

; --- build "hello world\0" ---------------------------------------
    xor  rax, rax
    mov  al, 0x64             ; 'd'
    shl  rax, 8
    mov  al, 0x6C             ; 'l'
    shl  rax, 8
    mov  al, 0x72             ; 'r'
    push rax                  ; -> "rld\0\0\0\0\0"
    mov  rax, 0x6F77206F6C6C6568 ; "hello wo"
    push rax
    mov  r12, rsp             ; r12 = lpText

; --- build "vrls.ws\0" (7 chars + inline terminator = 8 bytes) ---
    xor  rax, rax
    mov  al, 0x73             ; 's'
    shl  rax, 8
    mov  al, 0x77             ; 'w'
    shl  rax, 8
    mov  al, 0x2E             ; '.'
    shl  rax, 8
    mov  al, 0x73             ; 's'
    shl  rax, 8
    mov  al, 0x6C             ; 'l'
    shl  rax, 8
    mov  al, 0x72             ; 'r'
    shl  rax, 8
    mov  al, 0x76             ; 'v'
    push rax                  ; -> "vrls.ws\0"
    mov  r13, rsp             ; r13 = lpCaption

; --- MessageBoxA(NULL, text, caption, MB_ICONINFORMATION) --------
    xor  rcx, rcx             ; hWnd = NULL
    mov  rdx, r12             ; lpText
    mov  r8,  r13             ; lpCaption
    xor  r9, r9
    mov  r9b, 0x40            ; uType = MB_ICONINFORMATION (0x40)
    and  rsp, -10h
    sub  rsp, 20h
    call rsi                  ; MessageBoxA

; --- restore context & return ------------------------------------
    mov  rsp, rbp
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    pop  rbp
    ret
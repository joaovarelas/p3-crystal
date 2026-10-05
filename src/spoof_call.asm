bits 64

; SPOOF_CTX field offsets
%define CTX_ALLOC_SIZE  0x00
%define CTX_GADGET      0x08
%define CTX_BTIT        0x10
%define CTX_RUTS        0x18
%define CTX_BTIT_OFF    0x20
%define CTX_RUTS_OFF    0x28
%define CTX_NULL_OFF    0x30
%define CTX_REAL_RET    0x38
%define CTX_FAKE_STACK  0x40
%define CTX_FIXUP       0x48
%define CTX_REAL_RSP    0x50
%define CTX_ARGS        0x58

; spoof_call_inner(SPOOF_CTX *ctx, u64 func, a1..a11)
;   rcx=ctx  rdx=func  r8=a1  r9=a2
;   [rsp+0x28]=a3  [rsp+0x30]=a4  [rsp+0x38..0x68]=a5..a11
;
; Switches RSP to a heap fake stack, builds a synthetic call chain
; (gadget → BTIT → RUTS → NULL), then jumps to the NT function.
;
; Return path: NT ret → gadget (FF 23: jmp [rbx]) → fixup
; fixup reloads ctx from [fake_stack-8], restores RSP, jumps to real_ret.

global spoof_call_inner

spoof_call_inner:
    mov     r15, rcx                        ; r15 = ctx

    mov     rax, [rsp]
    mov     [r15 + CTX_REAL_RET], rax       ; save return addr
    mov     [r15 + CTX_REAL_RSP], rsp       ; save go()'s RSP

    lea     rbx, [r15 + CTX_FIXUP]          ; rbx = &ctx->fixup (for FF 23 gadget)

    ; shift args: func→r10, a1→rcx, a2→rdx, a3→r8, a4→r9
    mov     r10, rdx
    mov     rcx, r8
    mov     rdx, r9
    mov     r8,  [rsp+0x28]
    mov     r9,  [rsp+0x30]

    ; save a5..a11 to ctx before stack switch
    mov     rax, [rsp+0x38]  ;  mov     [r15 + CTX_ARGS + 0x00], rax
    mov     [r15 + CTX_ARGS + 0x00], rax
    mov     rax, [rsp+0x40]
    mov     [r15 + CTX_ARGS + 0x08], rax
    mov     rax, [rsp+0x48]
    mov     [r15 + CTX_ARGS + 0x10], rax
    mov     rax, [rsp+0x50]
    mov     [r15 + CTX_ARGS + 0x18], rax
    mov     rax, [rsp+0x58]
    mov     [r15 + CTX_ARGS + 0x20], rax
    mov     rax, [rsp+0x60]
    mov     [r15 + CTX_ARGS + 0x28], rax
    mov     rax, [rsp+0x68]
    mov     [r15 + CTX_ARGS + 0x30], rax

    ; compute fixup runtime addr via call/pop before stack switch
    call    .here
.here:
    pop     rax
    add     rax, (fixup - .here)
    mov     [r15 + CTX_FIXUP], rax

    ; store ctx below fake stack base so fixup can reload r15 after NT clobbers it
    mov     rax, [r15 + CTX_FAKE_STACK]
    mov     [rax - 8], r15

    ; switch to fake stack
    mov     rsp, [r15 + CTX_FAKE_STACK]

    ; build fake frame chain on fake stack
    mov     rax, [r15 + CTX_GADGET]
    mov     [rsp], rax                      ; [rsp+0x00] = gadget (NT ret lands here)

    mov     rax, [r15 + CTX_ARGS + 0x00]
    mov     [rsp+0x28], rax
    mov     rax, [r15 + CTX_ARGS + 0x08]
    mov     [rsp+0x30], rax
    mov     rax, [r15 + CTX_ARGS + 0x10]
    mov     [rsp+0x38], rax
    mov     rax, [r15 + CTX_ARGS + 0x18]
    mov     [rsp+0x40], rax
    mov     rax, [r15 + CTX_ARGS + 0x20]
    mov     [rsp+0x48], rax
    mov     rax, [r15 + CTX_ARGS + 0x28]
    mov     [rsp+0x50], rax
    mov     rax, [r15 + CTX_ARGS + 0x30]
    mov     [rsp+0x58], rax

    mov     rax, [r15 + CTX_BTIT]
    mov     r11, [r15 + CTX_BTIT_OFF]
    mov     [rsp + r11], rax                ; plant BTIT

    mov     rax, [r15 + CTX_RUTS]
    mov     r11, [r15 + CTX_RUTS_OFF]
    mov     [rsp + r11], rax                ; plant RUTS

    xor     rax, rax
    mov     r11, [r15 + CTX_NULL_OFF]
    add     r11, rsp
    mov     [r11], rax                      ; plant NULL terminator

    jmp     r10                             ; call NT function

; fixup — entered via gadget after NT function returns
; rsp = fake_stack + 8, rax = NT return value (preserved through restore)
fixup:
    mov     r15, [rsp - 16]                 ; reload ctx from [fake_stack - 8]
    mov     rsp, [r15 + CTX_REAL_RSP]       ; restore go()'s RSP
    jmp     qword [r15 + CTX_REAL_RET]      ; return to go()
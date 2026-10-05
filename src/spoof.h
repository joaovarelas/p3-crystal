#pragma once

#include <windows.h>
#include <stdint.h>

#include "dfr.h"

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;



/* ── SPOOF_CTX ───────────────────────────────────────────────────────── */
typedef struct {
    u64 alloc_size;   /* +0x00  total bytes sub'd from fake RSP        */
    u64 gadget;       /* +0x08  FF 23 gadget addr in kernelbase         */
    u64 btit;         /* +0x10  BaseThreadInitThunk + 0x14              */
    u64 ruts;         /* +0x18  RtlUserThreadStart  + 0x21              */
    u64 btit_off;     /* +0x20  [fake_rsp + btit_off] = btit            */
    u64 ruts_off;     /* +0x28  [fake_rsp + ruts_off] = ruts            */
    u64 null_off;     /* +0x30  [fake_rsp + null_off] = 0               */
    u64 real_ret;     /* +0x38  go()'s return addr (set per-call)       */
    u64 fake_stack;   /* +0x40  heap fake stack base (RSP switches here)*/
    u64 fixup;        /* +0x48  addr of fixup label in spoof_call.asm   */
    u64 real_rsp;     /* +0x50  go()'s RSP to restore in fixup          */
    u64 args[7];      /* +0x58  a5..a11 saved before stack switch       */
                      /* +0x60 +0x68 +0x70 +0x78 +0x80 +0x88           */
} SPOOF_CTX;

extern SPOOF_CTX *g_ctx;


/* spoof_call_inner — raw asm in spoof_call.bin, linked via linkfunc    */
u64 spoof_call_inner(SPOOF_CTX *ctx, u64 func,
                     u64 a1, u64 a2, u64 a3, u64 a4, u64 a5,
                     u64 a6, u64 a7, u64 a8, u64 a9, u64 a10, u64 a11);

                     static inline __attribute__((always_inline)) u64  spoof_call(u64 func,
                              u64 a1, u64 a2, u64 a3, u64 a4, u64 a5,
                              u64 a6, u64 a7, u64 a8, u64 a9, u64 a10, u64 a11)
{
    return spoof_call_inner(g_ctx, func,
                            a1, a2, a3, a4, a5,
                            a6, a7, a8, a9, a10, a11);
}


void init_spoof(void);


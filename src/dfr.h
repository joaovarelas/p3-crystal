#pragma once
#include <windows.h>

NTSYSAPI LONG NTAPI NTDLL$NtQueryInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
NTSYSAPI NTSTATUS NTAPI NTDLL$NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
NTSYSAPI NTSTATUS NTAPI NTDLL$NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T ProtectSize, ULONG NewProtect, PULONG OldProtect);
NTSYSAPI NTSTATUS NTAPI NTDLL$NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
NTSYSAPI NTSTATUS NTAPI NTDLL$NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
NTSYSAPI NTSTATUS NTAPI NTDLL$NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
WINBASEAPI BOOL WINAPI USER32$PostThreadMessageA(DWORD idThread, UINT Msg, WPARAM wParam, LPARAM lParam);
WINBASEAPI BOOL WINAPI KERNEL32$ConvertFiberToThread();
WINBASEAPI VOID WINAPI KERNEL32$DeleteFiber(LPVOID lpFiber);
WINBASEAPI BOOL WINAPI KERNEL32$CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
WINBASEAPI PRUNTIME_FUNCTION WINAPI KERNEL32$RtlLookupFunctionEntry (DWORD64 ControlPc, PDWORD64 ImageBase, PVOID HistoryTable);
WINBASEAPI VOID WINAPI KERNEL32$SwitchToFiber (LPVOID lpFiber);
WINBASEAPI BOOL WINAPI KERNEL32$K32EnumProcessModulesEx (HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded, DWORD dwFilterFlag);
WINBASEAPI PVOID NTAPI NTDLL$RtlAllocateHeap (PVOID HeapHandle, ULONG Flags, SIZE_T Size);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap (VOID);
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA (LPCSTR lpModuleName);
WINBASEAPI PVOID WINAPI KERNEL32$ConvertThreadToFiber(PVOID lpParameter);
WINBASEAPI VOID WINAPI KERNELBASE$GetCurrentThreadStackLimits (PULONG_PTR LowLimit, PULONG_PTR HighLimit);
WINBASEAPI PVOID WINAPI KERNEL32$CreateFiber(SIZE_T dwStackSize, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter);
WINBASEAPI HANDLE  WINAPI KERNEL32$CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);
WINBASEAPI UINT WINAPI KERNEL32$WinExec( LPCSTR lpCmdLine, UINT uCmdShow );
WINBASEAPI VOID WINAPI KERNEL32$Sleep( DWORD dwMilliseconds );
WINBASEAPI VOID WINAPI KERNEL32$OutputDebugStringA(LPCSTR lpOutputString);

NTSYSAPI int NTAPI NTDLL$vsprintf(char* buffer, const char* format, va_list argptr);
NTSYSAPI int NTAPI NTDLL$sprintf(char* buffer, const char* format, ...);

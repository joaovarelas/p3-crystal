#pragma once 

#include <windows.h>
#include "native.h"

NTSYSAPI int NTAPI NTDLL$sprintf(char* buffer, const char* format, ...);
NTSYSAPI int NTAPI NTDLL$vsprintf(char* buffer, const char* format, va_list argptr);
NTSYSAPI LONG NTAPI NTDLL$NtQueryInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
NTSYSAPI NTSTATUS NTAPI NTDLL$NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NTSYSAPI NTSTATUS NTAPI NTDLL$NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
NTSYSAPI NTSTATUS NTAPI NTDLL$NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T ProtectSize, ULONG NewProtect, PULONG OldProtect);
NTSYSAPI NTSTATUS NTAPI NTDLL$NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
NTSYSAPI NTSTATUS NTAPI NTDLL$NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
NTSYSAPI NTSTATUS NTAPI NTDLL$NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);
NTSYSAPI NTSTATUS NTAPI NTDLL$NtClose(HANDLE Handle);
NTSYSAPI NTSTATUS NTAPI NTDLL$NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
NTSYSAPI NTSTATUS NTAPI NTDLL$RtlCreateProcessParametersEx(PRTL_USER_PROCESS_PARAMETERS *pProcessParameters, PUNICODE_STRING ImagePathName, PUNICODE_STRING DllPath, PUNICODE_STRING CurrentDirectory, PUNICODE_STRING CommandLine, PVOID Environment, PUNICODE_STRING WindowTitle, PUNICODE_STRING DesktopInfo, PUNICODE_STRING ShellInfo, PUNICODE_STRING RuntimeData, ULONG Flags);
NTSYSAPI NTSTATUS NTAPI NTDLL$RtlDestroyProcessParameters(PRTL_USER_PROCESS_PARAMETERS ProcessParameters);
NTSYSAPI NTSTATUS NTAPI NTDLL$NtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, PVOID ProcessObjectAttributes, PVOID ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList);
NTSYSAPI NTSTATUS NTAPI NTDLL$NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
NTSYSAPI  VOID NTAPI   NTDLL$RtlUserThreadStart(LPTHREAD_START_ROUTINE Function, PVOID Parameter);

WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI VOID WINAPI KERNEL32$BaseThreadInitThunk(DWORD LdrReserved, LPTHREAD_START_ROUTINE lpStartAddress, PVOID lpParameter);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI BOOL WINAPI KERNEL32$ConvertFiberToThread();
WINBASEAPI BOOL WINAPI KERNEL32$CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
WINBASEAPI BOOL WINAPI KERNEL32$K32EnumProcessModulesEx (HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded, DWORD dwFilterFlag);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
WINBASEAPI BOOL WINAPI USER32$PostThreadMessageA(DWORD idThread, UINT Msg, WPARAM wParam, LPARAM lParam);
WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
WINBASEAPI HANDLE  WINAPI KERNEL32$CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap (VOID);
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA (LPCSTR lpModuleName);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI PRUNTIME_FUNCTION WINAPI KERNEL32$RtlLookupFunctionEntry (DWORD64 ControlPc, PDWORD64 ImageBase, PVOID HistoryTable);
WINBASEAPI PVOID NTAPI NTDLL$RtlAllocateHeap (PVOID HeapHandle, ULONG Flags, SIZE_T Size);
WINBASEAPI PVOID WINAPI KERNEL32$ConvertThreadToFiber(PVOID lpParameter);
WINBASEAPI PVOID WINAPI KERNEL32$CreateFiber(SIZE_T dwStackSize, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter);
WINBASEAPI UINT WINAPI KERNEL32$WinExec( LPCSTR lpCmdLine, UINT uCmdShow );
WINBASEAPI VOID WINAPI KERNEL32$DeleteFiber(LPVOID lpFiber);
WINBASEAPI VOID WINAPI KERNEL32$OutputDebugStringA(LPCSTR lpOutputString);
WINBASEAPI VOID WINAPI KERNEL32$Sleep( DWORD dwMilliseconds );
WINBASEAPI VOID WINAPI KERNEL32$SwitchToFiber (LPVOID lpFiber);
WINBASEAPI VOID WINAPI KERNELBASE$GetCurrentThreadStackLimits (PULONG_PTR LowLimit, PULONG_PTR HighLimit);

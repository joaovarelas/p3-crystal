#pragma once
#include <windows.h>

typedef struct
{
    PVOID ptr; /* function to call                           */
    DWORD ssn; /* syscall number (0 = not a direct syscall)  */
    int argc;  /* number of valid entries in args[]          */
    ULONG_PTR args[12];
} FUNCTION_CALL;

ULONG_PTR spoof_call(FUNCTION_CALL *call);

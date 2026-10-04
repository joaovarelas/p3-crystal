#pragma once

#include <windows.h>


#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)


typedef struct _PROCESS_BASIC_INFORMATION {
    LONG ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[21];
    PVOID LoaderData;
    PVOID ProcessParameters;
    BYTE Reserved3[520];
    PVOID PostProcessInitRoutine;
    BYTE Reserved4[136];
} PEB;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;


#define RTL_MAX_DRIVE_LETTERS 32

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;


typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;

    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;

    UNICODE_STRING RedirectionDllName; // RS4
    UNICODE_STRING HeapPartitionName; // 19H1
    ULONG_PTR DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    ULONG DefaultThreadpoolThreadMaximum;
    ULONG HeapMemoryTypeMask; // WIN11
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;




// PS_CREATE_STATE
typedef enum _PS_CREATE_STATE {
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName,
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE;

// PS_CREATE_INFO
typedef struct _PS_CREATE_INFO {
    SIZE_T Size;
    PS_CREATE_STATE State;
    union {
        struct {
            union {
                ULONG InitFlags;
                struct {
                    UCHAR WriteWatch             : 1;
                    UCHAR DetectManifest         : 1;
                    UCHAR IFEOSkipDebugger       : 1;
                    UCHAR IFEODoNotPropagateKey  : 1;
                    UCHAR SpareBits1             : 4;
                    UCHAR SpareBits2             : 8;
                    USHORT ProhibitedImageChars  : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;
        struct { HANDLE FileHandle;          } FailSection;
        struct { USHORT DllCharacteristics;  } ExeFormat;
        struct { HANDLE IFEOKey;             } ExeName;
        struct {
            union {
                ULONG OutputFlags;
                struct {
                    UCHAR ProtectedProcess      : 1;
                    UCHAR AddressSpaceOverride  : 1;
                    UCHAR DevOverrideEnabled    : 1;
                    UCHAR ManifestDetected      : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1            : 3;
                    UCHAR SpareBits2            : 8;
                    USHORT SpareBits3           : 16;
                };
            };
            HANDLE    FileHandle;
            HANDLE    SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG     UserProcessParametersWow64;
            ULONG     CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG     PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG     ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, *PPS_CREATE_INFO;

// PS_ATTRIBUTE
typedef struct _PS_ATTRIBUTE {
    ULONG_PTR  Attribute;
    SIZE_T     Size;
    union {
        ULONG_PTR Value;
        PVOID     ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

// Flags
#define PS_ATTRIBUTE_IMAGE_NAME              0x00020005UL
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001UL
#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED 0x01
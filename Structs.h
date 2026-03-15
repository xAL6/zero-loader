#pragma once
#include <Windows.h>

// =============================================
// Undocumented Windows Structures for PEB Walk
// =============================================

typedef struct _UNICODE_STR {
    USHORT  Length;
    USHORT  MaximumLength;
    PWSTR   Buffer;
} UNICODE_STR, * PUNICODE_STR;

typedef struct _LDR_DT_TABLE_ENTRY {
    LIST_ENTRY  InLoadOrderLinks;
    LIST_ENTRY  InMemoryOrderLinks;
    LIST_ENTRY  InInitializationOrderLinks;
    PVOID       DllBase;
    PVOID       EntryPoint;
    ULONG       SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG       Flags;
    WORD        LoadCount;
    WORD        TlsIndex;
    union {
        LIST_ENTRY  HashLinks;
        struct {
            PVOID   SectionPointer;
            ULONG   CheckSum;
        };
    };
    union {
        ULONG   TimeDateStamp;
        PVOID   LoadedImports;
    };
    PVOID   EntryPointActivationContext;
    PVOID   PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DT_TABLE_ENTRY, * PLDR_DT_TABLE_ENTRY;

typedef struct _PEB_LD_DATA {
    ULONG       Length;
    BOOLEAN     Initialized;
    HANDLE      SsHandle;
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
    PVOID       EntryInProgress;
    BOOLEAN     ShutdownInProgress;
    HANDLE      ShutdownThreadId;
} PEB_LD_DATA, * PPEB_LD_DATA;

typedef struct _PEB2 {
    BOOLEAN                 InheritedAddressSpace;
    BOOLEAN                 ReadImageFileExecOptions;
    BOOLEAN                 BeingDebugged;
    union {
        BOOLEAN             BitField;
        struct {
            BOOLEAN         ImageUsesLargePages : 1;
            BOOLEAN         IsProtectedProcess : 1;
            BOOLEAN         IsImageDynamicallyRelocated : 1;
            BOOLEAN         SkipPatchingUser32Forwarders : 1;
            BOOLEAN         IsPackagedProcess : 1;
            BOOLEAN         IsAppContainer : 1;
            BOOLEAN         IsProtectedProcessLight : 1;
            BOOLEAN         IsLongPathAwareProcess : 1;
        };
    };
    HANDLE                  Mutant;
    PVOID                   ImageBaseAddress;
    PPEB_LD_DATA            Ldr;
    PVOID                   ProcessParameters;
    PVOID                   SubSystemData;
    HANDLE                  ProcessHeap;
    PRTL_CRITICAL_SECTION   FastPebLock;
    PVOID                   AtlThunkSListPtr;
    PVOID                   IFEOKey;
    union {
        ULONG               CrossProcessFlags;
        struct {
            ULONG           ProcessInJob : 1;
            ULONG           ProcessInitializing : 1;
            ULONG           ProcessUsingVEH : 1;
            ULONG           ProcessUsingVCH : 1;
            ULONG           ProcessUsingFTH : 1;
            ULONG           ProcessPreviouslyThrottled : 1;
            ULONG           ProcessCurrentlyThrottled : 1;
            ULONG           ProcessImagesHotPatched : 1;
            ULONG           ReservedBits0 : 24;
        };
    };
    union {
        PVOID               KernelCallbackTable;
        PVOID               UserSharedInfoPtr;
    };
    ULONG                   SystemReserved;
    ULONG                   AtlThunkSListPtr32;
    PVOID                   ApiSetMap;
    ULONG                   TlsExpansionCounter;
    PVOID                   TlsBitmap;
    ULONG                   TlsBitmapBits[2];
    PVOID                   ReadOnlySharedMemoryBase;
    PVOID                   SharedData;
    PVOID*                  ReadOnlyStaticServerData;
    PVOID                   AnsiCodePageData;
    PVOID                   OemCodePageData;
    PVOID                   UnicodeCaseTableData;
    ULONG                   NumberOfProcessors;
    ULONG                   NtGlobalFlag;
    // ... truncated, enough for our purposes
} PEB2, * PPEB2;

// USTRING for SystemFunction032 (RC4)
typedef struct _USTRING {
    DWORD   Length;
    DWORD   MaximumLength;
    PVOID   Buffer;
} USTRING, * PUSTRING;


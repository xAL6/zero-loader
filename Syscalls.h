#pragma once
#include <Windows.h>
#include "Structs.h"

// =============================================
// Indirect Syscall Engine
// =============================================

// NTDLL module config (cached)
typedef struct _NTDLL_CONFIG {
    ULONG_PTR   uModule;
    PDWORD      pdwArrayOfAddresses;
    PDWORD      pdwArrayOfNames;
    PWORD       pwArrayOfOrdinals;
    DWORD       dwNumberOfNames;
} NTDLL_CONFIG, * PNTDLL_CONFIG;

// Single syscall entry
typedef struct _NT_SYSCALL {
    DWORD   dwSSn;              // Syscall Service Number
    DWORD   dwSyscallHash;      // Jenkins hash of the name
    PVOID   pSyscallAddress;    // Address of syscall;ret in ntdll (for indirect)
} NT_SYSCALL, * PNT_SYSCALL;

// All resolved syscalls
typedef struct _NTAPI_FUNC {
    NT_SYSCALL  NtAllocateVirtualMemory;
    NT_SYSCALL  NtProtectVirtualMemory;
    NT_SYSCALL  NtWaitForSingleObject;
    NT_SYSCALL  NtCreateSection;
    NT_SYSCALL  NtMapViewOfSection;
} NTAPI_FUNC, * PNTAPI_FUNC;

// ASM functions (defined in AsmStub.asm)
extern VOID SetSSn(DWORD wSSn, PVOID pSyscallAddr);

// RunSyscall must be declared with max param count (12) so the compiler
// allocates correct stack space for syscalls like NtMapViewOfSection (10 params)
extern NTSTATUS RunSyscall(
    ULONG_PTR u1, ULONG_PTR u2, ULONG_PTR u3, ULONG_PTR u4,
    ULONG_PTR u5, ULONG_PTR u6, ULONG_PTR u7, ULONG_PTR u8,
    ULONG_PTR u9, ULONG_PTR u10, ULONG_PTR u11, ULONG_PTR u12
);

// Macro to set SSN before each syscall — uses random gadget from pool
#define SET_SYSCALL(NtFunc) SetSSn((NtFunc).dwSSn, GetRandomGadget())

// Init functions
BOOL InitNtdllConfigStructure(VOID);
BOOL FetchNtSyscall(IN DWORD dwSyscallHash, OUT PNT_SYSCALL pNtSyscall);
BOOL InitializeNtSyscalls(OUT PNTAPI_FUNC pNtApis);

// Gadget randomization
PVOID GetRandomGadget(VOID);

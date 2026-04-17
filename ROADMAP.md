# Roadmap

Forward-looking improvement backlog for `zero-loader`. Each item lists
scope, engineering cost, required pre-work, and the detection axis it
targets. Nothing here is committed — this is a design document.

Items are grouped by commitment level. Top of the list = ready to
execute after current branch lands; bottom = structurally deep or
architecture-changing.

---

## A. Validation gates (do these first, no code)

These unblock safer decisions about the opt-in / stretch work below.

### A.1 Target-environment memory scan

- Build loader with current `HEAD`, deploy on a representative
  workstation matching the intended target (Defender ATP on, EDR vendor
  of interest).
- Run Moneta (`Moneta64.exe -p <pid> -m *`) and Pe-Sieve
  (`pe-sieve /pid <pid> /quiet`) against the loader process.
- Capture flags per region: stomped `.text` (expect clean if #10 worked),
  heap (watch for the 1 MB synthetic-stack block if `ENABLE_SYNTHETIC_STACK`
  is on), private RW regions.
- **Decision point**: if stomped regions show "executable + no matching
  image base", #10 failed — debug `RtlAddFunctionTable` resolution.

### A.2 Stack-walk truthiness check

- Attach WinDbg, break after `SwitchToFiber`, run `k` and `.frame /r`
  on the fiber thread.
- Walk should terminate cleanly at a module-boundary frame — no `?`
  markers, no misaligned RSP.
- Repeat with `ENABLE_SYNTHETIC_STACK` on; if unwinding diverges or
  reads garbage past the three fake anchors, #9 MVP is too fragile for
  the target env.

### A.3 Host compatibility (DLL sideload only)

- For each intended host EXE, check whether `ConvertThreadToFiber` is
  already imported or called (`dumpbin /imports`, IDA cross-ref).
- Hosts that manage their own fibers (rare: DB engines, some game
  engines, some VM runtimes) are incompatible with `#12`; fallback will
  kick in but loses the main-thread stealth advantage.

---

## B. Near-term (days, low risk)

### B.1 Reduce synthetic-stack size when opt-in

- **Scope**: change `FAKE_STACK_BYTES` from 1 MB to 64 KB. Move RSP to
  `buffer + 48 KB`, leaving 16 KB "above" (unused) and 48 KB below for
  shellcode pushes.
- **Why**: 1 MB private blocks with function pointers inside are a
  heuristic signal. 64 KB matches fiber-default stack size.
- **Pre-req**: verify Beacon/Sliver payloads never push > 48 KB (they
  don't; typical depth < 16 KB).
- **Cost**: ~10 LoC.

### B.2 Replace `HeapAlloc` with `NtAllocateVirtualMemory` for fake stack

- **Scope**: use the already-resolved `NtApis.NtAllocateVirtualMemory`
  indirect syscall. Region attributes `MEM_COMMIT | MEM_RESERVE`,
  `PAGE_READWRITE`.
- **Why**: thread stacks themselves are `VirtualAlloc`'d; a similarly-
  sized private RW block looks more like a legit stack than a heap
  block full of function pointers.
- **Cost**: ~20 LoC (pass `NtApis` into `BuildSyntheticStack`).

### B.3 `VirtualProtect` the call-gadget return site to `PAGE_EXECUTE_READONLY`

- **Scope**: no-op — it already is. Document this in `CollectCallGadgets`
  so nobody later tries to patch the gadget location thinking it's writable.

### B.4 Randomize `Mutate.py` entropy-filler pool per build

- **Scope**: pick a subset of `LOW_ENTROPY_FILLERS` per run rather than
  using the full list every time. Different sections get different
  string distributions.
- **Why**: currently every build has the same filler pool, making the
  set of strings itself a signature.
- **Cost**: ~15 LoC.

---

## C. Structural upgrades (weeks, medium risk)

### C.1 Complete Draugr (replaces #9 MVP)

**What's missing vs MVP:**

1. **Synthetic UNWIND_INFO per frame.** Each fake return gets its own
   `RUNTIME_FUNCTION` + `UNWIND_INFO` registered with
   `RtlAddFunctionTable`, describing the actual frame size we pushed
   (not borrowing ntdll's). `RtlVirtualUnwind` pops the correct byte
   count and walks cleanly.

2. **Per-call stack swap.** Primitive `SpoofCall(target, arg1..arg4)`
   swaps to a fresh fake stack, calls the API, swaps back.
   Return value preserved in RAX. Loader's own API calls (VirtualProtect
   on stomped region, LoadLibraryA of amsi/wininet/ktmw32) are all
   callstack-spoofed, not just the final shellcode jump.

3. **Variable frame count.** 3-to-8 frames per spoof, depth chosen per
   call via RDTSC, so behavioural fingerprinting can't lock onto a
   fixed depth.

**Scope**: 400-600 LoC.
- `.pdata` parser extracting real frame sizes from ntdll/kernel32/kernelbase
- UNWIND_CODE synthesizer (UWOP_PUSH_NONVOL, UWOP_ALLOC_SMALL,
  UWOP_SAVE_XMM128 etc.) matching our synthetic frame layout
- Re-entrant `SpoofCall` asm stub with arg passthrough (RCX/RDX/R8/R9
  + shadow space + stack args)
- `RtlAddFunctionTable` bookkeeping with matching `RtlDeleteFunctionTable`
  at `CleanupEvasion` time

**Pre-req**: A.2 stack-walk validation must pass with MVP first,
otherwise we're solving a problem we can't measure.

**Alternative**: bring in [Kudaes/Unwinder](https://github.com/Kudaes/Unwinder)
or [NtDallas/Draugr](https://github.com/NtDallas/Draugr) as an external
reference, port the primitives to CRT-free C. Saves ~200 LoC of
`.pdata` / UWOP plumbing but adds a dependency-review step.

### C.2 Per-syscall gadget-pool rotation

- **Scope**: current `CollectSyscallGadgets` builds one pool at init and
  `GetRandomGadget` picks from it. Behavioural fingerprinting on
  "syscall originates from ntdll section offset X" can still learn the
  distribution.
- **Upgrade**: re-harvest the pool periodically (e.g. every N syscalls),
  weighted so rarely-used gadgets get picked more often.
- **Cost**: ~40 LoC.
- **Return**: marginal; indirect syscalls are already well-covered.

### C.3 `RtlAddFunctionTable` → `RtlInstallFunctionTableCallback`

- **Scope**: switch from a static `RUNTIME_FUNCTION` array to a
  callback-based registration. The kernel calls our callback on demand
  to fetch unwind info, letting us serve different descriptors per
  `rip` without allocating N entries up-front.
- **Why**: enables the per-call spoof primitive in C.1 with less
  memory fragmentation.
- **Cost**: ~80 LoC.

---

## D. Architecture changes (pivot-level, high risk)

### D.1 `#11 Trap Flag` — only if the architecture pivots away from indirect syscalls

Currently skipped because indirect syscalls jump directly to
`syscall;ret` gadgets and bypass any hooked ntdll stub prologue.
Trap-Flag argument tampering only matters if we're going **through**
the hooked stub.

**Would become valuable if:**

- We switch to direct syscalls for some reason (e.g. a future Windows
  kernel change that blocks indirect syscalls via KCFG-like mechanism)
- We want to spoof args visible to userland-hook inspectors without
  triggering the kernel's real syscall filter (some EDRs re-check args
  kernel-side — Trap Flag swap happens between the two)

**Scope**: ~400 LoC.
- VEH dispatcher with RIP-range routing (must coexist with AMSI/ETW
  patchless handler — currently `STATUS_SINGLE_STEP` is unambiguous)
- EFLAGS.TF set/clear sequencing
- Per-syscall "decoy/real arg" pair in a thread-local slot

### D.2 Sleep obfuscation — only if loader pivots to permanent implant

The loader currently exits Main by entering shellcode (Poison Fiber
path) or the alertable-wait keep-alive (fallback path). Its own memory
after shellcode runs is not a concern — shellcode (Beacon, Sliver,
Havoc) manages its own sleep-mask.

**Would become valuable if:**

- Loader code needs to survive in memory and re-execute on callback
- We start caching decrypted payload in loader memory for re-use

Candidates (per the 2024-2026 survey, see commit message of
`ee99cca`):
- Hypnus (TpSetTimer/TpSetWait ROP)
- Shelter (ROP + AES-NI, full-PE encryption)
- AceLdr 2024 (`Wait:UserRequest` version, already partially adopted)

**Scope**: 600-1200 LoC depending on technique.

### D.3 Early Cascade Injection (Outflank 2024-10)

Loader currently relies on the target running the host EXE with an EDR
that's already attached. Early Cascade spawns a suspended child and
writes shellcode into its PEB `Ldr` callback / TLS array before the
EDR DLL is loaded.

**Architectural change**: loader becomes an **injector** rather than a
self-contained payload runner. Big refactor — `main.c` splits into
parent-path (spawn + patch) and child-path (pre-EDR execution).

**Scope**: ~800 LoC; structurally touches everything.

**Only do this if**: DLL sideload variant's current host-compat pain
exceeds the engineering cost.

---

## E. Out of scope (explicitly rejected)

Documented here so we don't re-evaluate them in every sprint.

| Technique | Why skipped |
|-----------|-------------|
| GPU memory hiding (D3D11) | Requires D3D11/DXGI DLL loads in a CLI-style loader — vastly out-of-family DLL-load sequence becomes the signature. Breaks CRT-free. Fails on headless servers and virtualized-GPU sessions. |
| O-MVLL / clang-cl toolchain | Loader depends on MSVC + `ml64` + `/NODEFAULTLIB` specifics. Migrating to clang-cl for IR-level obfuscation risks breaking assembly integration and CRT-free guarantees. ROI smaller than a custom CFF macro set on MSVC. |
| EDR-Preloader via AppVerifier | Requires HKLM registry write (admin), leaves Sysmon EventID 12/13 breadcrumbs. The UAC variant could host this as "post-elevation permanent unhook" but integration cost >> current hook-dodging approach. |
| DllNotificationInjection (self-callback) | Mutually exclusive with our `BlindDllNotifications`. Picking one means giving up the other's coverage; current blinding is strictly more defensive. |
| ARM64EC native build | Enterprise ARM64 adoption <5%, no concrete target demand. Would require `AsmStub_arm64.asm`, `svc #0; ret` gadget pattern, dual-build CI. |

---

## F. Validation-driven enable list

Items that can be flipped on **only after specific validation steps**.
Kept separate because turning them on blindly reintroduces known risk.

| Flag / item | Pre-req | Gate |
|-------------|---------|------|
| `ENABLE_SYNTHETIC_STACK` | A.1 + A.2 clean on target env | No new Moneta/Pe-Sieve flags; WinDbg stack-walk clean |
| `RWX_SHELLCODE` | Known Go/Sliver shellcode | Target shellcode documented to write its own pages |
| `REQUIRE_ELEVATION` (DLL sideload) | Admin path is the intended escalation | Host EXE acceptable to UAC-prompt; target user has dismiss-friendly context |

---

## Change log pointers

Full history of what landed is in `git log claude/code-optimization-review-5pUm6`.
Major commits:

- `754155a` PEB-walk dedup + single-pass syscall resolution
- `de1469b` #1 `Wait:UserRequest`
- `15d97fe` #2 DLL preload shuffle
- `e12ed57` #3 `\KnownDlls\ntdll.dll` SSN source
- `746ad11` `NtClose` handle cleanup
- `1f0c3b9` #4 multi-module call-gadget pool
- `9181d3e` #6 entropy-balanced Mutate.py
- `8b8acdd` #10 Stomp + synthetic `RUNTIME_FUNCTION`
- `ee99cca` #12 Poison Fiber + #9 Draugr MVP
- `ce99348` Gate #9 behind `ENABLE_SYNTHETIC_STACK`
- `619e15e` CLAUDE.md + README.md sync

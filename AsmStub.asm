;; AsmStub.asm - Indirect Syscall Stub (x64 MASM)
;; Provides SetSSn to configure SSN + target address
;; and RunSyscall to execute the indirect syscall

.data
    wSSn            DWORD   000h        ; Current SSN
    qSyscallAddr    QWORD   000h        ; Address of syscall;ret in ntdll

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

end

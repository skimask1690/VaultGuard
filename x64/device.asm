; ==============================================================================
; Vault Guard - Driver Device Layer
;
; Author: Marek Wesolowski (wesmar)
; Purpose: device open/close and EnsureDriverReady orchestration.
; ==============================================================================

option casemap:none

include consts.inc
include globals.inc
include driver_consts.inc

EXTRN CreateFileW           :PROC
EXTRN CloseHandle           :PROC
EXTRN IsDriverInstalled     :PROC
EXTRN InstallDriver         :PROC
EXTRN StartDriver           :PROC

.code
; OpenDevice  ?  rax=1/0  (sets g_hDevice)
;
; CreateFileW takes 7 args: rcx,rdx,r8,r9,[+20],[+28],[+30]
; Stack: entry rsp%16=8; push rbx,rsi (+16)?8; sub 38h (+56)?0 ?
; ==============================================================================
PUBLIC OpenDevice
OpenDevice proc
    push    rbx
    push    rsi
    sub     rsp, 38h

    mov     qword ptr [rsp+30h], 0          ; hTemplateFile
    mov     dword ptr [rsp+28h], 0          ; dwFlagsAndAttributes
    mov     dword ptr [rsp+20h], OPEN_EXISTING
    xor     r9d, r9d                        ; lpSecurityAttributes
    xor     r8d, r8d                        ; dwShareMode
    mov     edx, GENERIC_RW
    lea     rcx, str_device
    call    CreateFileW
    cmp     rax, INVALID_HANDLE_VALUE
    je      @od_fail

    mov     g_hDevice, rax
    mov     eax, 1
    jmp     @od_ret

@od_fail:
    mov     g_hDevice, 0
    xor     eax, eax
@od_ret:
    add     rsp, 38h
    pop     rsi
    pop     rbx
    ret
OpenDevice endp

; ==============================================================================
; CloseDevice  ?  void
; Stack: entry rsp%16=8; push rbx,rsi (+16)?8; sub 28h (+40)?0 ?
; ==============================================================================
PUBLIC CloseDevice
CloseDevice proc
    push    rbx
    push    rsi
    sub     rsp, 28h

    mov     rbx, g_hDevice
    test    rbx, rbx
    jz      @cd_done
    cmp     rbx, INVALID_HANDLE_VALUE
    je      @cd_done

    mov     rcx, rbx
    call    CloseHandle
    mov     g_hDevice, 0

@cd_done:
    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret
CloseDevice endp

; ==============================================================================
; EnsureDriverReady -> rax=1/0
; Opens the device if possible. If not, installs the service when missing,
; starts the driver, then opens the device again.
; Stack: entry rsp%16=8; sub 28h -> rsp%16=0
; ==============================================================================
PUBLIC EnsureDriverReady
EnsureDriverReady proc
    sub     rsp, 28h

    call    OpenDevice
    test    eax, eax
    jnz     @ready

    call    IsDriverInstalled
    test    eax, eax
    jnz     @start

    call    InstallDriver
    test    eax, eax
    jz      @fail

@start:
    call    StartDriver
    test    eax, eax
    jnz     @open_after_start

    ; StartDriver failed for reason other than 183/1056 ? last-ditch open attempt.
    call    OpenDevice
    test    eax, eax
    jnz     @ready
    jmp     @fail

@open_after_start:
    call    OpenDevice
    test    eax, eax
    jz      @fail

@ready:
    mov     eax, 1
    jmp     @ret

@fail:
    xor     eax, eax
@ret:
    add     rsp, 28h
    ret
EnsureDriverReady endp
end

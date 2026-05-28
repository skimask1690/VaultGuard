; ==============================================================================
; Vault Guard - Driver SCM Layer
;
; Author: Marek Wesolowski (wesmar)
; Purpose: install/start/stop/uninstall and startup type management for clrcd.
; ==============================================================================

option casemap:none

include consts.inc
include globals.inc

EXTRN OpenSCManagerW        :PROC
EXTRN CreateServiceW        :PROC
EXTRN OpenServiceW          :PROC
EXTRN StartServiceW         :PROC
EXTRN ControlService        :PROC
EXTRN ChangeServiceConfigW  :PROC
EXTRN DeleteService         :PROC
EXTRN CloseServiceHandle    :PROC
EXTRN DeleteFileW           :PROC
EXTRN GetSystemDirectoryW   :PROC
EXTRN GetLastError          :PROC
EXTRN ExtractDriver         :PROC
EXTRN RegCreateKeyExW       :PROC
EXTRN RegSetValueExW        :PROC
EXTRN RegCloseKey           :PROC

; ==============================================================================
; CONSTANT STRINGS
; ==============================================================================
.const
str_svc_name    dw 'c','l','r','c','d',0
str_svc_display dw 'V','a','u','l','t','G','u','a','r','d',' ','D','r','i','v','e','r',0
str_device      dw 05Ch,05Ch,'.',05Ch,'B','E','7','9','F','7','D','8','5','3','E','6','4','3','0','8','9','D','5','1','E','D','C','D','A','7','9','8','0','5','C','4',0
str_deps        dw 'F','l','t','M','g','r',0,0

str_group           dw 'F','S','F','i','l','t','e','r',' ','C','o','n','t','e','n','t'
                    dw ' ','S','c','r','e','e','n','e','r',0
str_def_inst        dw 'D','e','f','a','u','l','t','I','n','s','t','a','n','c','e',0
str_altitude_val    dw 'A','l','t','i','t','u','d','e',0
str_flags_val       dw 'F','l','a','g','s',0
str_altitude_data   dw '3','8','9','9','9','1',0
str_svc_clrcd_inst  dw 'S','Y','S','T','E','M','\','C','u','r','r','e','n','t','C','o'
                    dw 'n','t','r','o','l','S','e','t','\','S','e','r','v','i','c','e'
                    dw 's','\','c','l','r','c','d','\','I','n','s','t','a','n','c','e'
                    dw 's',0
str_svc_clrcd_inst_clrcd dw 'S','Y','S','T','E','M','\','C','u','r','r','e','n','t','C','o'
                         dw 'n','t','r','o','l','S','e','t','\','S','e','r','v','i','c','e'
                         dw 's','\','c','l','r','c','d','\','I','n','s','t','a','n','c','e'
                         dw 's','\','c','l','r','c','d',0

str_drv_nt_path     dw '\','S','y','s','t','e','m','R','o','o','t','\','s','y','s','t','e'
                    dw 'm','3','2','\','d','r','i','v','e','r','s','\','v','g','.','s','y'
                    dw 's',0

SVC_CTRL_STOP   EQU 1

; ==============================================================================

; ==============================================================================
; DATA
; ==============================================================================
.data
    align 8

PUBLIC str_svc_name
PUBLIC str_device
PUBLIC g_statusResult
PUBLIC str_drive

g_statusResult  db 16 dup(0)   ; VG_STATUS
str_drive       dw 0,':',0
inst_flags_zero dd 0

.data?
    svc_status_buf  db 36 dup(?)    ; SERVICE_STATUS_PROCESS
    inst_hkey1      dq ?

; ==============================================================================
; CODE
; ==============================================================================
.code
; ==============================================================================
; IsDriverInstalled  ?  rax=1/0
; Stack: entry rsp%16=8; push rbx,rsi (+16) ? rsp%16=8; sub 28h (+40) ? 0 ?
; ==============================================================================
PUBLIC IsDriverInstalled
IsDriverInstalled proc
    push    rbx
    push    rsi
    sub     rsp, 28h

    mov     r8d, SC_MANAGER_CONNECT
    xor     edx, edx
    xor     ecx, ecx
    call    OpenSCManagerW
    test    rax, rax
    jz      @idi_fail
    mov     rbx, rax

    mov     r8d, SERVICE_QUERY_STATUS
    lea     rdx, str_svc_name
    mov     rcx, rbx
    call    OpenServiceW
    test    rax, rax
    jz      @idi_no

    mov     rcx, rax
    call    CloseServiceHandle
    mov     rcx, rbx
    call    CloseServiceHandle
    mov     eax, 1
    jmp     @idi_ret

@idi_no:
    mov     rcx, rbx
    call    CloseServiceHandle
@idi_fail:
    xor     eax, eax
@idi_ret:
    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret
IsDriverInstalled endp

; ==============================================================================
; InstallDriver  ?  rax=1/0
;
; CreateServiceW takes 13 args:
;   rcx,rdx,r8,r9,[+20],[+28],[+30],[+38],[+40],[+48],[+50],[+58],[+60]
; Need slots at +20..+60 = 9 slots (72 bytes) beyond shadow.
; Total stack needed: 4 non-vol pushes (32) + sub 68h (104) ? rsp%16=0 ?
; (entry rsp%16=8; push 4 ? rsp%16=8; sub 68h ? rsp%16=0)
; [rsp+20h..60h] args; [rsp+68h..] = pushed non-volatiles
; ==============================================================================
PUBLIC InstallDriver
InstallDriver proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 68h

    call    ExtractDriver
    test    eax, eax
    jz      @inst_fail

    mov     r8d, SC_MANAGER_ALL
    xor     edx, edx
    xor     ecx, ecx
    call    OpenSCManagerW
    test    rax, rax
    jz      @inst_fail
    mov     rbx, rax                            ; hSCM

    mov     qword ptr [rsp+60h], 0              ; lpPassword = NULL
    mov     qword ptr [rsp+58h], 0              ; lpServiceStartName = NULL (LocalSystem)
    lea     r10, str_deps
    mov     qword ptr [rsp+50h], r10            ; lpDependencies = "FltMgr\0\0"
    mov     qword ptr [rsp+48h], 0              ; lpdwTagId = NULL
    lea     r10, str_group
    mov     qword ptr [rsp+40h], r10            ; lpLoadOrderGroup = "FSFilter Content Screener"
    lea     r10, str_drv_nt_path
    mov     qword ptr [rsp+38h], r10            ; lpBinaryPathName = \SystemRoot\...\vg.sys
    mov     dword ptr [rsp+30h], SERVICE_ERROR_NORMAL
    mov     dword ptr [rsp+28h], SERVICE_DEMAND_START  ; start on demand only
    mov     dword ptr [rsp+20h], SERVICE_KERNEL_DRIVER ; type = kernel driver
    mov     r9d, SERVICE_ALL_ACCESS             ; dwDesiredAccess
    lea     r8, str_svc_display                 ; lpDisplayName
    lea     rdx, str_svc_name                   ; lpServiceName = "clrcd"
    mov     rcx, rbx                            ; hSCManager
    call    CreateServiceW
    test    rax, rax
    jz      @inst_close_fail

    mov     rcx, rax
    call    CloseServiceHandle
    mov     rcx, rbx
    call    CloseServiceHandle

    ; HKLM\...\Services\clrcd\Instances
    mov     qword ptr [rsp+40h], 0
    lea     rax, inst_hkey1
    mov     qword ptr [rsp+38h], rax
    mov     qword ptr [rsp+30h], 0
    mov     dword ptr [rsp+28h], KEY_ALL_ACCESS
    mov     dword ptr [rsp+20h], 0
    xor     r9d, r9d
    xor     r8d, r8d
    lea     rdx, str_svc_clrcd_inst
    mov     rcx, HKEY_LOCAL_MACHINE
    call    RegCreateKeyExW
    test    eax, eax
    jnz     @inst_fail

    mov     dword ptr [rsp+28h], 12             ; sizeof L"clrcd\0"
    lea     rax, str_svc_name
    mov     qword ptr [rsp+20h], rax
    mov     r9d, REG_SZ
    xor     r8d, r8d
    lea     rdx, str_def_inst
    mov     rcx, inst_hkey1
    call    RegSetValueExW

    mov     rcx, inst_hkey1
    call    RegCloseKey

    ; HKLM\...\Services\clrcd\Instances\clrcd
    mov     qword ptr [rsp+40h], 0
    lea     rax, inst_hkey1
    mov     qword ptr [rsp+38h], rax
    mov     qword ptr [rsp+30h], 0
    mov     dword ptr [rsp+28h], KEY_ALL_ACCESS
    mov     dword ptr [rsp+20h], 0
    xor     r9d, r9d
    xor     r8d, r8d
    lea     rdx, str_svc_clrcd_inst_clrcd
    mov     rcx, HKEY_LOCAL_MACHINE
    call    RegCreateKeyExW
    test    eax, eax
    jnz     @inst_fail

    mov     dword ptr [rsp+28h], 14             ; cbData = sizeof L"389991\0"
    lea     rax, str_altitude_data
    mov     qword ptr [rsp+20h], rax            ; lpData = "389991"
    mov     r9d, REG_SZ
    xor     r8d, r8d                            ; Reserved = 0
    lea     rdx, str_altitude_val               ; "Altitude"
    mov     rcx, inst_hkey1
    call    RegSetValueExW                      ; set mini-filter altitude

    mov     dword ptr [rsp+28h], 4              ; cbData = sizeof(DWORD)
    lea     rax, inst_flags_zero
    mov     qword ptr [rsp+20h], rax            ; lpData = 0
    mov     r9d, REG_DWORD
    xor     r8d, r8d
    lea     rdx, str_flags_val                  ; "Flags"
    mov     rcx, inst_hkey1
    call    RegSetValueExW                      ; Flags = 0 (required by FltMgr)

    mov     rcx, inst_hkey1
    call    RegCloseKey

    mov     eax, 1
    jmp     @inst_ret

@inst_close_fail:
    mov     rcx, rbx
    call    CloseServiceHandle
@inst_fail:
    xor     eax, eax
@inst_ret:
    add     rsp, 68h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
InstallDriver endp

; ==============================================================================
; StartDriver  ?  rax=1/0  (ERROR_SERVICE_ALREADY_RUNNING counts as success)
; Stack: entry rsp%16=8; push rbx,rsi (+16) ? 8; sub 28h (+40) ? 0 ?
; ==============================================================================
PUBLIC StartDriver
StartDriver proc
    push    rbx
    push    rsi
    sub     rsp, 28h

    mov     r8d, SC_MANAGER_CONNECT
    xor     edx, edx
    xor     ecx, ecx
    call    OpenSCManagerW
    test    rax, rax
    jz      @start_fail
    mov     rbx, rax

    mov     r8d, SERVICE_START
    lea     rdx, str_svc_name
    mov     rcx, rbx
    call    OpenServiceW
    test    rax, rax
    jz      @start_close_scm
    mov     rsi, rax                        ; hSvc

    ; StartServiceW(hSvc, 0, NULL)
    xor     r8d, r8d
    xor     edx, edx
    mov     rcx, rsi
    call    StartServiceW
    test    eax, eax
    jnz     @start_ok

    call    GetLastError
    cmp     eax, ERROR_SERVICE_ALREADY_RUNNING
    je      @start_ok
    cmp     eax, ERROR_ALREADY_EXISTS   ; DriverEntry returned NAME_COLLISION, device still live
    jne     @start_svc_fail

@start_ok:
    mov     rcx, rsi
    call    CloseServiceHandle
    mov     rcx, rbx
    call    CloseServiceHandle
    mov     eax, 1
    jmp     @start_ret

@start_svc_fail:
    mov     rcx, rsi
    call    CloseServiceHandle
@start_close_scm:
    mov     rcx, rbx
    call    CloseServiceHandle
@start_fail:
    xor     eax, eax
@start_ret:
    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret
StartDriver endp

; ==============================================================================
; SetDriverStartType  rcx=startType(SERVICE_DEMAND_START|SERVICE_AUTO_START)
;                    ?  rax=1/0
;
; Uses ChangeServiceConfigW directly; no sc.exe shell-out.  Only the start type is
; changed, every other service field stays SERVICE_NO_CHANGE/NULL.
;
; Stack: entry rsp%16=8; push rbx,rsi,rdi (+24)?0; sub 60h (+96)?0 ?
; ChangeServiceConfigW has 11 args; stack args live at [rsp+20h]..[rsp+50h].
; ==============================================================================
PUBLIC SetDriverStartType
SetDriverStartType proc
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 60h

    mov     esi, ecx                        ; desired start type

    mov     r8d, SC_MANAGER_CONNECT
    xor     edx, edx
    xor     ecx, ecx
    call    OpenSCManagerW
    test    rax, rax
    jz      @sdst_fail
    mov     rbx, rax                        ; hSCM

    mov     r8d, SERVICE_CHANGE_CONFIG
    lea     rdx, str_svc_name
    mov     rcx, rbx
    call    OpenServiceW
    test    rax, rax
    jz      @sdst_close_scm
    mov     rdi, rax                        ; hSvc (volatile enough inside this proc)

    ; ChangeServiceConfigW(hSvc, NO_CHANGE, startType, NO_CHANGE,
    ;                      NULL, NULL, NULL, NULL, NULL, NULL, NULL)
    mov     qword ptr [rsp+50h], 0          ; lpDisplayName
    mov     qword ptr [rsp+48h], 0          ; lpPassword
    mov     qword ptr [rsp+40h], 0          ; lpServiceStartName
    mov     qword ptr [rsp+38h], 0          ; lpDependencies
    mov     qword ptr [rsp+30h], 0          ; lpdwTagId
    mov     qword ptr [rsp+28h], 0          ; lpLoadOrderGroup
    mov     qword ptr [rsp+20h], 0          ; lpBinaryPathName
    mov     r9d, SERVICE_NO_CHANGE          ; dwErrorControl
    mov     r8d, esi                        ; dwStartType
    mov     edx, SERVICE_NO_CHANGE          ; dwServiceType
    mov     rcx, rdi
    call    ChangeServiceConfigW
    mov     esi, eax                        ; save BOOL

    mov     rcx, rdi
    call    CloseServiceHandle
    mov     rcx, rbx
    call    CloseServiceHandle
    test    esi, esi
    jz      @sdst_fail
    mov     eax, 1
    jmp     @sdst_ret

@sdst_close_scm:
    mov     rcx, rbx
    call    CloseServiceHandle
@sdst_fail:
    xor     eax, eax
@sdst_ret:
    add     rsp, 60h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
SetDriverStartType endp

; ==============================================================================
; StopDriver  ?  rax=1/0
; Stack: entry rsp%16=8; push rbx,rsi (+16)?8; sub 28h (+40)?0 ?
; ==============================================================================
PUBLIC StopDriver
StopDriver proc
    push    rbx
    push    rsi
    sub     rsp, 28h

    mov     r8d, SC_MANAGER_CONNECT
    xor     edx, edx
    xor     ecx, ecx
    call    OpenSCManagerW
    test    rax, rax
    jz      @stop_fail
    mov     rbx, rax

    mov     r8d, SERVICE_STOP
    lea     rdx, str_svc_name
    mov     rcx, rbx
    call    OpenServiceW
    test    rax, rax
    jz      @stop_close_scm
    mov     rsi, rax

    ; ControlService(hSvc, SERVICE_CONTROL_STOP, &svc_status_buf)
    lea     r8, svc_status_buf
    mov     edx, SVC_CTRL_STOP
    mov     rcx, rsi
    call    ControlService

    mov     rcx, rsi
    call    CloseServiceHandle
    mov     rcx, rbx
    call    CloseServiceHandle
    mov     eax, 1
    jmp     @stop_ret

@stop_close_scm:
    mov     rcx, rbx
    call    CloseServiceHandle
@stop_fail:
    xor     eax, eax
@stop_ret:
    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret
StopDriver endp

; ==============================================================================
; UninstallDriver  ?  rax=1/0
; Stack: entry rsp%16=8; push rbx,rsi (+16)?8; sub 28h (+40)?0 ?
; ==============================================================================
PUBLIC UninstallDriver
UninstallDriver proc
    push    rbx
    push    rsi
    sub     rsp, 28h

    call    StopDriver          ; ignore result

    mov     r8d, SC_MANAGER_ALL
    xor     edx, edx
    xor     ecx, ecx
    call    OpenSCManagerW
    test    rax, rax
    jz      @uninst_fail
    mov     rbx, rax

    mov     r8d, SERVICE_DELETE_SVC
    lea     rdx, str_svc_name
    mov     rcx, rbx
    call    OpenServiceW
    test    rax, rax
    jz      @uninst_close_scm
    mov     rsi, rax

    mov     rcx, rsi
    call    DeleteService
    xchg    rax, rsi            ; rsi=DeleteService result, rax=hSvc handle
    mov     rcx, rax
    call    CloseServiceHandle
    mov     rcx, rbx
    call    CloseServiceHandle
    test    rsi, rsi
    jz      @uninst_fail
    mov     eax, 1
    jmp     @uninst_ret

@uninst_close_scm:
    mov     rcx, rbx
    call    CloseServiceHandle
@uninst_fail:
    xor     eax, eax
@uninst_ret:
    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret
UninstallDriver endp

; ==============================================================================
; DeleteDriverFile  ?  rax=1/0
;
; Deletes %SystemRoot%\System32\drivers\vg.sys after the driver service has been
; stopped/deleted.  Failure is reported to the caller but /uninstall treats it as
; best-effort because a loaded driver may remain pending until reboot.
;
; Stack: entry rsp%16=8; push rbx,rsi,rdi (+24)?0; sub 20h (+32)?0 ?
; ==============================================================================
PUBLIC DeleteDriverFile
DeleteDriverFile proc
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 20h

    mov     edx, MAX_PATH
    lea     rcx, g_tempBuf
    call    GetSystemDirectoryW
    test    eax, eax
    jz      @ddf_fail

    lea     rdi, g_tempBuf
    lea     rdi, [rdi + rax*2]              ; append at terminating NUL

    mov     word ptr [rdi +  0], '\'
    mov     word ptr [rdi +  2], 'd'
    mov     word ptr [rdi +  4], 'r'
    mov     word ptr [rdi +  6], 'i'
    mov     word ptr [rdi +  8], 'v'
    mov     word ptr [rdi + 10], 'e'
    mov     word ptr [rdi + 12], 'r'
    mov     word ptr [rdi + 14], 's'
    mov     word ptr [rdi + 16], '\'
    mov     word ptr [rdi + 18], 'v'
    mov     word ptr [rdi + 20], 'g'
    mov     word ptr [rdi + 22], '.'
    mov     word ptr [rdi + 24], 's'
    mov     word ptr [rdi + 26], 'y'
    mov     word ptr [rdi + 28], 's'
    mov     word ptr [rdi + 30], 0

    lea     rcx, g_tempBuf
    call    DeleteFileW
    test    eax, eax
    jz      @ddf_fail
    mov     eax, 1
    jmp     @ddf_ret

@ddf_fail:
    xor     eax, eax
@ddf_ret:
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DeleteDriverFile endp

end

; ==============================================================================
; Vault Guard - Driver Management and IOCTL
;
; Author: Marek Wesołowski (wesmar)
; Purpose: SCM install/start/stop/uninstall, device open/close, IOCTL wrappers.
;
; Exported (SCM):
;   InstallDriver()   → rax=1 ok / 0 fail
;   UninstallDriver() → rax=1 ok / 0 fail
;   StartDriver()     → rax=1 ok / 0 fail
;   StopDriver()      → rax=1 ok / 0 fail
;   IsDriverInstalled() → rax=1 yes / 0 no
;   EnsureDriverReady() → rax=1 ok / 0 fail (install/start/open atomically)
;
; Exported (device):
;   OpenDevice()      → rax=1 ok / 0 fail  (sets g_hDevice)
;   CloseDevice()     → void
;
; Exported (IOCTL):
;   IoctlSetActive(active:BYTE)             → rax=1/0
;   IoctlGetStatus()                        → rax=1/0  (fills g_statusResult)
;   IoctlAddPath(flags:BYTE, path:PWSTR)    → rax=1/0
;   IoctlRemovePath(path:PWSTR)             → rax=1/0
;   IoctlAddTrusted(name:PWSTR)             → rax=1/0
;   IoctlRemoveTrusted(name:PWSTR)          → rax=1/0
;   IoctlEnumPaths()                        → rax=1/0  (fills g_ioBuf)
;   IoctlEnumTrusted()                      → rax=1/0  (fills g_ioBuf)
;   IoctlClearAll()                         → rax=1/0
; ==============================================================================

option casemap:none

include consts.inc
include globals.inc

EXTRN OpenSCManagerW        :PROC
EXTRN CreateServiceW        :PROC
EXTRN OpenServiceW          :PROC
EXTRN StartServiceW         :PROC
EXTRN ControlService        :PROC
EXTRN DeleteService         :PROC
EXTRN CloseServiceHandle    :PROC
EXTRN CreateFileW           :PROC
EXTRN DeviceIoControl       :PROC
EXTRN CloseHandle           :PROC
EXTRN GetLastError          :PROC
EXTRN QueryDosDeviceW       :PROC
EXTRN ExtractDriver         :PROC
EXTRN wcslen_p              :PROC
EXTRN wcscpy_p              :PROC
EXTRN wcscat_p              :PROC
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
; DATA
; ==============================================================================
.data
    align 8

PUBLIC g_statusResult
g_statusResult  db 16 dup(0)   ; VG_STATUS
str_drive       dw 0,':',0
inst_flags_zero dd 0

.data?
    svc_status_buf  db 36 dup(?)    ; SERVICE_STATUS_PROCESS
    ioctl_bytes_ret dd ?
    inst_hkey1      dq ?

; ==============================================================================
; CODE
; ==============================================================================
.code

; ==============================================================================
; Macro: IOCTL_CALL — inline DeviceIoControl with common pattern
; Avoids repeated boilerplate. ioctl_code passed as immediate.
; Caller must have set up 8-arg-capable frame (sub 48h min after 2 pushes).
; ==============================================================================

; Helper: frame for functions that only call CloseServiceHandle/CloseHandle (2 args)
; Use: push rbx,rsi (16) + sub 28h (40) → entry(8)-16-40 aligned?
; entry rsp%16=8; push 2×8=16 → rsp%16=0 wrong direction:
; rsp starts at some value where rsp%16=8 (the call pushed return addr).
; push rbx: rsp-=8 → rsp%16=0
; push rsi: rsp-=8 → rsp%16=8
; sub 28h: rsp-=40 → rsp%16=0 ✓   (push 2 + sub 28h = correct)

; ==============================================================================
; IsDriverInstalled  →  rax=1/0
; Stack: entry rsp%16=8; push rbx,rsi (+16) → rsp%16=8; sub 28h (+40) → 0 ✓
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
; InstallDriver  →  rax=1/0
;
; CreateServiceW takes 13 args:
;   rcx,rdx,r8,r9,[+20],[+28],[+30],[+38],[+40],[+48],[+50],[+58],[+60]
; Need slots at +20..+60 = 9 slots (72 bytes) beyond shadow.
; Total stack needed: 4 non-vol pushes (32) + sub 68h (104) → rsp%16=0 ✓
; (entry rsp%16=8; push 4 → rsp%16=8; sub 68h → rsp%16=0)
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
; StartDriver  →  rax=1/0  (ERROR_SERVICE_ALREADY_RUNNING counts as success)
; Stack: entry rsp%16=8; push rbx,rsi (+16) → 8; sub 28h (+40) → 0 ✓
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
; StopDriver  →  rax=1/0
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 28h (+40)→0 ✓
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
; UninstallDriver  →  rax=1/0
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 28h (+40)→0 ✓
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
; OpenDevice  →  rax=1/0  (sets g_hDevice)
;
; CreateFileW takes 7 args: rcx,rdx,r8,r9,[+20],[+28],[+30]
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 38h (+56)→0 ✓
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
; CloseDevice  →  void
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 28h (+40)→0 ✓
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

    ; StartDriver failed for reason other than 183/1056 — last-ditch open attempt.
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

; ==============================================================================
; _Ioctl8 — internal: DeviceIoControl with 8 args, no in-buffer output buffer only
;   rcx = ioctl code
;   rdx = outBuf ptr (or NULL)
;   r8  = outBuf size
; → rax=1/0
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 48h (+72)→0 ✓
; DeviceIoControl: rcx=hDev, rdx=code, r8=pIn, r9=szIn, [+20]=pOut, [+28]=szOut, [+30]=pBytesRet, [+38]=pOv
; ==============================================================================
_Ioctl8 proc
    push    rbx
    push    rsi
    sub     rsp, 48h

    mov     rbx, rcx            ; ioctl
    mov     rsi, rdx            ; outBuf

    mov     qword ptr [rsp+38h], 0              ; lpOverlapped
    lea     r10, [rsp+34h]
    mov     qword ptr [rsp+30h], r10            ; lpBytesReturned
    mov     r9d, r8d                            ; nOutBufferSize → move to [+28] below
    ; Wait: r8 = outBufSize (3rd arg to _Ioctl8), but DeviceIoControl:
    ;   r8 = lpInBuffer, r9 = nInBufferSize, [+20] = lpOutBuffer, [+28] = nOutBufSize
    ; For no-input calls:
    mov     dword ptr [rsp+28h], r8d            ; nOutBufferSize
    mov     qword ptr [rsp+20h], rsi            ; lpOutBuffer
    xor     r9d, r9d                            ; nInBufferSize = 0
    xor     r8d, r8d                            ; lpInBuffer = NULL
    mov     edx, ebx                            ; dwIoControlCode
    mov     rcx, g_hDevice                      ; hDevice
    call    DeviceIoControl
    test    eax, eax
    setnz   al
    movzx   eax, al

    add     rsp, 48h
    pop     rsi
    pop     rbx
    ret
_Ioctl8 endp

; ==============================================================================
; IoctlSetActive  rcx=active(DWORD)  →  rax=1/0
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 48h (+72)→0 ✓
; ==============================================================================
PUBLIC IoctlSetActive
IoctlSetActive proc
    push    rbx
    push    rsi
    sub     rsp, 48h

    ; Original client sends a 4-byte active flag.
    and     ecx, 0FFh                           ; clamp to byte range (0 or 1)
    mov     dword ptr [rsp+40h], ecx            ; store flag on stack

    mov     qword ptr [rsp+38h], 0              ; lpOverlapped = NULL
    lea     r10, [rsp+3Ch]
    mov     qword ptr [rsp+30h], r10            ; lpBytesReturned (scratch)
    mov     dword ptr [rsp+28h], 0              ; nOutBufSize = 0
    mov     qword ptr [rsp+20h], 0              ; lpOutBuf = NULL (write-only IOCTL)
    mov     r9d, 4                              ; nInBufSize = sizeof(DWORD)
    lea     r8, [rsp+40h]                       ; lpInBuf = &active flag
    mov     edx, IOCTL_VG_SET_ACTIVE
    mov     rcx, g_hDevice
    call    DeviceIoControl
    test    eax, eax
    setnz   al
    movzx   eax, al

    add     rsp, 48h
    pop     rsi
    pop     rbx
    ret
IoctlSetActive endp

; ==============================================================================
; IoctlGetStatus  →  rax=1/0  (fills g_statusResult, 16 bytes)
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 48h (+72)→0 ✓
; ==============================================================================
PUBLIC IoctlGetStatus
IoctlGetStatus proc
    push    rbx
    push    rsi
    sub     rsp, 48h

    mov     qword ptr [rsp+38h], 0              ; lpOverlapped = NULL
    lea     r10, [rsp+3Ch]
    mov     qword ptr [rsp+30h], r10            ; lpBytesReturned
    mov     dword ptr [rsp+28h], VG_STATUS_SIZE ; nOutBufSize
    lea     r10, g_statusResult
    mov     qword ptr [rsp+20h], r10            ; lpOutBuf = g_statusResult
    xor     r9d, r9d                            ; nInBufSize = 0
    xor     r8d, r8d                            ; lpInBuf = NULL
    mov     edx, IOCTL_VG_GET_STATUS
    mov     rcx, g_hDevice
    call    DeviceIoControl
    test    eax, eax
    setnz   al
    movzx   eax, al

    add     rsp, 48h
    pop     rsi
    pop     rbx
    ret
IoctlGetStatus endp

; ==============================================================================
; IoctlAddPath  rcx=flags(BYTE)  rdx=path(PWSTR)  →  rax=1/0
; Original driver protocol:
;   DWORD flags
;   WCHAR ntPath[]  e.g. \Device\HarddiskVolume3\dir
; Stack: entry rsp%16=8; push rbx,rsi,rdi,r12 (+32)→8; sub 48h (+72)→0 ✓
; ==============================================================================
PUBLIC IoctlAddPath
IoctlAddPath proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 48h

    movzx   ebx, cl             ; flags (VG_FLAG_* bitmask)
    mov     rsi, rdx            ; DOS path e.g. "C:\dir"

    ; Build L"C:" drive query string from first WCHAR of DOS path.
    movzx   eax, word ptr [rsi]  ; drive letter
    mov     word ptr [str_drive], ax

    ; g_ioBuf layout: [0..3]=DWORD flags, [4..]=NT device path (e.g. \Device\HarddiskVolume3\dir)
    lea     rdi, g_ioBuf
    mov     dword ptr [rdi], ebx                ; store protection flags

    mov     r8d, 520                            ; output buffer size in WCHARs
    lea     rdx, [rdi + 4]                      ; output: NT device prefix
    lea     rcx, str_drive                      ; input: "C:"
    call    QueryDosDeviceW                     ; resolve "C:" → "\Device\HarddiskVolume3"
    test    eax, eax
    jz      @iap_fail                           ; drive not found

    ; Append the suffix that comes after "C:" in the DOS path.
    lea     rdx, [rsi + 4]                      ; DOS path after "C:" (e.g. "\dir")
    lea     rcx, [rdi + 4]                      ; append to NT prefix
    call    wcscat_p

    lea     rcx, [rdi + 4]
    call    wcslen_p
    lea     rbx, [rax*2 + 6]     ; total input size: DWORD flags + path WCHARs + null

    mov     qword ptr [rsp+38h], 0
    lea     r10, [rsp+3Ch]
    mov     qword ptr [rsp+30h], r10
    mov     dword ptr [rsp+28h], 0
    mov     qword ptr [rsp+20h], 0
    mov     r9d, VG_ORIG_PATH_INPUT_SIZE        ; original sends the fixed record size
    lea     r8, g_ioBuf
    mov     edx, IOCTL_VG_ADD_PATH
    mov     rcx, g_hDevice
    call    DeviceIoControl
    test    eax, eax
    setnz   al
    movzx   eax, al
    jmp     @iap_ret

@iap_fail:
    xor     eax, eax
@iap_ret:
    add     rsp, 48h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
IoctlAddPath endp

; ==============================================================================
; IoctlRemovePath  rcx=path(PWSTR)  →  rax=1/0
; Stack: entry rsp%16=8; push rbx,rsi,rdi,r12 (+32)→8; sub 48h (+72)→0 ✓
; ==============================================================================
PUBLIC IoctlRemovePath
IoctlRemovePath proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 48h

    mov     rsi, rcx            ; DOS path

    ; Build drive string "C:" from path[0].
    movzx   eax, word ptr [rsi]
    mov     word ptr [str_drive], ax

    ; Match IoctlAddPath/original format: DWORD reserved + NT device path.
    lea     rdi, g_ioBuf
    mov     dword ptr [rdi], 0

    mov     r8d, 520
    lea     rdx, [rdi + 4]
    lea     rcx, str_drive
    call    QueryDosDeviceW
    test    eax, eax
    jz      @irp_fail

    lea     rdx, [rsi + 4]
    lea     rcx, [rdi + 4]
    call    wcscat_p

    lea     rcx, [rdi + 4]
    call    wcslen_p
    lea     rbx, [rax*2 + 6]     ; DWORD reserved + path bytes + null WCHAR

    mov     qword ptr [rsp+38h], 0
    lea     r10, [rsp+3Ch]
    mov     qword ptr [rsp+30h], r10
    mov     dword ptr [rsp+28h], 0
    mov     qword ptr [rsp+20h], 0
    mov     r9d, VG_ORIG_PATH_INPUT_SIZE
    lea     r8, g_ioBuf
    mov     edx, IOCTL_VG_REMOVE_PATH
    mov     rcx, g_hDevice
    call    DeviceIoControl
    test    eax, eax
    setnz   al
    movzx   eax, al
    jmp     @irp_ret

@irp_fail:
    xor     eax, eax
@irp_ret:
    add     rsp, 48h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
IoctlRemovePath endp

; ==============================================================================
; IoctlAddTrusted  rcx=name(PWSTR)  →  rax=1/0
; Original trusted record is 0xD94 bytes. Process name starts at +4.
; Stack: entry rsp%16=8; push rbx,rsi,rdi,r12 (+32)→8; sub 48h (+72)→0 ✓
; ==============================================================================
PUBLIC IoctlAddTrusted
IoctlAddTrusted proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 48h

    mov     rsi, rcx

    ; Clear one fixed trusted record in g_ioBuf.
    lea     rdi, g_ioBuf
    xor     eax, eax
    mov     ecx, VG_TRUSTED_RECORD_SIZE / 8
    rep stosq
    mov     ecx, (VG_TRUSTED_RECORD_SIZE MOD 8) / 4
    rep stosd

    lea     rcx, [g_ioBuf + VG_TRUSTED_RECORD_NAME]
    mov     rdx, rsi
    call    wcscpy_p

    mov     qword ptr [rsp+38h], 0
    lea     r10, [rsp+3Ch]
    mov     qword ptr [rsp+30h], r10
    mov     dword ptr [rsp+28h], 0
    mov     qword ptr [rsp+20h], 0
    mov     r9d, VG_TRUSTED_RECORD_SIZE
    lea     r8, g_ioBuf
    mov     edx, IOCTL_VG_ADD_TRUSTED
    mov     rcx, g_hDevice
    call    DeviceIoControl
    test    eax, eax
    setnz   al
    movzx   eax, al

    add     rsp, 48h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
IoctlAddTrusted endp

; ==============================================================================
; IoctlRemoveTrusted  rcx=name(PWSTR)  →  rax=1/0
; The driver IOCTL replaces the whole trusted list. A zero-size input clears it;
; callers should reload persisted trusted entries afterward if needed.
; ==============================================================================
PUBLIC IoctlRemoveTrusted
IoctlRemoveTrusted proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 48h

    mov     qword ptr [rsp+38h], 0              ; lpOverlapped = NULL
    lea     r10, [rsp+3Ch]
    mov     qword ptr [rsp+30h], r10            ; lpBytesReturned
    mov     dword ptr [rsp+28h], 0              ; nOutBufSize = 0
    mov     qword ptr [rsp+20h], 0              ; lpOutBuf = NULL
    xor     r9d, r9d                            ; nInBufSize = 0 (driver clears list)
    lea     r8, g_ioBuf                         ; lpInBuf (unused, but non-NULL)
    mov     edx, IOCTL_VG_REMOVE_TRUSTED        ; zero-size input = clear trusted list
    mov     rcx, g_hDevice
    call    DeviceIoControl
    test    eax, eax
    setnz   al
    movzx   eax, al

    add     rsp, 48h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
IoctlRemoveTrusted endp

; ==============================================================================
; IoctlEnumPaths  →  rax=1/0  (fills g_ioBuf with VG_ENUM_REPLY + entries)
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 48h (+72)→0 ✓
; ==============================================================================
PUBLIC IoctlEnumPaths
IoctlEnumPaths proc
    push    rbx
    push    rsi
    sub     rsp, 48h

    mov     qword ptr [rsp+38h], 0              ; lpOverlapped = NULL
    lea     r10, [rsp+3Ch]
    mov     qword ptr [rsp+30h], r10            ; lpBytesReturned
    mov     dword ptr [rsp+28h], VG_IOCTL_BUF_SIZE  ; nOutBufSize = 64 KB
    lea     r10, g_ioBuf
    mov     qword ptr [rsp+20h], r10            ; lpOutBuf = g_ioBuf
    xor     r9d, r9d                            ; nInBufSize = 0
    xor     r8d, r8d                            ; lpInBuf = NULL
    mov     edx, IOCTL_VG_ENUM_PATHS            ; returns VG_ENUM_REPLY + entries
    mov     rcx, g_hDevice
    call    DeviceIoControl
    test    eax, eax
    setnz   al
    movzx   eax, al

    add     rsp, 48h
    pop     rsi
    pop     rbx
    ret
IoctlEnumPaths endp

; ==============================================================================
; IoctlEnumTrusted  →  rax=1/0
; ==============================================================================
PUBLIC IoctlEnumTrusted
IoctlEnumTrusted proc
    push    rbx
    push    rsi
    sub     rsp, 48h

    mov     qword ptr [rsp+38h], 0
    lea     r10, [rsp+3Ch]
    mov     qword ptr [rsp+30h], r10
    mov     dword ptr [rsp+28h], VG_IOCTL_BUF_SIZE
    lea     r10, g_ioBuf
    mov     qword ptr [rsp+20h], r10
    xor     r9d, r9d
    xor     r8d, r8d
    mov     edx, IOCTL_VG_ENUM_TRUSTED
    mov     rcx, g_hDevice
    call    DeviceIoControl
    test    eax, eax
    setnz   al
    movzx   eax, al

    add     rsp, 48h
    pop     rsi
    pop     rbx
    ret
IoctlEnumTrusted endp

; ==============================================================================
; IoctlClearAll  →  rax=1/0
; ==============================================================================
PUBLIC IoctlClearAll
IoctlClearAll proc
    push    rbx
    push    rsi
    sub     rsp, 48h

    mov     qword ptr [rsp+38h], 0              ; lpOverlapped = NULL
    lea     r10, [rsp+3Ch]
    mov     qword ptr [rsp+30h], r10            ; lpBytesReturned
    mov     dword ptr [rsp+28h], 0              ; nOutBufSize = 0
    mov     qword ptr [rsp+20h], 0              ; lpOutBuf = NULL
    xor     r9d, r9d                            ; nInBufSize = 0
    xor     r8d, r8d                            ; lpInBuf = NULL
    mov     edx, IOCTL_VG_CLEAR_ALL             ; removes all paths + trusted entries
    mov     rcx, g_hDevice
    call    DeviceIoControl
    test    eax, eax
    setnz   al
    movzx   eax, al

    add     rsp, 48h
    pop     rsi
    pop     rbx
    ret
IoctlClearAll endp

end

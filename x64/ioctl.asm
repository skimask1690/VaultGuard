; ==============================================================================
; Vault Guard - Driver IOCTL Layer
;
; Author: Marek Wesolowski (wesmar)
; Purpose: DeviceIoControl wrappers and DOS-path to NT-path marshalling.
; ==============================================================================

option casemap:none

include consts.inc
include globals.inc
include driver_consts.inc

EXTRN DeviceIoControl       :PROC
EXTRN QueryDosDeviceW       :PROC
EXTRN wcslen_p              :PROC
EXTRN wcscpy_p              :PROC
EXTRN wcscat_p              :PROC

.data?
    ioctl_bytes_ret dd ?

.code
; _Ioctl8 ? internal: DeviceIoControl with 8 args, no in-buffer output buffer only
;   rcx = ioctl code
;   rdx = outBuf ptr (or NULL)
;   r8  = outBuf size
; ? rax=1/0
; Stack: entry rsp%16=8; push rbx,rsi (+16)?8; sub 48h (+72)?0 ?
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
    mov     r9d, r8d                            ; nOutBufferSize ? move to [+28] below
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
; IoctlSetActive  rcx=active(DWORD)  ?  rax=1/0
; Stack: entry rsp%16=8; push rbx,rsi (+16)?8; sub 48h (+72)?0 ?
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
; IoctlGetStatus  ?  rax=1/0  (fills g_statusResult, 16 bytes)
; Stack: entry rsp%16=8; push rbx,rsi (+16)?8; sub 48h (+72)?0 ?
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
; IoctlAddPath  rcx=flags(BYTE)  rdx=path(PWSTR)  ?  rax=1/0
; Original driver protocol:
;   DWORD flags
;   WCHAR ntPath[]  e.g. \Device\HarddiskVolume3\dir
; Stack: entry rsp%16=8; push rbx,rsi,rdi,r12 (+32)?8; sub 48h (+72)?0 ?
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
    call    QueryDosDeviceW                     ; resolve "C:" ? "\Device\HarddiskVolume3"
    test    eax, eax
    jz      @iap_fail                           ; drive not found

    ; Append the suffix that comes after "C:" in the DOS path.
    lea     rdx, [rsi + 4]                      ; DOS path after "C:" (e.g. "\dir")
    lea     rcx, [rdi + 4]                      ; append to NT prefix
    call    wcscat_p

    ; Strip trailing backslash ? driver prefix match requires path[len] == '\' or 0, not stored '\'
    lea     rcx, [rdi + 4]
    call    wcslen_p
    test    eax, eax
    jz      @iap_do_size
    dec     eax
    cmp     word ptr [rdi + 4 + rax*2], '\'
    jne     @iap_do_size
    mov     word ptr [rdi + 4 + rax*2], 0
@iap_do_size:
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
; IoctlRemovePath  rcx=path(PWSTR)  ?  rax=1/0
; Stack: entry rsp%16=8; push rbx,rsi,rdi,r12 (+32)?8; sub 48h (+72)?0 ?
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
    test    eax, eax
    jz      @irp_do_size
    dec     eax
    cmp     word ptr [rdi + 4 + rax*2], '\'
    jne     @irp_do_size
    mov     word ptr [rdi + 4 + rax*2], 0
@irp_do_size:
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
; IoctlAddTrusted  rcx=name(PWSTR)  ?  rax=1/0
; Original trusted record is 0xD94 bytes. Process name starts at +4.
; Stack: entry rsp%16=8; push rbx,rsi,rdi,r12 (+32)?8; sub 48h (+72)?0 ?
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
; IoctlRemoveTrusted  rcx=name(PWSTR)  ?  rax=1/0
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
; IoctlEnumPaths  ?  rax=1/0  (fills g_ioBuf with VG_ENUM_REPLY + entries)
; Stack: entry rsp%16=8; push rbx,rsi (+16)?8; sub 48h (+72)?0 ?
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
; IoctlEnumTrusted  ?  rax=1/0
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
; IoctlClearAll  ?  rax=1/0
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

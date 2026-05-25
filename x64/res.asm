; ==============================================================================
; Vault Guard - Driver Resource Extraction
;
; Author: Marek Wesołowski (wesmar)
; Purpose: Extract embedded icon+CAB payload (RCDATA IDR_DRIVER) to
;          %SystemRoot%\system32\drivers\vg.sys
;
; Exported:
;   GetDriverPath() → rax = ptr to g_driverPath (static wide buf)
;   ExtractDriver() → rax = 1 success / 0 fail
; ==============================================================================

option casemap:none

include consts.inc
include globals.inc

EXTRN FindResourceW                  :PROC
EXTRN LoadResource                   :PROC
EXTRN LockResource                   :PROC
EXTRN SizeofResource                 :PROC
EXTRN GetSystemWindowsDirectoryW     :PROC
EXTRN CreateFileW                    :PROC
EXTRN WriteFile                      :PROC
EXTRN CloseHandle                    :PROC
EXTRN GetProcessHeap                 :PROC
EXTRN HeapAlloc                      :PROC
EXTRN HeapFree                       :PROC
EXTRN FDICreate                      :PROC
EXTRN FDICopy                        :PROC
EXTRN FDIDestroy                     :PROC

EXTRN wcscat_p                       :PROC

; ==============================================================================
; CONSTANT STRINGS
; ==============================================================================
.const

str_drv_rel dw '\','s','y','s','t','e','m','3','2','\','d','r','i','v','e','r','s','\','v','g','.','s','y','s',0
ansi_cab    db "memory.cab",0
ansi_path   db 0

; ==============================================================================
; DATA
; ==============================================================================
.data
    align 4
    dd_bytes_written dd 0
    align 8
    g_fdiCabPtr     dq 0
    g_fdiCabOff     dq 0
    g_fdiCabEnd     dq 0
    g_fdiOutPtr     dq 0
    g_fdiOutUsed    dq 0

.data?

PUBLIC g_driverPath
g_driverPath    dw 280 dup(?)

; ==============================================================================
; CODE
; ==============================================================================
.code

; ==============================================================================
; FDI callbacks: read CAB bytes from memory, collect extracted file in heap buffer.
; ==============================================================================
fdi_alloc proc
    sub     rsp, 28h
    mov     r10, rcx
    call    GetProcessHeap
    mov     r8, r10
    xor     edx, edx
    mov     rcx, rax
    call    HeapAlloc
    add     rsp, 28h
    ret
fdi_alloc endp

fdi_free proc
    sub     rsp, 28h
    mov     r10, rcx
    call    GetProcessHeap
    mov     r8, r10
    xor     edx, edx
    mov     rcx, rax
    call    HeapFree
    add     rsp, 28h
    ret
fdi_free endp

fdi_open proc
    mov     eax, 1
    ret
fdi_open endp

fdi_close proc
    xor     eax, eax
    ret
fdi_close endp

fdi_seek proc
    movsxd  rax, edx
    cmp     r8d, SEEK_SET_VAL
    je      @set
    cmp     r8d, SEEK_CUR_VAL
    je      @cur
    add     rax, g_fdiCabEnd
    jmp     @store
@set:
    jmp     @store
@cur:
    add     rax, g_fdiCabOff
@store:
    mov     g_fdiCabOff, rax
    ret
fdi_seek endp

fdi_read proc
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 20h

    mov     ebx, r8d
    mov     rax, g_fdiCabEnd
    sub     rax, g_fdiCabOff
    cmp     rbx, rax
    jbe     @count_ok
    mov     rbx, rax
@count_ok:
    test    rbx, rbx
    jz      @done

    mov     rdi, rdx
    mov     rsi, g_fdiCabPtr
    add     rsi, g_fdiCabOff
    mov     rcx, rbx
    rep     movsb
    add     g_fdiCabOff, rbx

@done:
    mov     eax, ebx
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
fdi_read endp

fdi_write proc
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 20h

    mov     ebx, r8d
    test    ebx, ebx
    jz      @done

    mov     rdi, g_fdiOutPtr
    add     rdi, g_fdiOutUsed
    mov     rsi, rdx
    mov     rcx, rbx
    rep     movsb
    add     g_fdiOutUsed, rbx

@done:
    mov     eax, ebx
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
fdi_write endp

fdi_notify proc
    cmp     ecx, fdintCOPY_FILE
    je      @copy
    cmp     ecx, fdintCLOSE_FILE_INFO
    je      @close
    xor     eax, eax
    ret
@copy:
    mov     eax, 1
    ret
@close:
    mov     eax, 1
    ret
fdi_notify endp

; ==============================================================================
; DecompressDriverResource -> EAX=1/0, g_fdiOutPtr/g_fdiOutUsed on success.
; ==============================================================================
DecompressDriverResource proc
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 70h

    ; FindResourceW(NULL, IDR_DRIVER, RT_RCDATA)
    mov     r8d, RT_RCDATA
    mov     edx, IDR_DRIVER
    xor     ecx, ecx
    call    FindResourceW
    test    rax, rax
    jz      @fail
    mov     rsi, rax

    mov     rdx, rsi
    xor     ecx, ecx
    call    SizeofResource
    cmp     eax, ICON_SIZE + 4
    jbe     @fail
    mov     rdi, rax

    mov     rdx, rsi
    xor     ecx, ecx
    call    LoadResource
    test    rax, rax
    jz      @fail

    mov     rcx, rax
    call    LockResource
    test    rax, rax
    jz      @fail

    lea     r10, [rax + ICON_SIZE]
    mov     g_fdiCabPtr, r10
    mov     g_fdiCabOff, 0
    mov     r10, rdi
    sub     r10, ICON_SIZE
    mov     g_fdiCabEnd, r10

    call    GetProcessHeap
    mov     r8, FDI_OUT_BUFSIZE
    xor     edx, edx
    mov     rcx, rax
    call    HeapAlloc
    test    rax, rax
    jz      @fail
    mov     g_fdiOutPtr, rax
    mov     g_fdiOutUsed, 0

    ; zero ERF at [rsp+60h]
    xor     eax, eax
    mov     qword ptr [rsp+60h], rax
    mov     dword ptr [rsp+68h], eax

    lea     r10, fdi_write
    mov     qword ptr [rsp+20h], r10
    lea     r10, fdi_close
    mov     qword ptr [rsp+28h], r10
    lea     r10, fdi_seek
    mov     qword ptr [rsp+30h], r10
    xor     eax, eax
    mov     qword ptr [rsp+38h], rax
    lea     rax, [rsp+60h]
    mov     qword ptr [rsp+40h], rax
    lea     r9, fdi_read
    lea     r8, fdi_open
    lea     rdx, fdi_free
    lea     rcx, fdi_alloc
    call    FDICreate
    test    rax, rax
    jz      @failbuf
    mov     rbx, rax

    lea     r10, fdi_notify
    mov     qword ptr [rsp+20h], r10
    xor     eax, eax
    mov     qword ptr [rsp+28h], rax
    mov     qword ptr [rsp+30h], rax
    xor     r9d, r9d
    lea     r8, ansi_path
    lea     rdx, ansi_cab
    mov     rcx, rbx
    call    FDICopy
    mov     rdi, rax

    mov     rcx, rbx
    call    FDIDestroy

    test    rdi, rdi
    jz      @failbuf
    cmp     g_fdiOutUsed, 0
    je      @failbuf
    mov     eax, 1
    jmp     @ret

@failbuf:
    call    GetProcessHeap
    mov     r8, g_fdiOutPtr
    xor     edx, edx
    mov     rcx, rax
    call    HeapFree
    mov     g_fdiOutPtr, 0
    mov     g_fdiOutUsed, 0
@fail:
    xor     eax, eax
@ret:
    add     rsp, 70h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DecompressDriverResource endp

; ==============================================================================
; GetDriverPath  →  rax = ptr to g_driverPath
; Stack: entry rsp%16=8; sub 28h → rsp%16=0 ✓
; ==============================================================================
PUBLIC GetDriverPath
GetDriverPath proc
    sub     rsp, 28h

    mov     edx, MAX_PATH
    lea     rcx, g_driverPath
    call    GetSystemWindowsDirectoryW

    lea     rdx, str_drv_rel
    lea     rcx, g_driverPath
    call    wcscat_p

    lea     rax, g_driverPath
    add     rsp, 28h
    ret
GetDriverPath endp

; ==============================================================================
; ExtractDriver  →  rax = 1 success / 0 fail
;
; Register map (all non-volatile, saved/restored):
;   rbx = pData (after CAB decompression)
;   rdi = decompressed size in bytes
;   r12 = hFile
;
; Stack: entry rsp%16=8; push rbx,rsi,rdi,r12 (32) → rsp%16=8;
;        sub 38h (56) → rsp%16=0 ✓
; [rsp+20h..2Fh] shadow space
; [rsp+30h]      5th arg slot (hTemplateFile for CreateFileW)
; ==============================================================================
PUBLIC ExtractDriver
ExtractDriver proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 38h

    call    DecompressDriverResource
    test    eax, eax
    jz      @ed_fail
    mov     rbx, g_fdiOutPtr                ; rbx = decompressed driver data
    mov     rdi, g_fdiOutUsed               ; rdi = decompressed size

    ; Build driver path
    call    GetDriverPath

    ; CreateFileW(g_driverPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
    ;             FILE_ATTRIBUTE_NORMAL, NULL)
    mov     qword ptr [rsp+30h], 0          ; hTemplateFile = NULL
    mov     dword ptr [rsp+28h], FILE_ATTRIBUTE_NORMAL
    mov     dword ptr [rsp+20h], CREATE_ALWAYS
    xor     r9d, r9d                        ; lpSecurityAttributes = NULL
    xor     r8d, r8d                        ; dwShareMode = 0
    mov     edx, GENERIC_WRITE
    lea     rcx, g_driverPath
    call    CreateFileW
    cmp     rax, INVALID_HANDLE_VALUE
    je      @ed_fail
    mov     r12, rax                        ; r12 = hFile

    ; WriteFile(hFile, pData, size, &dd_bytes_written, NULL)
    mov     qword ptr [rsp+20h], 0          ; lpOverlapped = NULL
    lea     r9, dd_bytes_written            ; lpNumberOfBytesWritten
    mov     r8d, edi                        ; nNumberOfBytesToWrite
    mov     rdx, rbx                        ; lpBuffer
    mov     rcx, r12                        ; hFile
    call    WriteFile
    mov     rsi, rax                        ; save WriteFile result

    ; CloseHandle(hFile) — always close regardless of write result
    mov     rcx, r12
    call    CloseHandle

    test    rsi, rsi                        ; WriteFile returned 0 = fail
    jz      @ed_fail

    call    GetProcessHeap
    mov     r8, g_fdiOutPtr
    xor     edx, edx
    mov     rcx, rax
    call    HeapFree
    mov     g_fdiOutPtr, 0
    mov     g_fdiOutUsed, 0

    mov     eax, 1
    jmp     @ed_ret

@ed_fail:
    cmp     g_fdiOutPtr, 0
    je      @ed_fail_no_free
    call    GetProcessHeap
    mov     r8, g_fdiOutPtr
    xor     edx, edx
    mov     rcx, rax
    call    HeapFree
    mov     g_fdiOutPtr, 0
    mov     g_fdiOutUsed, 0
@ed_fail_no_free:
    xor     eax, eax

@ed_ret:
    add     rsp, 38h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
ExtractDriver endp

end

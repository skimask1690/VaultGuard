; ==============================================================================
; Vault Guard - Export / Enumeration
;
; Author: Marek Wesołowski (wesmar)
; Purpose: CSV export of protected folders and trusted apps.
;
; Exported:
;   _CliEnumItems(rcx=pszOutFile)    → calls ExitProcess
;   _CliEnumTrusted(rcx=pszOutFile)  → calls ExitProcess
; ==============================================================================

option casemap:none

include consts.inc
include globals.inc

EXTRN CreateFileW           :PROC
EXTRN WriteFile             :PROC
EXTRN CloseHandle           :PROC
EXTRN RegOpenKeyExW         :PROC
EXTRN RegEnumValueW         :PROC
EXTRN RegCloseKey           :PROC

EXTRN EnsureDriverReady     :PROC
EXTRN CloseDevice           :PROC
EXTRN IoctlEnumTrusted      :PROC

EXTRN wcslen_p              :PROC
EXTRN WideWriteLn           :PROC
EXTRN _CliFinish            :PROC

; ==============================================================================
; CONSTANT DATA
; ==============================================================================
.const

str_key_paths_cli   dw 'S','o','f','t','w','a','r','e','\','V','G','\','P','a','t','h','s',0
str_key_trusted_cli dw 'S','o','f','t','w','a','r','e','\','V','G','\','T','r','u','s','t','e','d',0

w_bom               dw 0FEFFh
w_comma             dw ','
w_crlf              dw 13,10
w_one               dw '1'
w_zero              dw '0'

str_csv_paths_hdr   dw 'P','a','t','h',',','H','i','d','d','e','n',','
                    dw 'L','o','c','k','e','d',',','R','e','a','d','O','n','l','y',','
                    dw 'N','o','E','x','e','c',13,10,0

str_csv_trust_hdr   dw 'A','p','p','l','i','c','a','t','i','o','n',13,10,0

msg_ok_export       dw 'E','x','p','o','r','t',' ','c','o','m','p','l','e','t','e','.',0
msg_err_file        dw 'E','r','r','o','r',':',' ','C','a','n','n','o','t',' ','c','r','e','a','t','e',' ','o','u','t','p','u','t',' ','f','i','l','e','.',0
msg_err_nodrv       dw 'E','r','r','o','r',':',' ','D','r','i','v','e','r',' ','n','o','t',' ','r','u','n','n','i','n','g','.',0
msg_err_ioctl       dw 'E','r','r','o','r',':',' ','D','r','i','v','e','r',' ','I','O','C','T','L',' ','f','a','i','l','e','d','.',0

; ==============================================================================
; MUTABLE DATA
; ==============================================================================
.data
    align 4
    dw_written          dd 0
    cli_reg_namelen     dd 0
    cli_reg_datalen     dd 0
    cli_reg_type        dd 0
    cli_reg_flags       dd 0
    align 8
    cli_reg_hkey        dq 0
    cli_reg_name        dw 520 dup(0)

; ==============================================================================
; CODE
; ==============================================================================
.code

; ==============================================================================
; _WriteBytes  rcx=hFile  rdx=pBuf  r8=nBytes
; Stack: sub 28h; entry rsp%16=8; 8+40=48; 48%16=0 ✓
; ==============================================================================
_WriteBytes proc
    sub     rsp, 28h
    mov     qword ptr [rsp+20h], 0
    lea     r9, dw_written
    call    WriteFile
    add     rsp, 28h
    ret
_WriteBytes endp

; ==============================================================================
; _WriteWStr  rcx=hFile  rdx=pWStr
; Stack: push rbx,rsi (+16); sub 28h (+40); total 56; 8+56=64; 64%16=0 ✓
; ==============================================================================
_WriteWStr proc
    push    rbx
    push    rsi
    sub     rsp, 28h

    mov     rbx, rcx
    mov     rsi, rdx

    mov     rcx, rsi
    call    wcslen_p
    test    eax, eax
    jz      @wws_ret
    shl     eax, 1
    mov     r8d, eax
    mov     rdx, rsi
    mov     rcx, rbx
    call    _WriteBytes

@wws_ret:
    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret
_WriteWStr endp

; ==============================================================================
; _CliEnumItems  rcx=pszOutFile  → calls ExitProcess
; Stack: push rbx,rsi,rdi,r12,r13,r14 (+48); sub 48h (+72); 8+120=128; 128%16=0 ✓
; ==============================================================================
PUBLIC _CliEnumItems
_CliEnumItems proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    sub     rsp, 48h

    mov     r14, rcx            ; save output filename

@cei_create_file:
    mov     qword ptr [rsp+30h], 0
    mov     dword ptr [rsp+28h], FILE_ATTRIBUTE_NORMAL
    mov     dword ptr [rsp+20h], CREATE_ALWAYS
    xor     r9d, r9d
    xor     r8d, r8d
    mov     edx, GENERIC_WRITE
    mov     rcx, r14
    call    CreateFileW
    cmp     rax, INVALID_HANDLE_VALUE
    je      @cei_file_err
    mov     rbx, rax            ; hFile

    mov     r8d, 2
    lea     rdx, w_bom
    mov     rcx, rbx
    call    _WriteBytes

    lea     rdx, str_csv_paths_hdr
    mov     rcx, rbx
    call    _WriteWStr

    ; Export from registry — authoritative persisted state.
    lea     rax, cli_reg_hkey
    mov     qword ptr [rsp+20h], rax
    mov     r9d, KEY_READ
    xor     r8d, r8d
    lea     rdx, str_key_paths_cli
    mov     rcx, HKEY_CURRENT_USER
    call    RegOpenKeyExW
    test    eax, eax
    jnz     @cei_done

    xor     r13d, r13d

@cei_loop:
    mov     cli_reg_namelen, 520
    mov     cli_reg_datalen, 4
    lea     rax, cli_reg_datalen
    mov     qword ptr [rsp+38h], rax
    lea     rax, cli_reg_flags
    mov     qword ptr [rsp+30h], rax
    lea     rax, cli_reg_type
    mov     qword ptr [rsp+28h], rax
    mov     qword ptr [rsp+20h], 0
    lea     r9, cli_reg_namelen
    lea     r8, cli_reg_name
    mov     edx, r13d
    mov     rcx, cli_reg_hkey
    call    RegEnumValueW
    cmp     eax, ERROR_NO_MORE_ITEMS
    je      @cei_close_reg
    test    eax, eax
    jnz     @cei_next

    mov     edi, cli_reg_flags
    and     edi, 0Fh

    lea     rsi, cli_reg_name
    mov     rcx, rsi
    call    wcslen_p
    test    eax, eax
    jz      @cei_next
    mov     r12d, eax
    shl     r12d, 1

    mov     rdx, rsi
    mov     r8d, r12d
    mov     rcx, rbx
    call    _WriteBytes

    mov     r8d, 2
    lea     rdx, w_comma
    mov     rcx, rbx
    call    _WriteBytes

    ; Hidden
    test    edi, VG_FLAG_HIDDEN
    lea     rdx, w_one
    jnz     @cei_h1
    lea     rdx, w_zero
@cei_h1:
    mov     r8d, 2
    mov     rcx, rbx
    call    _WriteBytes

    mov     r8d, 2
    lea     rdx, w_comma
    mov     rcx, rbx
    call    _WriteBytes

    ; Locked
    test    edi, VG_FLAG_LOCKED
    lea     rdx, w_one
    jnz     @cei_l1
    lea     rdx, w_zero
@cei_l1:
    mov     r8d, 2
    mov     rcx, rbx
    call    _WriteBytes

    mov     r8d, 2
    lea     rdx, w_comma
    mov     rcx, rbx
    call    _WriteBytes

    ; ReadOnly
    test    edi, VG_FLAG_READONLY
    lea     rdx, w_one
    jnz     @cei_r1
    lea     rdx, w_zero
@cei_r1:
    mov     r8d, 2
    mov     rcx, rbx
    call    _WriteBytes

    mov     r8d, 2
    lea     rdx, w_comma
    mov     rcx, rbx
    call    _WriteBytes

    ; NoExec
    test    edi, VG_FLAG_NOEXEC
    lea     rdx, w_one
    jnz     @cei_x1
    lea     rdx, w_zero
@cei_x1:
    mov     r8d, 2
    mov     rcx, rbx
    call    _WriteBytes

    mov     r8d, 4
    lea     rdx, w_crlf
    mov     rcx, rbx
    call    _WriteBytes

@cei_next:
    inc     r13d
    jmp     @cei_loop

@cei_close_reg:
    mov     rcx, cli_reg_hkey
    call    RegCloseKey

@cei_done:
    mov     rcx, rbx
    call    CloseHandle
    lea     rcx, msg_ok_export
    call    WideWriteLn
    xor     ecx, ecx
    call    _CliFinish

@cei_file_err:
    lea     rcx, msg_err_file
    call    WideWriteLn
    mov     ecx, 1
    call    _CliFinish

    add     rsp, 48h
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_CliEnumItems endp

; ==============================================================================
; _CliEnumTrusted  rcx=pszOutFile  → calls ExitProcess
; Stack: same frame as _CliEnumItems ✓
; ==============================================================================
PUBLIC _CliEnumTrusted
_CliEnumTrusted proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    sub     rsp, 48h

    mov     r14, rcx

    call    EnsureDriverReady
    test    eax, eax
    jz      @cet_no_driver

    call    IoctlEnumTrusted
    test    eax, eax
    jz      @cet_enum_empty

    call    CloseDevice

@cet_create_file:
    mov     qword ptr [rsp+30h], 0
    mov     dword ptr [rsp+28h], FILE_ATTRIBUTE_NORMAL
    mov     dword ptr [rsp+20h], CREATE_ALWAYS
    xor     r9d, r9d
    xor     r8d, r8d
    mov     edx, GENERIC_WRITE
    mov     rcx, r14
    call    CreateFileW
    cmp     rax, INVALID_HANDLE_VALUE
    je      @cet_file_err
    mov     rbx, rax

    mov     r8d, 2
    lea     rdx, w_bom
    mov     rcx, rbx
    call    _WriteBytes

    lea     rdx, str_csv_trust_hdr
    mov     rcx, rbx
    call    _WriteWStr

    ; Export trusted apps from persisted registry config.
    lea     rax, cli_reg_hkey
    mov     qword ptr [rsp+20h], rax
    mov     r9d, KEY_READ
    xor     r8d, r8d
    lea     rdx, str_key_trusted_cli
    mov     rcx, HKEY_CURRENT_USER
    call    RegOpenKeyExW
    test    eax, eax
    jnz     @cet_done

    xor     r13d, r13d

@cet_loop:
    mov     cli_reg_namelen, 520
    mov     qword ptr [rsp+38h], 0
    mov     qword ptr [rsp+30h], 0
    mov     qword ptr [rsp+28h], 0
    mov     qword ptr [rsp+20h], 0
    lea     r9, cli_reg_namelen
    lea     r8, cli_reg_name
    mov     edx, r13d
    mov     rcx, cli_reg_hkey
    call    RegEnumValueW
    cmp     eax, ERROR_NO_MORE_ITEMS
    je      @cet_close_reg
    test    eax, eax
    jnz     @cet_next

    lea     rdx, cli_reg_name
    mov     rcx, rdx
    call    wcslen_p
    shl     eax, 1
    mov     r8d, eax
    lea     rdx, cli_reg_name
    mov     rcx, rbx
    call    _WriteBytes

    mov     r8d, 4
    lea     rdx, w_crlf
    mov     rcx, rbx
    call    _WriteBytes

@cet_next:
    inc     r13d
    jmp     @cet_loop

@cet_close_reg:
    mov     rcx, cli_reg_hkey
    call    RegCloseKey

@cet_done:
    mov     rcx, rbx
    call    CloseHandle
    lea     rcx, msg_ok_export
    call    WideWriteLn
    xor     ecx, ecx
    call    _CliFinish

@cet_no_driver:
    lea     rcx, msg_err_nodrv
    call    WideWriteLn
    mov     ecx, 1
    call    _CliFinish

@cet_enum_empty:
    call    CloseDevice
    lea     rax, g_ioBuf
    mov     dword ptr [rax + VG_ER_COUNT], 0
    mov     dword ptr [rax + VG_ER_TOTALBYTES], 0
    jmp     @cet_create_file

@cet_ioctl_err:
    call    CloseDevice
    lea     rcx, msg_err_ioctl
    call    WideWriteLn
    mov     ecx, 1
    call    _CliFinish

@cet_file_err:
    lea     rcx, msg_err_file
    call    WideWriteLn
    mov     ecx, 1
    call    _CliFinish

    add     rsp, 48h
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_CliEnumTrusted endp

end

; ==============================================================================
; Vault Guard - CLI Dispatcher
;
; Author: Marek Wesołowski (wesmar)
;
; Interface (matches original VaultGuard.exe):
;   vg.exe /?
;   vg.exe /enumitems    <outfile>
;   vg.exe /enumtrusted  <outfile>
;   vg.exe /protection   on | off
;   vg.exe /setitem      <path>  Hidden|Locked|Read-only|No-execution|Disabled
;   vg.exe /settrusted   <name>  Enabled|Disabled
;   /p <password>  silently ignored (driver has no password layer)
;
; Entry:  CliDispatch(rcx=argv[1], rdx=argv, r8=argc)
; Return: rax=0 if switch unknown → GUI mode
;         Known switches call ExitProcess directly.
; ==============================================================================

option casemap:none

include consts.inc
include globals.inc

EXTRN ExitProcess           :PROC
EXTRN CreateFileW           :PROC
EXTRN WriteFile             :PROC
EXTRN CloseHandle           :PROC
EXTRN RegOpenKeyExW         :PROC
EXTRN RegEnumValueW         :PROC
EXTRN RegCloseKey           :PROC

EXTRN OpenDevice            :PROC
EXTRN EnsureDriverReady     :PROC
EXTRN CloseDevice           :PROC
EXTRN IoctlSetActive        :PROC
EXTRN IoctlAddPath          :PROC
EXTRN IoctlRemovePath       :PROC
EXTRN IoctlAddTrusted       :PROC
EXTRN IoctlRemoveTrusted    :PROC
EXTRN IoctlEnumPaths        :PROC
EXTRN IoctlEnumTrusted      :PROC
EXTRN IoctlClearAll         :PROC

EXTRN wcslen_p              :PROC
EXTRN wcscmp_ci             :PROC
EXTRN wcs_ascii_lower_inplace :PROC
EXTRN WideWriteLn           :PROC
EXTRN ConsoleSendEnter      :PROC

EXTRN ConfigSavePath        :PROC
EXTRN ConfigRemovePath      :PROC
EXTRN ConfigSaveTrusted     :PROC
EXTRN ConfigRemoveTrusted   :PROC
EXTRN ConfigLoad            :PROC

EXTRN g_statusResult        :BYTE

; ==============================================================================
; CONSTANT DATA
; ==============================================================================
.const

sw_help         dw '/',63,0
sw_help_slash_h dw '/','h',0
sw_help_slash_help dw '/','h','e','l','p',0
sw_help_dash_h dw '-','h',0
sw_help_ddash_h dw '-','-','h',0
sw_help_dash_help dw '-','h','e','l','p',0
sw_help_ddash_help dw '-','-','h','e','l','p',0
sw_enumitems    dw '/','e','n','u','m','i','t','e','m','s',0
sw_enumtrusted  dw '/','e','n','u','m','t','r','u','s','t','e','d',0
sw_protection   dw '/','p','r','o','t','e','c','t','i','o','n',0
sw_setitem      dw '/','s','e','t','i','t','e','m',0
sw_settrusted   dw '/','s','e','t','t','r','u','s','t','e','d',0

str_on          dw 'o','n',0
str_off         dw 'o','f','f',0
str_enabled     dw 'E','n','a','b','l','e','d',0
str_disabled    dw 'D','i','s','a','b','l','e','d',0
str_hidden      dw 'H','i','d','d','e','n',0
str_locked      dw 'L','o','c','k','e','d',0
str_readonly    dw 'R','e','a','d','-','o','n','l','y',0
str_noexec      dw 'N','o','-','e','x','e','c','u','t','i','o','n',0
str_key_paths_cli dw 'S','o','f','t','w','a','r','e','\','V','G','\','P','a','t','h','s',0
str_key_trusted_cli dw 'S','o','f','t','w','a','r','e','\','V','G','\','T','r','u','s','t','e','d',0

; CSV content
w_bom             dw 0FEFFh
w_comma           dw ','
w_crlf            dw 13,10
w_one             dw '1'
w_zero            dw '0'

str_csv_paths_hdr dw 'P','a','t','h',',','H','i','d','d','e','n',','
                  dw 'L','o','c','k','e','d',',','R','e','a','d','O','n','l','y',','
                  dw 'N','o','E','x','e','c',13,10,0

str_csv_trust_hdr dw 'A','p','p','l','i','c','a','t','i','o','n',13,10,0

; Help lines
msg_h1  dw 'V','a','u','l','t','G','u','a','r','d',' ','C','L','I',0
msg_h2  dw 'U','s','a','g','e',':',0
msg_h3  dw ' ',' ','v','g','.','e','x','e',' ','<','c','o','m','m','a','n','d','>',' ','[','a','r','g','u','m','e','n','t','s',']',0
msg_h4  dw 0
msg_h5  dw 'C','o','m','m','a','n','d','s',':',0
msg_h6  dw ' ',' ','/',63,',',' ','/','h',',',' ','/','h','e','l','p',',',' ','-','h',',',' ','-','-','h',',',' ','-','h','e','l','p',',',' ','-','-','h','e','l','p',0
msg_h7  dw ' ',' ',' ',' ','S','h','o','w',' ','t','h','i','s',' ','h','e','l','p',' ','s','c','r','e','e','n','.',0
msg_h8  dw ' ',' ','/','e','n','u','m','i','t','e','m','s',' ','<','f','i','l','e','>',0
msg_h9  dw ' ',' ',' ',' ','E','x','p','o','r','t',' ','p','r','o','t','e','c','t','e','d',' ','f','o','l','d','e','r','s',' ','t','o',' ','C','S','V','.',0
msg_h10 dw ' ',' ','/','e','n','u','m','t','r','u','s','t','e','d',' ','<','f','i','l','e','>',0
msg_h11 dw ' ',' ',' ',' ','E','x','p','o','r','t',' ','a','l','l','o','w','e','d',' ','a','p','p','s',' ','t','o',' ','C','S','V','.',0
msg_h12 dw ' ',' ','/','p','r','o','t','e','c','t','i','o','n',' ','o','n','|','o','f','f',0
msg_h13 dw ' ',' ',' ',' ','E','n','a','b','l','e',' ','o','r',' ','d','i','s','a','b','l','e',' ','g','l','o','b','a','l',' ','p','r','o','t','e','c','t','i','o','n','.',0
msg_h14 dw ' ',' ','/','s','e','t','i','t','e','m',' ','<','p','a','t','h','>',' ','<','m','o','d','e','>',0
msg_h15 dw ' ',' ',' ',' ','M','o','d','e','s',':',' ','H','i','d','d','e','n',',',' ','L','o','c','k','e','d',','
        dw ' ','R','e','a','d','-','o','n','l','y',',',' ','N','o','-','e','x','e','c','u','t','i','o','n',','
        dw ' ','D','i','s','a','b','l','e','d','.',0
msg_h16 dw ' ',' ','/','s','e','t','t','r','u','s','t','e','d',' ','<','n','a','m','e','>',' ','<','m','o','d','e','>',0
msg_h17 dw ' ',' ',' ',' ','M','o','d','e','s',':',' ','E','n','a','b','l','e','d',',',' ','D','i','s','a','b','l','e','d','.',0
msg_h18 dw 0
msg_h19 dw 'E','x','a','m','p','l','e','s',':',0
msg_h20 dw ' ',' ','v','g','.','e','x','e',' ','/','s','e','t','i','t','e','m',' ','"','C',':','\','t','e','m','p','\','a','a','a','"',' ','H','i','d','d','e','n',0
msg_h21 dw ' ',' ','v','g','.','e','x','e',' ','/','s','e','t','i','t','e','m',' ','"','C',':','\','t','e','m','p','\','a','a','a','"',' ','D','i','s','a','b','l','e','d',0
msg_h22 dw ' ',' ','v','g','.','e','x','e',' ','/','s','e','t','t','r','u','s','t','e','d',' ','n','o','t','e','p','a','d','.','e','x','e',' ','E','n','a','b','l','e','d',0
msg_h23 dw ' ',' ','v','g','.','e','x','e',' ','/','e','n','u','m','i','t','e','m','s',' ','i','t','e','m','s','.','c','s','v',0

msg_ok_prot_on    dw 'P','r','o','t','e','c','t','i','o','n',' ','e','n','a','b','l','e','d','.',0
msg_ok_prot_off   dw 'P','r','o','t','e','c','t','i','o','n',' ','d','i','s','a','b','l','e','d','.',0
msg_ok_setitem    dw 'I','t','e','m',' ','u','p','d','a','t','e','d','.',0
msg_ok_settrusted dw 'T','r','u','s','t','e','d',' ','a','p','p',' ','u','p','d','a','t','e','d','.',0
msg_ok_export     dw 'E','x','p','o','r','t',' ','c','o','m','p','l','e','t','e','.',0
msg_err_nodrv     dw 'E','r','r','o','r',':',' ','D','r','i','v','e','r',' ','n','o','t',' ','r','u','n','n','i','n','g','.',0
msg_err_arg       dw 'E','r','r','o','r',':',' ','I','n','v','a','l','i','d',' ','a','r','g','u','m','e','n','t','.',0
msg_err_file      dw 'E','r','r','o','r',':',' ','C','a','n','n','o','t',' ','c','r','e','a','t','e',' ','o','u','t','p','u','t',' ','f','i','l','e','.',0
msg_err_ioctl     dw 'E','r','r','o','r',':',' ','D','r','i','v','e','r',' ','I','O','C','T','L',' ','f','a','i','l','e','d','.',0

; ==============================================================================
; MUTABLE DATA
; ==============================================================================
.data
    align 4
    dw_written  dd 0
    cli_reg_namelen dd 0
    cli_reg_datalen dd 0
    cli_reg_type    dd 0
    cli_reg_flags   dd 0
    align 8
    cli_reg_hkey dq 0
    cli_reg_name dw 520 dup(0)

; ==============================================================================
; CODE
; ==============================================================================
.code

; ==============================================================================
; _CliFinish  ecx=exitCode  →  never returns
; Injects Enter into console so parent CMD prompt reappears, then exits.
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 28h (+40)→0 ✓
; ==============================================================================
_CliFinish proc
    push    rbx
    push    rsi
    sub     rsp, 28h

    mov     ebx, ecx            ; save exit code (rbx is non-volatile)
    call    ConsoleSendEnter
    mov     ecx, ebx
    call    ExitProcess

    add     rsp, 28h            ; unreachable — MASM requires epilogue
    pop     rsi
    pop     rbx
    ret
_CliFinish endp

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
; _CliHelp  → void
; Stack: sub 28h; 8+40=48; 48%16=0 ✓
; ==============================================================================
_CliHelp proc
    sub     rsp, 28h

    lea     rcx, msg_h1
    call    WideWriteLn
    lea     rcx, msg_h2
    call    WideWriteLn
    lea     rcx, msg_h3
    call    WideWriteLn
    lea     rcx, msg_h4
    call    WideWriteLn
    lea     rcx, msg_h5
    call    WideWriteLn
    lea     rcx, msg_h6
    call    WideWriteLn
    lea     rcx, msg_h7
    call    WideWriteLn
    lea     rcx, msg_h8
    call    WideWriteLn
    lea     rcx, msg_h9
    call    WideWriteLn
    lea     rcx, msg_h10
    call    WideWriteLn
    lea     rcx, msg_h11
    call    WideWriteLn
    lea     rcx, msg_h12
    call    WideWriteLn
    lea     rcx, msg_h13
    call    WideWriteLn
    lea     rcx, msg_h14
    call    WideWriteLn
    lea     rcx, msg_h15
    call    WideWriteLn
    lea     rcx, msg_h16
    call    WideWriteLn
    lea     rcx, msg_h17
    call    WideWriteLn
    lea     rcx, msg_h18
    call    WideWriteLn
    lea     rcx, msg_h19
    call    WideWriteLn
    lea     rcx, msg_h20
    call    WideWriteLn
    lea     rcx, msg_h21
    call    WideWriteLn
    lea     rcx, msg_h22
    call    WideWriteLn
    lea     rcx, msg_h23
    call    WideWriteLn

    add     rsp, 28h
    ret
_CliHelp endp

; ==============================================================================
; _CliEnumItems  rcx=pszOutFile  → calls ExitProcess
; Stack: push rbx,rsi,rdi,r12,r13,r14 (+48); sub 48h (+72); 8+120=128; 128%16=0 ✓
; CreateFileW/RegEnumValueW stack args fit in the 48h local area.
; ==============================================================================
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
    ; --- create output file ---
    ; CreateFileW(lpFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
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

    ; --- BOM ---
    mov     r8d, 2
    lea     rdx, w_bom
    mov     rcx, rbx
    call    _WriteBytes

    ; --- header ---
    lea     rdx, str_csv_paths_hdr
    mov     rcx, rbx
    call    _WriteWStr

    ; Export protected folders from persisted config. This is the authoritative
    ; user-visible state; the driver enum buffer can lag after flags=0 removal.
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
    shl     r12d, 1                    ; path bytes, no terminator

    ; write path bytes
    mov     rdx, rsi
    mov     r8d, r12d
    mov     rcx, rbx
    call    _WriteBytes

    ; comma
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

    ; NoExec (last field — CRLF after)
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

    add     rsp, 48h    ; unreachable — needed for MASM proc epilogue
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

    ; BOM
    mov     r8d, 2
    lea     rdx, w_bom
    mov     rcx, rbx
    call    _WriteBytes

    ; header
    lea     rdx, str_csv_trust_hdr
    mov     rcx, rbx
    call    _WriteWStr

    ; Export trusted apps from persisted config. The driver keeps process trust
    ; state separately and does not enumerate these registry names reliably.
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

    ; write name bytes
    lea     rdx, cli_reg_name
    mov     rcx, rdx
    call    wcslen_p
    shl     eax, 1
    mov     r8d, eax
    lea     rdx, cli_reg_name
    mov     rcx, rbx
    call    _WriteBytes

    ; CRLF
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

; ==============================================================================
; CliDispatch  rcx=argv[1]  rdx=argv  r8=argc  →  rax=0 if unknown (→ GUI)
; Stack: push rbx,rsi,rdi,r12,r13,r14 (+48); sub 38h (+56); 8+104=112; 0 ✓
; ==============================================================================
PUBLIC CliDispatch
CliDispatch proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    sub     rsp, 38h

    mov     rbx, rcx    ; argv[1] = switch
    mov     rsi, rdx    ; argv[] array
    mov     edi, r8d    ; argc

    ; ── /? ───────────────────────────────────────────────────────────────────
    cmp     word ptr [rbx], '/'
    jne     @cd_try_help_cmp
    cmp     word ptr [rbx+2], '?'
    jne     @cd_try_help_cmp
    cmp     word ptr [rbx+4], 0
    jne     @cd_try_help_cmp
    jmp     @cd_help

@cd_try_help_cmp:
    lea     rdx, sw_help
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jz      @cd_help

    lea     rdx, sw_help_slash_h
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jz      @cd_help

    lea     rdx, sw_help_slash_help
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jz      @cd_help

    lea     rdx, sw_help_dash_h
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jz      @cd_help

    lea     rdx, sw_help_ddash_h
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jz      @cd_help

    lea     rdx, sw_help_dash_help
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jz      @cd_help

    lea     rdx, sw_help_ddash_help
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_try_enumitems

@cd_help:
    call    _CliHelp
    xor     ecx, ecx
    call    _CliFinish

    ; ── /enumitems <file> ────────────────────────────────────────────────────
@cd_try_enumitems:
    lea     rdx, sw_enumitems
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_try_enumtrusted

    cmp     edi, 3
    jl      @cd_bad_arg
    mov     rcx, qword ptr [rsi + 2*8]
    call    _CliEnumItems       ; never returns

    ; ── /enumtrusted <file> ──────────────────────────────────────────────────
@cd_try_enumtrusted:
    lea     rdx, sw_enumtrusted
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_try_protection

    cmp     edi, 3
    jl      @cd_bad_arg
    mov     rcx, qword ptr [rsi + 2*8]
    call    _CliEnumTrusted     ; never returns

    ; ── /protection on|off ───────────────────────────────────────────────────
@cd_try_protection:
    lea     rdx, sw_protection
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_try_setitem

    cmp     edi, 3
    jl      @cd_bad_arg
    mov     r12, qword ptr [rsi + 2*8]  ; "on" or "off"

    call    EnsureDriverReady
    test    eax, eax
    jz      @cd_no_driver

    lea     rdx, str_on
    mov     rcx, r12
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_prot_try_off

    call    CloseDevice
    call    ConfigLoad
    call    EnsureDriverReady
    test    eax, eax
    jz      @cd_no_driver
    mov     ecx, 1
    call    IoctlSetActive
    call    CloseDevice
    lea     rcx, msg_ok_prot_on
    call    WideWriteLn
    xor     ecx, ecx
    call    _CliFinish

@cd_prot_try_off:
    lea     rdx, str_off
    mov     rcx, r12
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_bad_arg_close

    xor     ecx, ecx
    call    IoctlSetActive
    call    CloseDevice
    lea     rcx, msg_ok_prot_off
    call    WideWriteLn
    xor     ecx, ecx
    call    _CliFinish

    ; ── /setitem <path> <mode> ────────────────────────────────────────────────
@cd_try_setitem:
    lea     rdx, sw_setitem
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_try_settrusted

    cmp     edi, 4
    jl      @cd_bad_arg
    mov     r12, qword ptr [rsi + 2*8]  ; path
    mov     r13, qword ptr [rsi + 3*8]  ; mode

    ; Disabled → unprotect but keep path in config as inactive
    lea     rdx, str_disabled
    mov     rcx, r13
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_si_flags

    call    EnsureDriverReady
    test    eax, eax
    jz      @cd_no_driver
    mov     rdx, r12
    xor     ecx, ecx
    call    IoctlAddPath
    test    eax, eax
    jz      @cd_ioctl_err
    xor     edx, edx
    mov     rcx, r12
    call    ConfigSavePath
    call    CloseDevice
    lea     rcx, msg_ok_setitem
    call    WideWriteLn
    xor     ecx, ecx
    call    _CliFinish

@cd_si_flags:
    xor     r14d, r14d

    lea     rdx, str_hidden
    mov     rcx, r13
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_si_try_locked
    or      r14d, VG_FLAG_HIDDEN
    jmp     @cd_si_add

@cd_si_try_locked:
    lea     rdx, str_locked
    mov     rcx, r13
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_si_try_readonly
    or      r14d, VG_FLAG_LOCKED
    jmp     @cd_si_add

@cd_si_try_readonly:
    lea     rdx, str_readonly
    mov     rcx, r13
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_si_try_noexec
    or      r14d, VG_FLAG_READONLY
    jmp     @cd_si_add

@cd_si_try_noexec:
    lea     rdx, str_noexec
    mov     rcx, r13
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_bad_arg
    or      r14d, VG_FLAG_NOEXEC

@cd_si_add:
    call    EnsureDriverReady
    test    eax, eax
    jz      @cd_no_driver
    mov     rdx, r12
    mov     ecx, r14d
    call    IoctlAddPath
    test    eax, eax
    jz      @cd_ioctl_err
    mov     ecx, 1
    call    IoctlSetActive
    test    eax, eax
    jz      @cd_ioctl_err
    call    CloseDevice
    mov     edx, r14d
    mov     rcx, r12
    call    ConfigSavePath
    lea     rcx, msg_ok_setitem
    call    WideWriteLn
    xor     ecx, ecx
    call    _CliFinish

    ; ── /settrusted <name> <mode> ─────────────────────────────────────────────
@cd_try_settrusted:
    lea     rdx, sw_settrusted
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_unknown

    cmp     edi, 4
    jl      @cd_bad_arg
    mov     r12, qword ptr [rsi + 2*8]  ; name
    mov     r13, qword ptr [rsi + 3*8]  ; mode

    lea     rdx, str_disabled
    mov     rcx, r13
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_st_try_enabled

    mov     rcx, r12
    call    ConfigRemoveTrusted
    mov     rcx, r12
    call    wcs_ascii_lower_inplace

    call    EnsureDriverReady
    test    eax, eax
    jz      @cd_no_driver
    mov     rcx, r12
    call    IoctlRemoveTrusted
    call    CloseDevice
    mov     rcx, r12
    call    ConfigRemoveTrusted
    lea     rcx, msg_ok_settrusted
    call    WideWriteLn
    xor     ecx, ecx
    call    _CliFinish

@cd_st_try_enabled:
    lea     rdx, str_enabled
    mov     rcx, r13
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_bad_arg

    mov     rcx, r12
    call    wcs_ascii_lower_inplace

    call    EnsureDriverReady
    test    eax, eax
    jz      @cd_no_driver
    mov     rcx, r12
    call    IoctlAddTrusted
    test    eax, eax
    jz      @cd_ioctl_err
    call    CloseDevice
    mov     rcx, r12
    call    ConfigSaveTrusted
    lea     rcx, msg_ok_settrusted
    call    WideWriteLn
    xor     ecx, ecx
    call    _CliFinish

    ; ── error / unknown ───────────────────────────────────────────────────────
@cd_unknown:
    xor     eax, eax
    jmp     @cd_ret

@cd_bad_arg_close:
    call    CloseDevice
@cd_bad_arg:
    lea     rcx, msg_err_arg
    call    WideWriteLn
    mov     ecx, 1
    call    _CliFinish

@cd_no_driver:
    lea     rcx, msg_err_nodrv
    call    WideWriteLn
    mov     ecx, 1
    call    _CliFinish

@cd_ioctl_err:
    call    CloseDevice
    lea     rcx, msg_err_ioctl
    call    WideWriteLn
    mov     ecx, 1
    call    _CliFinish

@cd_ret:
    add     rsp, 38h
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
CliDispatch endp

end

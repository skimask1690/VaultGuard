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
EXTRN CloseHandle           :PROC
EXTRN GetModuleFileNameW    :PROC
EXTRN CreateProcessW        :PROC
EXTRN WaitForSingleObject   :PROC
EXTRN GetExitCodeProcess    :PROC

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
EXTRN InstallDriver         :PROC
EXTRN UninstallDriver       :PROC
EXTRN StartDriver           :PROC
EXTRN StopDriver            :PROC
EXTRN IsDriverInstalled     :PROC
EXTRN SetDriverStartType    :PROC
EXTRN DeleteDriverFile      :PROC

EXTRN wcslen_p              :PROC
EXTRN wcscmp_ci             :PROC
EXTRN wcs_ascii_lower_inplace :PROC
EXTRN WideWriteLn           :PROC
EXTRN ConsoleSendEnter      :PROC

EXTRN _CliServiceInstall    :PROC
EXTRN _CliServiceUninstall  :PROC
EXTRN RemoveAppService      :PROC
EXTRN _SvcStart             :PROC

EXTRN _CliEnumItems         :PROC
EXTRN _CliEnumTrusted       :PROC

EXTRN ConfigSavePath        :PROC
EXTRN ConfigRemovePath      :PROC
EXTRN ConfigSaveTrusted     :PROC
EXTRN ConfigRemoveTrusted   :PROC
EXTRN ConfigLoad            :PROC
EXTRN ConfigDeleteAll       :PROC

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
sw_service      dw '/','s','e','r','v','i','c','e',0
sw_driver       dw '/','d','r','i','v','e','r',0
sw_uninstall    dw '/','u','n','i','n','s','t','a','l','l',0
str_install     dw 'i','n','s','t','a','l','l',0
str_uninstall   dw 'u','n','i','n','s','t','a','l','l',0
str_start       dw 's','t','a','r','t',0
str_stop        dw 's','t','o','p',0
str_auto        dw 'a','u','t','o',0
str_manual      dw 'm','a','n','u','a','l',0
str_startup     dw 's','t','a','r','t','u','p',0
sw_svcstart     dw '/','s','v','c','s','t','a','r','t',0
sw_tray         dw '/','t','r','a','y',0
sw_autostart    dw '/','a','u','t','o','s','t','a','r','t',0
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
; schtasks command line fragments for _CliAutostart
; "on" prefix up to and including the opening \" of the /tr value:
;   schtasks.exe /create /f /sc onlogon /rl highest /tn VaultGuard /tr "\"
str_scht_on_pre dw 's','c','h','t','a','s','k','s','.','e','x','e',' '
                dw '/','c','r','e','a','t','e',' ','/','f',' '
                dw '/','s','c',' ','o','n','l','o','g','o','n',' '
                dw '/','r','l',' ','h','i','g','h','e','s','t',' '
                dw '/','t','n',' ','V','a','u','l','t','G','u','a','r','d',' '
                dw '/','t','r',' ',22h,5Ch,22h,0
; "on" suffix appended after <exepath>: \" /tray"
str_scht_on_suf dw 5Ch,22h,' ','/','t','r','a','y',22h,0
; "off" full command: schtasks.exe /delete /f /tn VaultGuard
str_scht_off    dw 's','c','h','t','a','s','k','s','.','e','x','e',' '
                dw '/','d','e','l','e','t','e',' ','/','f',' '
                dw '/','t','n',' ','V','a','u','l','t','G','u','a','r','d',0
; powershell command to strip battery restrictions from the task (best-effort):
;   powershell.exe -NonInteractive -Command "Set-ScheduledTask -TaskName VaultGuard
;       -Settings (New-ScheduledTaskSettingsSet -DisallowStartIfOnBatteries:$false
;                  -StopIfGoingOnBatteries:$false)"
str_ps_battery  dw 'p','o','w','e','r','s','h','e','l','l','.','e','x','e',' '
                dw '-','N','o','n','I','n','t','e','r','a','c','t','i','v','e',' '
                dw '-','C','o','m','m','a','n','d',' ',22h
                dw 'S','e','t','-','S','c','h','e','d','u','l','e','d','T','a','s','k',' '
                dw '-','T','a','s','k','N','a','m','e',' ','V','a','u','l','t','G','u','a','r','d',' '
                dw '-','S','e','t','t','i','n','g','s',' '
                dw '(','N','e','w','-','S','c','h','e','d','u','l','e','d','T','a','s','k','S','e','t','t','i','n','g','s','S','e','t',' '
                dw '-','D','i','s','a','l','l','o','w','S','t','a','r','t','I','f','O','n','B','a','t','t','e','r','i','e','s',':'
                dw 24h,'f','a','l','s','e',' '
                dw '-','S','t','o','p','I','f','G','o','i','n','g','O','n','B','a','t','t','e','r','i','e','s',':'
                dw 24h,'f','a','l','s','e',')',22h,0

; Help lines
msg_h1  dw 'V','a','u','l','t','G','u','a','r','d',' ','C','L','I',0
msg_h2  dw 'U','s','a','g','e',':',0
msg_h3  dw ' ',' ','v','g','.','e','x','e',' ','<','c','o','m','m','a','n','d','>',' ','[','a','r','g','u','m','e','n','t','s',']',0
msg_h4  dw 0
msg_h5  dw 'C','o','m','m','a','n','d','s',':',0
msg_h6  dw ' ',' ','/',63,',',' ','/','h',',',' ','/','h','e','l','p',',',' ','-','h',',',' ','-','-','h',',',' ','-','h','e','l','p',',',' ','-','-','h','e','l','p',0
msg_h7  dw ' ',' ',' ',' ','S','h','o','w',' ','t','h','i','s',' ','h','e','l','p',' ','s','c','r','e','e','n','.',0
msg_h_sv1 dw ' ',' ','/','s','e','r','v','i','c','e',' ','i','n','s','t','a','l','l','|','u','n','i','n','s','t','a','l','l',0
msg_h_sv2 dw ' ',' ',' ',' ','R','e','g','i','s','t','e','r',' ','o','r',' ','r','e','m','o','v','e',' '
          dw 'v','g','.','e','x','e',' ','a','s',' ','a',' ','W','i','n','d','o','w','s',' ','s','e','r','v','i','c','e','.',0
msg_h_drv1 dw ' ',' ','/','d','r','i','v','e','r',' ','i','n','s','t','a','l','l',' ','[','m','a','n','u','a','l','|','a','u','t','o',']',0
msg_h_drv2 dw ' ',' ','/','d','r','i','v','e','r',' ','u','n','i','n','s','t','a','l','l',0
msg_h_drv3 dw ' ',' ','/','d','r','i','v','e','r',' ','s','t','a','r','t',' ','|',' ','s','t','o','p',0
msg_h_drv4 dw ' ',' ','/','d','r','i','v','e','r',' ','s','t','a','r','t','u','p',' ','m','a','n','u','a','l','|','a','u','t','o',0
msg_h_drv5 dw ' ',' ',' ',' ','M','a','n','a','g','e',' ','c','l','r','c','d',' ','d','r','i','v','e','r',' '
           dw 's','e','r','v','i','c','e','.', ' ','D','e','f','a','u','l','t',':',' ','m','a','n','u','a','l','.',0
msg_h_un1 dw ' ',' ','/','u','n','i','n','s','t','a','l','l',0
msg_h_un2 dw ' ',' ',' ',' ','S','t','o','p',' ','a','n','d',' ','r','e','m','o','v','e',' '
          dw 's','e','r','v','i','c','e','s',',',' ','d','r','i','v','e','r',',',' ','f','i','l','e','s',' '
          dw 'a','n','d',' ','r','e','g','i','s','t','r','y',' ','c','o','n','f','i','g','.',0
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
msg_h18 dw ' ',' ','/','t','r','a','y',0
msg_h19 dw ' ',' ',' ',' ','S','t','a','r','t',' ','m','i','n','i','m','i','z','e','d',' ','t','o',' ','s','y','s','t','e','m',' ','t','r','a','y','.',0
msg_h_as1 dw ' ',' ','/','a','u','t','o','s','t','a','r','t',' ','o','n','|','o','f','f',0
msg_h_as2 dw ' ',' ',' ',' ','R','e','g','i','s','t','e','r',' ','o','r',' ','r','e','m','o','v','e',' ','a','u','t','o','s','t','a','r','t',' ','e','n','t','r','y',' ','(','/','t','r','a','y',')','.', 0
msg_h20 dw 0
msg_h21 dw 'E','x','a','m','p','l','e','s',':',0
msg_h22 dw ' ',' ','v','g','.','e','x','e',' ','/','s','e','t','i','t','e','m',' ','"','C',':','\','t','e','m','p','\','a','a','a','"',' ','H','i','d','d','e','n',0
msg_h23 dw ' ',' ','v','g','.','e','x','e',' ','/','s','e','t','i','t','e','m',' ','"','C',':','\','t','e','m','p','\','a','a','a','"',' ','D','i','s','a','b','l','e','d',0
msg_h24 dw ' ',' ','v','g','.','e','x','e',' ','/','s','e','t','t','r','u','s','t','e','d',' ','n','o','t','e','p','a','d','.','e','x','e',' ','E','n','a','b','l','e','d',0
msg_h25 dw ' ',' ','v','g','.','e','x','e',' ','/','e','n','u','m','i','t','e','m','s',' ','i','t','e','m','s','.','c','s','v',0
msg_h26 dw ' ',' ','v','g','.','e','x','e',' ','/','t','r','a','y',0

msg_ok_autostart_on  dw 'A','u','t','o','s','t','a','r','t',' ','e','n','a','b','l','e','d','.',0
msg_ok_autostart_off dw 'A','u','t','o','s','t','a','r','t',' ','d','i','s','a','b','l','e','d','.',0
msg_err_schtasks     dw 'E','r','r','o','r',':',' ','S','c','h','e','d','u','l','e','r',' ','f','a','i','l','e','d','.',0
msg_ok_prot_on    dw 'P','r','o','t','e','c','t','i','o','n',' ','e','n','a','b','l','e','d','.',0
msg_ok_prot_off   dw 'P','r','o','t','e','c','t','i','o','n',' ','d','i','s','a','b','l','e','d','.',0
msg_ok_setitem    dw 'I','t','e','m',' ','u','p','d','a','t','e','d','.',0
msg_ok_settrusted dw 'T','r','u','s','t','e','d',' ','a','p','p',' ','u','p','d','a','t','e','d','.',0
msg_ok_driver     dw 'D','r','i','v','e','r',' ','u','p','d','a','t','e','d','.',0
msg_ok_uninstall  dw 'U','n','i','n','s','t','a','l','l',' ','c','o','m','p','l','e','t','e','.',0
msg_err_nodrv     dw 'E','r','r','o','r',':',' ','D','r','i','v','e','r',' ','n','o','t',' ','r','u','n','n','i','n','g','.',0
msg_err_arg       dw 'E','r','r','o','r',':',' ','I','n','v','a','l','i','d',' ','a','r','g','u','m','e','n','t','.',0
msg_err_ioctl     dw 'E','r','r','o','r',':',' ','D','r','i','v','e','r',' ','I','O','C','T','L',' ','f','a','i','l','e','d','.',0
msg_err_driver    dw 'E','r','r','o','r',':',' ','D','r','i','v','e','r',' ','m','a','n','a','g','e','m','e','n','t',' ','f','a','i','l','e','d','.',0

; ==============================================================================
; MUTABLE DATA
; ==============================================================================
.data

cli_trusted_buf dw (MAX_PATH + 8) dup(0)

; ==============================================================================
; CODE
; ==============================================================================
.code

; ==============================================================================
; _CliNormalizeTrusted  rcx=input -> rax=normalized buffer or 0
; Keeps the basename, lowercases ASCII, and appends .exe when missing. The
; driver compares at most 199 WCHARs in its fixed process-name field.
; ==============================================================================
_CliNormalizeTrusted proc
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 20h

    mov     rsi, rcx
    mov     rbx, rcx                    ; basename start
@cnt_scan:
    movzx   eax, word ptr [rsi]
    test    ax, ax
    jz      @cnt_copy_begin
    cmp     ax, '\'
    je      @cnt_sep
    cmp     ax, '/'
    je      @cnt_sep
    add     rsi, 2
    jmp     @cnt_scan
@cnt_sep:
    add     rsi, 2
    mov     rbx, rsi
    jmp     @cnt_scan

@cnt_copy_begin:
    cmp     word ptr [rbx], 0
    je      @cnt_fail
    lea     rdi, cli_trusted_buf
    xor     ecx, ecx                    ; copied character count
@cnt_copy:
    movzx   eax, word ptr [rbx]
    test    ax, ax
    jz      @cnt_copied
    cmp     ecx, 199
    jae     @cnt_fail
    cmp     ax, 'A'
    jb      @cnt_store
    cmp     ax, 'Z'
    ja      @cnt_store
    add     ax, 20h
@cnt_store:
    mov     word ptr [rdi + rcx*2], ax
    inc     ecx
    add     rbx, 2
    jmp     @cnt_copy

@cnt_copied:
    mov     word ptr [rdi + rcx*2], 0
    cmp     ecx, 4
    jb      @cnt_append
    mov     eax, ecx
    sub     eax, 4
    lea     rdx, [rdi + rax*2]
    cmp     word ptr [rdx], '.'
    jne     @cnt_append
    cmp     word ptr [rdx+2], 'e'
    jne     @cnt_append
    cmp     word ptr [rdx+4], 'x'
    jne     @cnt_append
    cmp     word ptr [rdx+6], 'e'
    je      @cnt_ok

@cnt_append:
    cmp     ecx, 195                    ; basename + ".exe" must fit 199 WCHARs
    ja      @cnt_fail
    mov     word ptr [rdi + rcx*2], '.'
    mov     word ptr [rdi + rcx*2 + 2], 'e'
    mov     word ptr [rdi + rcx*2 + 4], 'x'
    mov     word ptr [rdi + rcx*2 + 6], 'e'
    mov     word ptr [rdi + rcx*2 + 8], 0

@cnt_ok:
    lea     rax, cli_trusted_buf
    jmp     @cnt_ret
@cnt_fail:
    xor     eax, eax
@cnt_ret:
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_CliNormalizeTrusted endp

; ==============================================================================
; _CliFinish  ecx=exitCode  →  never returns
; Injects Enter into console so parent CMD prompt reappears, then exits.
; Stack: entry rsp%16=8; push rbx,rsi (+16)→8; sub 28h (+40)→0 ✓
; ==============================================================================
PUBLIC _CliFinish
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
    lea     rcx, msg_h_sv1
    call    WideWriteLn
    lea     rcx, msg_h_sv2
    call    WideWriteLn
    lea     rcx, msg_h_drv1
    call    WideWriteLn
    lea     rcx, msg_h_drv2
    call    WideWriteLn
    lea     rcx, msg_h_drv3
    call    WideWriteLn
    lea     rcx, msg_h_drv4
    call    WideWriteLn
    lea     rcx, msg_h_drv5
    call    WideWriteLn
    lea     rcx, msg_h_un1
    call    WideWriteLn
    lea     rcx, msg_h_un2
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
    lea     rcx, msg_h_as1
    call    WideWriteLn
    lea     rcx, msg_h_as2
    call    WideWriteLn
    lea     rcx, msg_h20
    call    WideWriteLn
    lea     rcx, msg_h21
    call    WideWriteLn
    lea     rcx, msg_h22
    call    WideWriteLn
    lea     rcx, msg_h23
    call    WideWriteLn
    lea     rcx, msg_h24
    call    WideWriteLn
    lea     rcx, msg_h25
    call    WideWriteLn
    lea     rcx, msg_h26
    call    WideWriteLn

    add     rsp, 28h
    ret
_CliHelp endp

; ==============================================================================
; RunCmdAndWait  rcx=lpCommandLine(LPWSTR)  →  rax=exitCode, -1 on CP failure
;
; Launches command in a hidden console window, waits for completion,
; returns process exit code.  Caller owns the writable buffer (CreateProcessW
; may modify lpCommandLine per MSDN).
;
; Stack: push rbx (+8→rsp%16=0); sub 0E0h (+224→rsp%16=0) ✓
; Frame from rsp:
;   [000h..01Fh]  shadow space           (32)
;   [020h..04Fh]  CreateProcessW args 5-10 (48)
;   [050h..057h]  pad                    ( 8)
;   [058h..0BFh]  STARTUPINFOW si        (104)
;   [0C0h..0D7h]  PROCESS_INFORMATION pi ( 24)
;   [0D8h..0DFh]  exitCode + pad         (  8)
; ==============================================================================
RunCmdAndWait proc
    push    rbx
    sub     rsp, 0E0h

    mov     rbx, rcx            ; save command line (non-volatile)

    ; ── Zero SI (104 B = 13 QWORDs) ──────────────────────────────────────────
    xor     eax, eax
    mov     qword ptr [rsp+058h+000h], rax
    mov     qword ptr [rsp+058h+008h], rax
    mov     qword ptr [rsp+058h+010h], rax
    mov     qword ptr [rsp+058h+018h], rax
    mov     qword ptr [rsp+058h+020h], rax
    mov     qword ptr [rsp+058h+028h], rax
    mov     qword ptr [rsp+058h+030h], rax
    mov     qword ptr [rsp+058h+038h], rax
    mov     qword ptr [rsp+058h+040h], rax
    mov     qword ptr [rsp+058h+048h], rax
    mov     qword ptr [rsp+058h+050h], rax
    mov     qword ptr [rsp+058h+058h], rax
    mov     qword ptr [rsp+058h+060h], rax
    mov     dword ptr [rsp+058h],      68h     ; si.cb = sizeof(STARTUPINFOW)
    ; ── Zero PI (24 B = 3 QWORDs) ────────────────────────────────────────────
    mov     qword ptr [rsp+0C0h], rax
    mov     qword ptr [rsp+0C8h], rax
    mov     qword ptr [rsp+0D0h], rax

    ; ── CreateProcessW ────────────────────────────────────────────────────────
    lea     rax, [rsp+0C0h]
    mov     qword ptr [rsp+48h], rax           ; arg10 &pi
    lea     rax, [rsp+058h]
    mov     qword ptr [rsp+40h], rax           ; arg9  &si
    mov     qword ptr [rsp+38h], 0             ; arg8  lpCurrentDirectory = NULL
    mov     qword ptr [rsp+30h], 0             ; arg7  lpEnvironment = NULL
    mov     dword ptr [rsp+28h], CREATE_NO_WINDOW ; arg6
    mov     dword ptr [rsp+20h], 0             ; arg5  bInheritHandles = FALSE
    xor     r9d, r9d
    xor     r8d, r8d
    mov     rdx, rbx
    xor     ecx, ecx
    call    CreateProcessW
    test    eax, eax
    jz      @rcw_fail

    ; ── Wait ──────────────────────────────────────────────────────────────────
    mov     edx, INFINITE
    mov     rcx, qword ptr [rsp+0C0h]          ; hProcess
    call    WaitForSingleObject

    ; ── Get exit code ────────────────────────────────────────────────────────
    mov     qword ptr [rsp+0D8h], 0
    lea     rdx, [rsp+0D8h]
    mov     rcx, qword ptr [rsp+0C0h]          ; hProcess
    call    GetExitCodeProcess

    ; ── Close handles ────────────────────────────────────────────────────────
    mov     rcx, qword ptr [rsp+0C8h]          ; hThread
    call    CloseHandle
    mov     rcx, qword ptr [rsp+0C0h]          ; hProcess
    call    CloseHandle

    mov     eax, dword ptr [rsp+0D8h]
    jmp     @rcw_ret

@rcw_fail:
    mov     eax, -1

@rcw_ret:
    add     rsp, 0E0h
    pop     rbx
    ret
RunCmdAndWait endp

; ==============================================================================
; _CliAutostart  rcx="on"|"off"  → calls ExitProcess
;
; on:  1) schtasks /create /f /sc onlogon /rl highest /tn VaultGuard
;              /tr "\"<exe>\" /tray"
;      2) powershell Set-ScheduledTask ... to clear battery restrictions
; off: schtasks /delete /f /tn VaultGuard
;
; Stack: push rbx,rsi,rdi (+24→rsp%16=0); sub 20h (+32→rsp%16=0) ✓
; ==============================================================================
_CliAutostart proc
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 20h

    mov     rbx, rcx            ; "on" or "off"

    ; ── off ──────────────────────────────────────────────────────────────────
    lea     rdx, str_off
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jnz     @cas_try_on

    lea     rdi, g_tempBuf
    lea     rsi, str_scht_off
@cas_copy_off:
    mov     ax, word ptr [rsi]
    mov     word ptr [rdi], ax
    add     rsi, 2
    add     rdi, 2
    test    ax, ax
    jnz     @cas_copy_off

    lea     rcx, g_tempBuf
    call    RunCmdAndWait
    test    eax, eax
    jnz     @cas_schtasks_err

    lea     rcx, msg_ok_autostart_off
    call    WideWriteLn
    xor     ecx, ecx
    call    _CliFinish

    ; ── on ───────────────────────────────────────────────────────────────────
@cas_try_on:
    lea     rdx, str_on
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jnz     @cas_bad_arg

    ; Build: [pre][exe][suf] → g_tempBuf
    lea     rdi, g_tempBuf
    lea     rsi, str_scht_on_pre
@cas_copy_pre:
    mov     ax, word ptr [rsi]
    test    ax, ax
    jz      @cas_pre_done
    mov     word ptr [rdi], ax
    add     rsi, 2
    add     rdi, 2
    jmp     @cas_copy_pre
@cas_pre_done:
    mov     r8d, MAX_PATH
    mov     rdx, rdi
    xor     ecx, ecx
    call    GetModuleFileNameW
    test    eax, eax
    jz      @cas_bad_arg
    lea     rdi, [rdi + rax*2]

    lea     rsi, str_scht_on_suf
@cas_copy_suf:
    mov     ax, word ptr [rsi]
    mov     word ptr [rdi], ax
    add     rsi, 2
    add     rdi, 2
    test    ax, ax
    jnz     @cas_copy_suf

    ; Run schtasks /create
    lea     rcx, g_tempBuf
    call    RunCmdAndWait
    test    eax, eax
    jnz     @cas_schtasks_err

    ; Fix battery restrictions (best-effort — ignore exit code)
    lea     rdi, g_tempBuf
    lea     rsi, str_ps_battery
@cas_copy_bat:
    mov     ax, word ptr [rsi]
    mov     word ptr [rdi], ax
    add     rsi, 2
    add     rdi, 2
    test    ax, ax
    jnz     @cas_copy_bat
    lea     rcx, g_tempBuf
    call    RunCmdAndWait

    lea     rcx, msg_ok_autostart_on
    call    WideWriteLn
    xor     ecx, ecx
    call    _CliFinish

@cas_bad_arg:
    lea     rcx, msg_err_arg
    call    WideWriteLn
    mov     ecx, 1
    call    _CliFinish

@cas_schtasks_err:
    lea     rcx, msg_err_schtasks
    call    WideWriteLn
    mov     ecx, 1
    call    _CliFinish

    add     rsp, 20h    ; unreachable
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_CliAutostart endp

; ==============================================================================
; _CliDriver  rcx=argv[2], rdx=argv, r8=argc  →  never returns
;
; API-only driver lifecycle for the real protection service "clrcd".
;   install [manual|auto]   create service (default: manual)
;   uninstall               stop + DeleteService + remove vg.sys
;   start | stop            runtime control (no reinstall)
;   startup manual|auto     change start type without reinstall (next boot)
;
; Stack: push rbx,rsi,rdi,r12 (+32); sub 28h (+40); 8+72=80; 0 ✓
; ==============================================================================
_CliDriver proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 28h

    mov     rbx, rcx                    ; subcommand
    mov     rsi, rdx                    ; argv[]
    mov     edi, r8d                    ; argc

    ; ── install [manual|auto] ───────────────────────────────────────────────
    lea     rdx, str_install
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jnz     @drv_try_uninstall

    call    IsDriverInstalled
    test    eax, eax
    jnz     @drv_install_set_type

    call    InstallDriver               ; CreateServiceW uses SERVICE_DEMAND_START
    test    eax, eax
    jz      @drv_err

@drv_install_set_type:
    cmp     edi, 4
    jl      @drv_manual                  ; default: manual
    mov     r12, qword ptr [rsi + 3*8]   ; argv[3] = manual|auto
    lea     rdx, str_auto
    mov     rcx, r12
    call    wcscmp_ci
    test    eax, eax
    jz      @drv_auto
    lea     rdx, str_manual
    mov     rcx, r12
    call    wcscmp_ci
    test    eax, eax
    jz      @drv_manual
    jmp     @drv_bad_arg

    ; ── uninstall ───────────────────────────────────────────────────────────
@drv_try_uninstall:
    lea     rdx, str_uninstall
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jnz     @drv_try_start

    call    IsDriverInstalled
    test    eax, eax
    jz      @drv_delete_file_only
    call    UninstallDriver
    test    eax, eax
    jz      @drv_err
@drv_delete_file_only:
    call    DeleteDriverFile             ; best-effort after SCM delete
    jmp     @drv_ok

    ; ── start ───────────────────────────────────────────────────────────────
@drv_try_start:
    lea     rdx, str_start
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jnz     @drv_try_stop
    call    StartDriver
    test    eax, eax
    jz      @drv_err
    jmp     @drv_ok

    ; ── stop ────────────────────────────────────────────────────────────────
@drv_try_stop:
    lea     rdx, str_stop
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jnz     @drv_try_startup
    call    StopDriver
    test    eax, eax
    jz      @drv_err
    jmp     @drv_ok

    ; ── startup manual|auto ─────────────────────────────────────────────────
    ; Change start type without reinstall. SCM rewrites HKLM\...\clrcd\Start
    ; via ChangeServiceConfigW — running driver is NOT affected.
@drv_try_startup:
    lea     rdx, str_startup
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jnz     @drv_bad_arg

    cmp     edi, 4
    jl      @drv_bad_arg                ; startup requires argv[3] = manual|auto
    mov     r12, qword ptr [rsi + 3*8]
    lea     rdx, str_auto
    mov     rcx, r12
    call    wcscmp_ci
    test    eax, eax
    jz      @drv_auto
    lea     rdx, str_manual
    mov     rcx, r12
    call    wcscmp_ci
    test    eax, eax
    jz      @drv_manual
    jmp     @drv_bad_arg

@drv_auto:
    mov     ecx, SERVICE_AUTO_START
    call    SetDriverStartType
    test    eax, eax
    jz      @drv_err
    jmp     @drv_ok

@drv_manual:
    mov     ecx, SERVICE_DEMAND_START
    call    SetDriverStartType
    test    eax, eax
    jz      @drv_err

@drv_ok:
    lea     rcx, msg_ok_driver
    call    WideWriteLn
    xor     ecx, ecx
    call    _CliFinish

@drv_bad_arg:
    lea     rcx, msg_err_arg
    call    WideWriteLn
    mov     ecx, 1
    call    _CliFinish

@drv_err:
    lea     rcx, msg_err_driver
    call    WideWriteLn
    mov     ecx, 1
    call    _CliFinish

    add     rsp, 28h            ; unreachable
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_CliDriver endp

; ==============================================================================
; _CliFullUninstall  →  never returns
;
; Stops userspace protection if reachable, removes the app service, removes the
; clrcd service, deletes the extracted driver file, and drops HKCU config.
; Individual cleanup failures are intentionally best-effort so stale partial
; installs can still be cleaned in one pass.
;
; Stack: entry rsp%16=8; sub 28h → 0 ✓
; ==============================================================================
_CliFullUninstall proc
    sub     rsp, 28h

    call    OpenDevice
    test    eax, eax
    jz      @un_no_device
    xor     ecx, ecx
    call    IoctlSetActive
    call    CloseDevice

@un_no_device:
    call    RemoveAppService
    call    StopDriver
    call    UninstallDriver
    call    DeleteDriverFile
    call    ConfigDeleteAll

    lea     rcx, msg_ok_uninstall
    call    WideWriteLn
    xor     ecx, ecx
    call    _CliFinish

    add     rsp, 28h            ; unreachable
    ret
_CliFullUninstall endp

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
    jnz     @cd_try_service

@cd_help:
    call    _CliHelp
    xor     ecx, ecx
    call    _CliFinish

    ; ── /service install|uninstall ───────────────────────────────────────────
@cd_try_service:
    lea     rdx, sw_service
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_try_driver

    cmp     edi, 3
    jl      @cd_bad_arg
    mov     r12, qword ptr [rsi + 2*8]  ; argv[2] = "install" / "uninstall"

    lea     rdx, str_install
    mov     rcx, r12
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_svc_uninst
    call    _CliServiceInstall          ; never returns

@cd_svc_uninst:
    lea     rdx, str_uninstall
    mov     rcx, r12
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_bad_arg
    call    _CliServiceUninstall        ; never returns

    ; ── /driver install [manual|auto]  OR  /driver start|stop|manual|auto  OR  /driver uninstall
@cd_try_driver:
    lea     rdx, sw_driver
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_try_uninstall

    cmp     edi, 3
    jl      @cd_bad_arg
    mov     rcx, qword ptr [rsi + 2*8]  ; argv[2] = driver subcommand
    mov     rdx, rsi
    mov     r8d, edi
    call    _CliDriver                  ; never returns

    ; ── /uninstall  (full product cleanup) ──────────────────────────────────
@cd_try_uninstall:
    lea     rdx, sw_uninstall
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_try_enumitems
    call    _CliFullUninstall           ; never returns

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
    call    ConfigLoad                 ; restore complete path/trusted arrays
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
    call    ConfigLoad                 ; single-item IOCTL above replaced the list
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
    jnz     @cd_try_svcstart

    cmp     edi, 4
    jl      @cd_bad_arg
    mov     r12, qword ptr [rsi + 2*8]  ; name
    mov     r13, qword ptr [rsi + 3*8]  ; mode

    mov     rcx, r12
    call    _CliNormalizeTrusted
    test    rax, rax
    jz      @cd_bad_arg
    mov     r12, rax

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
    call    ConfigLoad                 ; reload every remaining trusted record
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
    call    ConfigLoad                 ; reload complete trusted array
    lea     rcx, msg_ok_settrusted
    call    WideWriteLn
    xor     ecx, ecx
    call    _CliFinish

    ; ── /svcstart  (internal — invoked by SCM, not shown in help) ───────────
@cd_try_svcstart:
    lea     rdx, sw_svcstart
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_try_tray
    call    _SvcStart               ; never returns

    ; ── /tray ────────────────────────────────────────────────────────────────
@cd_try_tray:
    lea     rdx, sw_tray
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_try_autostart

    mov     g_startMinimized, 1
    ; fall through → @cd_try_autostart → @cd_unknown → return 0 (GUI mode)

    ; ── /autostart on|off ────────────────────────────────────────────────────
@cd_try_autostart:
    lea     rdx, sw_autostart
    mov     rcx, rbx
    call    wcscmp_ci
    test    eax, eax
    jnz     @cd_unknown

    cmp     edi, 3
    jl      @cd_bad_arg
    mov     rcx, qword ptr [rsi + 2*8]  ; argv[2] = "on"/"off"
    call    _CliAutostart               ; never returns

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

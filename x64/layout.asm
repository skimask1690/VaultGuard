; ==============================================================================
; Vault Guard - Window Layout
;
; Author: Marek Wesołowski (wesmar)
; Purpose: WM_CREATE handler — creates and configures all child controls.
;
; Exported:
;   _OnCreate(rcx=hwnd)  → void
; ==============================================================================

option casemap:none

include consts.inc
include globals.inc

; ── Win32 ─────────────────────────────────────────────────────────────────────
EXTRN CreateWindowExW           :PROC
EXTRN InitCommonControlsEx      :PROC
EXTRN SendMessageW              :PROC
EXTRN SetTimer                  :PROC
EXTRN DragAcceptFiles           :PROC
EXTRN ChangeWindowMessageFilterEx :PROC
EXTRN GetDpiForWindow            :PROC
EXTRN ShowProcPicker            :PROC   ; procpicker.asm
EXTRN GuiExportConfig           :PROC   ; impexp.asm
EXTRN GuiImportConfig           :PROC   ; impexp.asm

; ── Sibling modules ───────────────────────────────────────────────────────────
EXTRN _ReadDarkMode             :PROC   ; theme.asm
EXTRN ApplyDarkMode             :PROC   ; theme.asm
EXTRN _ApplyThemeColors         :PROC   ; theme.asm
EXTRN _SendFont                 :PROC   ; theme.asm
EXTRN CreateFonts               :PROC   ; theme.asm
EXTRN _LvAddColumn              :PROC   ; listview.asm
EXTRN RefreshLists              :PROC   ; listview.asm
EXTRN UpdateStatusBar           :PROC   ; handlers.asm
EXTRN ConfigLoad                :PROC   ; config.asm

EXTRN str_btn_toggle_off        :WORD   ; handlers.asm
EXTRN g_wmTaskbarCreated        :DWORD  ; window.asm

; ==============================================================================
; CONSTANT STRINGS
; ==============================================================================
.const

str_buttoncls   dw 'B','U','T','T','O','N',0
str_staticcls   dw 'S','T','A','T','I','C',0
str_listviewcls dw 'S','y','s','L','i','s','t','V','i','e','w','3','2',0
str_editcls     dw 'E','D','I','T',0

str_btn_add_path      dw 'A','d','d',' ','p','a','t','h','.','.','.',0
str_btn_restore       dw 'R','e','m','o','v','e',' ','s','e','l','e','c','t','e','d',0
str_btn_add_proc      dw 'A','d','d',0
str_btn_remove_proc   dw 'R','e','m','o','v','e',0
str_btn_add_running   dw 'A','d','d',' ','r','u','n','n','i','n','g',0
str_btn_export        dw 'E','x','p','o','r','t',0
str_btn_import        dw 'I','m','p','o','r','t',0

str_hdr_paths       dw 'P','r','o','t','e','c','t','e','d',' ','f','i','l','e','s','/','f','o','l','d','e','r','s',0
str_hdr_trusted     dw 'A','l','l','o','w','e','d',' ','a','p','p','s',' ','(','t','r','u','s','t','e','d',')',0

str_col_path        dw 'P','a','t','h',0
str_col_h           dw 'H','i','d','d','e','n',0
str_col_l           dw 'L','o','c','k','e','d',0
str_col_r           dw 'R','e','a','d','-','o','n','l','y',0
str_col_x           dw 'N','o',' ','r','u','n',0

str_col_process     dw 'P','r','o','c','e','s','s',' ','n','a','m','e',0

str_proc_hint       dw 'e','.','g','.',' ','t','o','t','a','l','c','m','d','6','4','.','e','x','e',0

; Author / copyright line shown at the bottom of the main window.
; Split across multiple dw lines to stay within MASM line-length limits.
; U+0142 = ł (l with stroke),  U+00AE = ® (registered sign)
str_author          dw 'A','u','t','h','o','r',':',' '
                    dw 'M','a','r','e','k',' '
                    dw 'W','e','s','o',0142h,'o','w','s','k','i'
                    dw ' ','-',' '
                    dw 'W','E','S','M','A','R',00AEh,' ','2','0','2','6'
                    dw ' ','-',' '
                    dw 'm','a','r','e','k','@','k','v','c','.','p','l'
                    dw ',',' '
                    dw 't','e','l','/','w','h','a','t','s','a','p','p'
                    dw ':',' ','+','4','8',' '
                    dw '6','0','7','-','4','4','0','-','2','8','3',0

; ==============================================================================
; DATA
; ==============================================================================
.data
    align 8

icc_ex  dd INITCOMMONCONTROLSEX_SIZE
        dd ICC_LISTVIEW_CLASSES

PUBLIC g_hwndEditTrusted
g_hwndEditTrusted   dq 0

; ==============================================================================
; CODE
; ==============================================================================
.code

PUBLIC _OnCreate

; ==============================================================================
; _OnCreate  rcx=hwnd  →  void
; Creates all child controls. Called from WM_CREATE.
; Stack: entry rsp%16=8; push rbx,rsi,rdi,r12,r13,r14 (+48)→8; sub 68h (+104)→0 ✓
; CreateWindowExW: 12 args → rcx..r9 (4) + 8 stack = [+20h..+58h]
; ==============================================================================
_OnCreate proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    sub     rsp, 68h

    mov     rbx, rcx            ; hwnd
    mov     g_hwndMain, rbx

    ; Per-monitor DPI, used to scale every 96-DPI-design control coordinate
    ; below. r13d is unused elsewhere in this proc and callee-saved, so it
    ; survives every call between here and the last CreateWindowExW.
    mov     rcx, rbx
    call    GetDpiForWindow
    mov     r13d, eax

    ; Init common controls
    lea     rcx, icc_ex
    call    InitCommonControlsEx

    ; Create fonts
    call    CreateFonts

    ; Detect system dark/light mode → g_isDarkMode
    call    _ReadDarkMode

    ; Apply DWM dark title bar + Mica based on g_isDarkMode
    mov     rcx, rbx
    call    ApplyDarkMode

    ; Accept drops from Explorer
    mov     edx, 1                          ; fAccept = TRUE
    mov     rcx, rbx
    call    DragAcceptFiles
    ; Allow WM_DROPFILES etc. to cross the UAC integrity boundary
    ; (elevated process can receive from non-elevated Explorer)
    xor     r9d, r9d                        ; pdwStatus = NULL
    mov     r8d, MSGFLT_ALLOW
    mov     edx, WM_DROPFILES
    mov     rcx, rbx
    call    ChangeWindowMessageFilterEx
    xor     r9d, r9d
    mov     r8d, MSGFLT_ALLOW
    mov     edx, WM_COPYDATA
    mov     rcx, rbx
    call    ChangeWindowMessageFilterEx
    xor     r9d, r9d
    mov     r8d, MSGFLT_ALLOW
    mov     edx, WM_COPYGLOBALDATA
    mov     rcx, rbx
    call    ChangeWindowMessageFilterEx

    ; Allow TaskbarCreated (registered msg, ID>=C000h) from Medium-IL Explorer
    ; to cross UIPI into this High-IL process. Fixes tray icon not appearing
    ; on logon when launched elevated via Task Scheduler.
    mov     edx, g_wmTaskbarCreated
    test    edx, edx
    jz      @oc_skip_taskbar_flt
    xor     r9d, r9d
    mov     r8d, MSGFLT_ALLOW
    mov     rcx, rbx
    call    ChangeWindowMessageFilterEx
@oc_skip_taskbar_flt:

    ; ── Toggle button: x=182 y=8 w=178 h=26 ─────────────────────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_BTN_TOGGLE
    mov     qword ptr [rsp+40h], rbx
    mov     eax, 26
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+38h], eax
    mov     eax, 178
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+30h], eax
    mov     eax, 8
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+28h], eax
    mov     eax, 182
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+20h], eax
    mov     r9d, STY_BUTTON
    lea     r8, str_btn_toggle_off
    lea     rdx, str_buttoncls
    xor     ecx, ecx
    call    CreateWindowExW
    mov     g_hwndBtnToggle, rax
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; ── Paths header static: x=20 y=10 w=157 h=22 ───────────────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_STATIC_PATHS_HDR
    mov     qword ptr [rsp+40h], rbx
    mov     eax, 22
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+38h], eax
    mov     eax, 157
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+30h], eax
    mov     eax, 10
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+28h], eax
    mov     eax, 20
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+20h], eax
    mov     r9d, STY_STATIC
    lea     r8, str_hdr_paths
    lea     rdx, str_staticcls
    xor     ecx, ecx
    call    CreateWindowExW
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; ── Add folder button: x=364 y=8 w=136 h=26 ─────────────────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_BTN_ADD_PATH
    mov     qword ptr [rsp+40h], rbx
    mov     eax, 26
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+38h], eax
    mov     eax, 136
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+30h], eax
    mov     eax, 8
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+28h], eax
    mov     eax, 364
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+20h], eax
    mov     r9d, STY_BUTTON
    lea     r8, str_btn_add_path
    lea     rdx, str_buttoncls
    xor     ecx, ecx
    call    CreateWindowExW
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; ── Remove selected button: x=504 y=8 w=139 h=26 ────────────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_BTN_REM_PATH
    mov     qword ptr [rsp+40h], rbx
    mov     eax, 26
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+38h], eax
    mov     eax, 139
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+30h], eax
    mov     eax, 8
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+28h], eax
    mov     eax, 504
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+20h], eax
    mov     r9d, STY_BUTTON
    lea     r8, str_btn_restore
    lea     rdx, str_buttoncls
    xor     ecx, ecx
    call    CreateWindowExW
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; ── Paths ListView: x=20 y=40 w=624 h=220 ───────────────────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_LV_PATHS
    mov     qword ptr [rsp+40h], rbx
    mov     eax, 220
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+38h], eax
    mov     eax, 624
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+30h], eax
    mov     eax, 40
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+28h], eax
    mov     eax, 20
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+20h], eax
    mov     r9d, (WS_CHILD_VISIBLE + LVS_REPORT + LVS_SHOWSELALWAYS)
    xor     r8d, r8d
    lea     rdx, str_listviewcls
    mov     ecx, WS_EX_CLIENTEDGE
    call    CreateWindowExW
    mov     g_hwndLvPaths, rax

    ; Full-row select + grid lines + double-buffer + row-level checkboxes
    mov     r9d, (LVS_EX_FULLROWSELECT + LVS_EX_GRIDLINES + LVS_EX_DOUBLEBUFFER + LVS_EX_CHECKBOXES)
    mov     r8d, (LVS_EX_FULLROWSELECT + LVS_EX_GRIDLINES + LVS_EX_DOUBLEBUFFER + LVS_EX_CHECKBOXES)
    mov     edx, LVM_SETEXTENDEDLISTVIEWSTYLE
    mov     rcx, g_hwndLvPaths
    call    SendMessageW

    ; Columns: Path(300) Hidden(80) Locked(80) Read-only(80) No run(80)  total=620=client
    ; Width computed into r8d BEFORE edx=index below, since idiv clobbers edx.
    mov     r9, offset str_col_path
    mov     eax, 300
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     r8d, eax
    xor     edx, edx
    mov     rcx, g_hwndLvPaths
    call    _LvAddColumn

    mov     r9, offset str_col_h
    mov     eax, 80
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     r8d, eax
    mov     edx, 1
    mov     rcx, g_hwndLvPaths
    call    _LvAddColumn

    mov     r9, offset str_col_l
    mov     eax, 80
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     r8d, eax
    mov     edx, 2
    mov     rcx, g_hwndLvPaths
    call    _LvAddColumn

    mov     r9, offset str_col_r
    mov     eax, 80
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     r8d, eax
    mov     edx, 3
    mov     rcx, g_hwndLvPaths
    call    _LvAddColumn

    mov     r9, offset str_col_x
    mov     eax, 80
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     r8d, eax
    mov     edx, 4
    mov     rcx, g_hwndLvPaths
    call    _LvAddColumn

    ; ── Trusted header: x=20 y=278 w=158 h=22 ───────────────────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_STATIC_TRUSTED_HDR
    mov     qword ptr [rsp+40h], rbx
    mov     eax, 22
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+38h], eax
    mov     eax, 158
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+30h], eax
    mov     eax, 278
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+28h], eax
    mov     eax, 20
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+20h], eax
    mov     r9d, STY_STATIC
    lea     r8, str_hdr_trusted
    lea     rdx, str_staticcls
    xor     ecx, ecx
    call    CreateWindowExW
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; ── Trusted process edit: x=182 y=276 w=178 h=26 (shorter to fit new buttons) ──
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_EDIT_TRUSTED
    mov     qword ptr [rsp+40h], rbx
    mov     eax, 26
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+38h], eax
    mov     eax, 178
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+30h], eax
    mov     eax, 276
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+28h], eax
    mov     eax, 182
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+20h], eax
    mov     r9d, (WS_CHILD_VISIBLE + WS_TABSTOP + ES_AUTOHSCROLL)
    lea     r8, str_proc_hint
    lea     rdx, str_editcls
    mov     ecx, WS_EX_CLIENTEDGE
    call    CreateWindowExW
    mov     g_hwndEditTrusted, rax
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; ── Trusted add button: x=364 y=276 w=70 h=26 ───────────────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_BTN_ADD_TRUSTED
    mov     qword ptr [rsp+40h], rbx
    mov     eax, 26
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+38h], eax
    mov     eax, 70
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+30h], eax
    mov     eax, 276
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+28h], eax
    mov     eax, 364
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+20h], eax
    mov     r9d, STY_BUTTON
    lea     r8, str_btn_add_proc
    lea     rdx, str_buttoncls
    xor     ecx, ecx
    call    CreateWindowExW
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; ── Add running process button: x=440 y=276 w=110 h=26 ───────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_BTN_ADD_RUNNING
    mov     qword ptr [rsp+40h], rbx
    mov     eax, 26
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+38h], eax
    mov     eax, 110
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+30h], eax
    mov     eax, 276
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+28h], eax
    mov     eax, 440
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+20h], eax
    mov     r9d, STY_BUTTON
    lea     r8, str_btn_add_running
    lea     rdx, str_buttoncls
    xor     ecx, ecx
    call    CreateWindowExW
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; ── Trusted remove button: x=556 y=276 w=87 h=26 ───────────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_BTN_REM_TRUSTED
    mov     qword ptr [rsp+40h], rbx
    mov     eax, 26
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+38h], eax
    mov     eax, 87
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+30h], eax
    mov     eax, 276
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+28h], eax
    mov     eax, 556
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+20h], eax
    mov     r9d, STY_BUTTON
    lea     r8, str_btn_remove_proc
    lea     rdx, str_buttoncls
    xor     ecx, ecx
    call    CreateWindowExW
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; ── Trusted ListView: x=20 y=308 w=624 h=140 (≈6 rows) ─────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_LV_TRUSTED
    mov     qword ptr [rsp+40h], rbx
    mov     eax, 140
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+38h], eax
    mov     eax, 624
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+30h], eax
    mov     eax, 308
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+28h], eax
    mov     eax, 20
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+20h], eax
    mov     r9d, (WS_CHILD_VISIBLE + LVS_REPORT + LVS_SHOWSELALWAYS)
    xor     r8d, r8d
    lea     rdx, str_listviewcls
    mov     ecx, WS_EX_CLIENTEDGE
    call    CreateWindowExW
    mov     g_hwndLvTrusted, rax

    ; No grid lines for trusted list; add row-level checkboxes
    mov     r9d, (LVS_EX_FULLROWSELECT + LVS_EX_DOUBLEBUFFER + LVS_EX_CHECKBOXES)
    mov     r8d, (LVS_EX_FULLROWSELECT + LVS_EX_DOUBLEBUFFER + LVS_EX_CHECKBOXES)
    mov     edx, LVM_SETEXTENDEDLISTVIEWSTYLE
    mov     rcx, g_hwndLvTrusted
    call    SendMessageW

    ; Column: Process name (620)
    mov     r9, offset str_col_process
    mov     eax, 620
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     r8d, eax
    xor     edx, edx
    mov     rcx, g_hwndLvTrusted
    call    _LvAddColumn

    ; ── Export button: x=20 y=454 w=90 h=22 ────────────────────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_BTN_EXPORT
    mov     qword ptr [rsp+40h], rbx
    mov     eax, 22
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+38h], eax
    mov     eax, 90
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+30h], eax
    mov     eax, 454
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+28h], eax
    mov     eax, 20
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+20h], eax
    mov     r9d, STY_BUTTON
    lea     r8, str_btn_export
    lea     rdx, str_buttoncls
    xor     ecx, ecx
    call    CreateWindowExW
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; ── Import button: x=115 y=454 w=90 h=22 ───────────────────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_BTN_IMPORT
    mov     qword ptr [rsp+40h], rbx
    mov     eax, 22
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+38h], eax
    mov     eax, 90
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+30h], eax
    mov     eax, 454
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+28h], eax
    mov     eax, 115
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+20h], eax
    mov     r9d, STY_BUTTON
    lea     r8, str_btn_import
    lea     rdx, str_buttoncls
    xor     ecx, ecx
    call    CreateWindowExW
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; ── Author / copyright static: x=20 y=482 w=624 h=18 ───────────────────
    mov     r14, g_hInstance
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], r14
    mov     qword ptr [rsp+48h], IDC_STATIC_AUTHOR
    mov     qword ptr [rsp+40h], rbx
    mov     eax, 18
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+38h], eax
    mov     eax, 624
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+30h], eax
    mov     eax, 482
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+28h], eax
    mov     eax, 20
    imul    eax, r13d
    mov     ecx, 96
    cdq
    idiv    ecx
    mov     dword ptr [rsp+20h], eax
    mov     r9d, STY_STATIC_CENTER
    lea     r8, str_author
    lea     rdx, str_staticcls
    xor     ecx, ecx
    call    CreateWindowExW
    mov     rcx, rax
    mov     rdx, g_hFontSmall
    call    _SendFont

    ; Apply theme: brush + SetWindowTheme + LV colors
    call    _ApplyThemeColors

    ; Start periodic refresh timer (polls driver status + updates ListView)
    xor     r9d, r9d                        ; lpTimerFunc = NULL (uses WM_TIMER)
    mov     r8d, TIMER_STATUS_MS            ; interval in ms
    mov     edx, TIMER_STATUS_ID
    mov     rcx, rbx
    call    SetTimer

    ; Bootstrap: read driver status, load persisted config, populate lists
    call    UpdateStatusBar                 ; sets title bar / toggle button text
    call    ConfigLoad                      ; adds saved paths to driver via IOCTL
    call    RefreshLists                    ; populates both ListViews from registry

    add     rsp, 68h
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_OnCreate endp

end

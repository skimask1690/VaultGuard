; ==============================================================================
; Vault Guard - Self-Service Management CLI Handlers + Win32 Service Runtime
;
; Author: Marek Wesołowski (wesmar)
;
; Registers / unregisters vg.exe itself as a Win32 service in the SCM.
; Also provides the service-mode entry point invoked by the SCM via /svcstart.
;
; Exports (CLI):
;   _CliServiceInstall    — vg /service install   → never returns
;   _CliServiceUninstall  — vg /service uninstall → never returns
;
; Exports (SCM runtime):
;   _SvcStart             — vg /svcstart  → StartServiceCtrlDispatcherW
;
; Required privilege: SeCreateServicePrivilege (Administrator).
; ==============================================================================

option casemap:none

include consts.inc
include globals.inc

; ── Win32 API (advapi32 / kernel32, already linked) ───────────────────────────
EXTRN OpenSCManagerW             :PROC
EXTRN CreateServiceW             :PROC
EXTRN StartServiceW              :PROC
EXTRN OpenServiceW               :PROC
EXTRN ControlService             :PROC
EXTRN DeleteService              :PROC
EXTRN CloseServiceHandle         :PROC
EXTRN GetLastError               :PROC
EXTRN GetModuleFileNameW         :PROC
EXTRN RegisterServiceCtrlHandlerExW :PROC
EXTRN SetServiceStatus           :PROC
EXTRN StartServiceCtrlDispatcherW :PROC
EXTRN ChangeServiceConfig2W      :PROC
EXTRN CreateEventW               :PROC
EXTRN WaitForSingleObject        :PROC
EXTRN SetEvent                   :PROC
EXTRN CloseHandle                :PROC
EXTRN ExitProcess                :PROC

; ── Internal (strutil.asm / cli.asm) ─────────────────────────────────────────
EXTRN WideWriteLn                :PROC
EXTRN _CliFinish                 :PROC

; ==============================================================================
; MUTABLE DATA
; ==============================================================================
.data
    align 8
    gSvcStatus          db 28 dup(0)    ; SERVICE_STATUS (7 DWORDs, 28 bytes)
    gSvcStatusHandle    dq 0            ; SERVICE_STATUS_HANDLE from RegisterServiceCtrlHandlerExW
    ghSvcStopEvent      dq 0            ; Manual-reset event; signalled on STOP/SHUTDOWN/PRESHUTDOWN

; ==============================================================================
; CONSTANT DATA
; ==============================================================================
.const

; SCM service name (short, no spaces) and display name shown in services.msc
svc_name        dw 'V','a','u','l','t','G','u','a','r','d',0
svc_display     dw 'V','a','u','l','t',' ','G','u','a','r','d',0
svc_description dw 'P','r','o','t','e','c','t','s',' ','f','o','l','d','e','r','s',' ','a','n','d'
                dw ' ','f','i','l','e','s',' ','v','i','a',' ','k','e','r','n','e','l',' '
                dw 'F','S','F','i','l','t','e','r',' ','m','i','n','i','f','i','l','t','e','r','.',0

; Result messages (follow project convention: "Verb done." / "Error: reason.")
msg_ok_svc_inst     dw 'S','e','r','v','i','c','e',' ','i','n','s','t','a','l','l','e','d','.',0
msg_ok_svc_uninst   dw 'S','e','r','v','i','c','e',' ','r','e','m','o','v','e','d','.',0

msg_err_svc_exists  dw 'E','r','r','o','r',':',' ','S','e','r','v','i','c','e',' '
                    dw 'a','l','r','e','a','d','y',' ','i','n','s','t','a','l','l','e','d','.',0

msg_err_svc_inst    dw 'E','r','r','o','r',':',' ','C','a','n','n','o','t',' '
                    dw 'c','r','e','a','t','e',' ','s','e','r','v','i','c','e','.',0

msg_err_svc_noinst  dw 'E','r','r','o','r',':',' ','S','e','r','v','i','c','e',' '
                    dw 'n','o','t',' ','i','n','s','t','a','l','l','e','d','.',0

msg_err_svc_del     dw 'E','r','r','o','r',':',' ','C','a','n','n','o','t',' '
                    dw 'd','e','l','e','t','e',' ','s','e','r','v','i','c','e','.',0

msg_err_svc_scm     dw 'E','r','r','o','r',':',' ','C','a','n','n','o','t',' '
                    dw 'o','p','e','n',' ','S','C','M','.',0

msg_err_svc_path    dw 'E','r','r','o','r',':',' ','C','a','n','n','o','t',' '
                    dw 'r','e','s','o','l','v','e',' ','e','x','e','c','u','t','a','b','l','e',' ','p','a','t','h','.',0

; ==============================================================================
; CODE
; ==============================================================================
.code

; ==============================================================================
; _CliServiceInstall  →  never returns
;
; Registers this EXE as a demand-start Win32 service named "VaultGuard".
; Binary path registered with SCM: "<exepath>" /svcstart
; On ERROR_ALREADY_EXISTS (183) reports a specific message.
;
; Stack:  push rbx,rsi,r12 (+24); sub 70h (+112); 8+136=144; 144%16=0 ✓
;
; CreateServiceW has 13 parameters; args 5–13 live on the stack.
; Register allocation:  rbx = hSCM,  rsi = scratch (path build),  r12 = LastError
; ==============================================================================
PUBLIC _CliServiceInstall
_CliServiceInstall proc
    push    rbx
    push    rsi
    push    r12
    sub     rsp, 70h

    ; ── Build quoted binary path in g_tempBuf: "<exe>" /svcstart ─────────────
    ; Layout: ['"'][path chars]['"'][' ']['/svcstart'][NUL]
    lea     rsi, g_tempBuf
    mov     word ptr [rsi], '"'         ; opening quote at char 0

    mov     r8d, MAX_PATH
    lea     rdx, [rsi + 2]              ; exe path written starting at byte +2 (char 1)
    xor     ecx, ecx                    ; hModule = NULL → this EXE
    call    GetModuleFileNameW
    test    eax, eax
    jz      @csi_path_err               ; 0 chars = failure

    ; rsi = &g_tempBuf[0], rax = chars written (path, no null)
    ; Append: " /svcstart\0  at the null terminator position
    add     rsi, 2                      ; rsi → first path char (byte +2)
    lea     rsi, [rsi + rax*2]          ; rsi → null terminator after path (advance rax WCHARs)
    ; Write closing quote + suffix
    mov     word ptr [rsi +  0], '"'
    mov     word ptr [rsi +  2], ' '
    mov     word ptr [rsi +  4], '/'
    mov     word ptr [rsi +  6], 's'
    mov     word ptr [rsi +  8], 'v'
    mov     word ptr [rsi + 10], 'c'
    mov     word ptr [rsi + 12], 's'
    mov     word ptr [rsi + 14], 't'
    mov     word ptr [rsi + 16], 'a'
    mov     word ptr [rsi + 18], 'r'
    mov     word ptr [rsi + 20], 't'
    mov     word ptr [rsi + 22], 0

    ; ── Open Service Control Manager with create rights ────────────────────────
    mov     r8d, SC_MANAGER_CREATE_SERVICE + SC_MANAGER_CONNECT
    xor     edx, edx
    xor     ecx, ecx
    call    OpenSCManagerW
    test    rax, rax
    jz      @csi_scm_err
    mov     rbx, rax                    ; rbx = hSCM

    ; ── Create the Win32 service entry ────────────────────────────────────────
    ; CreateServiceW(hSCM,
    ;   L"VaultGuard",            ← lpServiceName   (rdx)
    ;   L"Vault Guard",           ← lpDisplayName   (r8)
    ;   SERVICE_ALL_ACCESS,       ← dwDesiredAccess  (r9)
    ;   SERVICE_WIN32_OWN_PROCESS,← dwServiceType    [rsp+20h]
    ;   SERVICE_DEMAND_START,     ← dwStartType      [rsp+28h]
    ;   SERVICE_ERROR_NORMAL,     ← dwErrorControl   [rsp+30h]
    ;   g_tempBuf,                ← lpBinaryPathName [rsp+38h]
    ;   NULL, NULL, NULL,         ← group/tag/deps   [rsp+40h..50h]
    ;   NULL,                     ← lpServiceStartName = NULL (LocalSystem) [rsp+58h]
    ;   NULL)                     ← lpPassword       [rsp+60h]
    mov     qword ptr [rsp+60h], 0
    mov     qword ptr [rsp+58h], 0
    mov     qword ptr [rsp+50h], 0
    mov     qword ptr [rsp+48h], 0
    mov     qword ptr [rsp+40h], 0
    lea     rax, g_tempBuf
    mov     qword ptr [rsp+38h], rax
    mov     dword ptr [rsp+30h], SERVICE_ERROR_NORMAL
    mov     dword ptr [rsp+28h], SERVICE_DEMAND_START
    mov     dword ptr [rsp+20h], SERVICE_WIN32_OWN_PROCESS
    mov     r9d, SERVICE_ALL_ACCESS
    lea     r8, svc_display
    lea     rdx, svc_name
    mov     rcx, rbx
    call    CreateServiceW
    test    rax, rax
    jz      @csi_create_err
    mov     rsi, rax                    ; rsi = hSvc

    ; ── Set service description (SERVICE_CONFIG_DESCRIPTION = 1) ─────────────
    ; SERVICE_DESCRIPTIONW = { LPWSTR lpDescription } — one pointer, placed in shadow slot
    lea     rax, svc_description
    mov     qword ptr [rsp+20h], rax    ; SERVICE_DESCRIPTIONW.lpDescription
    lea     r8, [rsp+20h]               ; lpInfo → SERVICE_DESCRIPTIONW on stack
    mov     edx, 1                      ; SERVICE_CONFIG_DESCRIPTION
    mov     rcx, rsi                    ; hSvc
    call    ChangeServiceConfig2W       ; best-effort; ignore return value

    ; ── Start the service immediately (best-effort; ignore return value) ─────
    xor     r8d, r8d                    ; lpServiceArgVectors = NULL
    xor     edx, edx                    ; dwNumServiceArgs = 0
    mov     rcx, rsi                    ; hSvc
    call    StartServiceW

    ; ── Success ───────────────────────────────────────────────────────────────
    mov     rcx, rsi
    call    CloseServiceHandle
    mov     rcx, rbx
    call    CloseServiceHandle
    lea     rcx, msg_ok_svc_inst
    call    WideWriteLn
    xor     ecx, ecx
    call    _CliFinish

    ; ── CreateServiceW failed ─────────────────────────────────────────────────
@csi_create_err:
    call    GetLastError
    mov     r12d, eax
    mov     rcx, rbx
    call    CloseServiceHandle

    cmp     r12d, ERROR_ALREADY_EXISTS
    jne     @csi_inst_err

    lea     rcx, msg_err_svc_exists
    call    WideWriteLn
    mov     ecx, 1
    call    _CliFinish

@csi_inst_err:
    lea     rcx, msg_err_svc_inst
    call    WideWriteLn
    mov     ecx, 1
    call    _CliFinish

@csi_scm_err:
    lea     rcx, msg_err_svc_scm
    call    WideWriteLn
    mov     ecx, 1
    call    _CliFinish

@csi_path_err:
    lea     rcx, msg_err_svc_path
    call    WideWriteLn
    mov     ecx, 1
    call    _CliFinish

    add     rsp, 70h            ; unreachable — MASM requires epilogue
    pop     r12
    pop     rsi
    pop     rbx
    ret
_CliServiceInstall endp

; ==============================================================================
; _CliServiceUninstall  →  never returns
;
; Best-effort stop followed by DeleteService.
; On ERROR_SERVICE_DOES_NOT_EXIST (0x424) reports a friendly message.
;
; Stack:  push rbx,rsi,r12 (+24); sub 40h (+64); 8+88=96; 96%16=0 ✓
;
; Frame: [rsp+20h..3Bh] = SERVICE_STATUS buffer (28 B) for ControlService
; ==============================================================================
PUBLIC _CliServiceUninstall
_CliServiceUninstall proc
    push    rbx
    push    rsi
    push    r12
    sub     rsp, 40h

    ; ── Open SCM ──────────────────────────────────────────────────────────────
    mov     r8d, SC_MANAGER_CONNECT
    xor     edx, edx
    xor     ecx, ecx
    call    OpenSCManagerW
    test    rax, rax
    jz      @csu_scm_err
    mov     rbx, rax

    ; ── Open the service ──────────────────────────────────────────────────────
    mov     r8d, SERVICE_STOP + SERVICE_DELETE_SVC + SERVICE_QUERY_STATUS
    lea     rdx, svc_name
    mov     rcx, rbx
    call    OpenServiceW
    test    rax, rax
    jz      @csu_open_err
    mov     rsi, rax

    ; ── Best-effort stop (ignored — may already be stopped) ──────────────────
    lea     r8, [rsp+20h]
    mov     edx, SERVICE_CONTROL_STOP
    mov     rcx, rsi
    call    ControlService

    ; ── Delete ────────────────────────────────────────────────────────────────
    mov     rcx, rsi
    call    DeleteService
    test    eax, eax
    jz      @csu_delete_err

    ; ── Success ───────────────────────────────────────────────────────────────
    mov     rcx, rsi
    call    CloseServiceHandle
    mov     rcx, rbx
    call    CloseServiceHandle
    lea     rcx, msg_ok_svc_uninst
    call    WideWriteLn
    xor     ecx, ecx
    call    _CliFinish

@csu_delete_err:
    call    GetLastError
    mov     r12d, eax
    mov     rcx, rsi
    call    CloseServiceHandle
    mov     rcx, rbx
    call    CloseServiceHandle
    lea     rcx, msg_err_svc_del
    call    WideWriteLn
    mov     ecx, 1
    call    _CliFinish

@csu_open_err:
    call    GetLastError
    mov     r12d, eax
    mov     rcx, rbx
    call    CloseServiceHandle
    cmp     r12d, ERROR_SERVICE_DOES_NOT_EXIST
    jne     @csu_open_generic_err
    lea     rcx, msg_err_svc_noinst
    call    WideWriteLn
    mov     ecx, 1
    call    _CliFinish

@csu_open_generic_err:
    lea     rcx, msg_err_svc_scm
    call    WideWriteLn
    mov     ecx, 1
    call    _CliFinish

@csu_scm_err:
    lea     rcx, msg_err_svc_scm
    call    WideWriteLn
    mov     ecx, 1
    call    _CliFinish

    add     rsp, 40h            ; unreachable — MASM requires epilogue
    pop     r12
    pop     rsi
    pop     rbx
    ret
_CliServiceUninstall endp

; ==============================================================================
; RemoveAppService  →  rax=1/0
;
; API-only helper for full product uninstall.  Stops and deletes the VaultGuard
; Win32 service without printing or exiting; missing service is treated as clean.
;
; Stack: entry rsp%16=8; push rbx,rsi,rdi (+24)→0; sub 40h (+64)→0 ✓
; [rsp+20h..3Bh] = SERVICE_STATUS for ControlService.
; ==============================================================================
PUBLIC RemoveAppService
RemoveAppService proc
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 40h

    mov     r8d, SC_MANAGER_CONNECT
    xor     edx, edx
    xor     ecx, ecx
    call    OpenSCManagerW
    test    rax, rax
    jz      @ras_fail
    mov     rbx, rax

    mov     r8d, SERVICE_STOP + SERVICE_DELETE_SVC + SERVICE_QUERY_STATUS
    lea     rdx, svc_name
    mov     rcx, rbx
    call    OpenServiceW
    test    rax, rax
    jz      @ras_missing
    mov     rsi, rax

    lea     r8, [rsp+20h]
    mov     edx, SERVICE_CONTROL_STOP
    mov     rcx, rsi
    call    ControlService

    mov     rcx, rsi
    call    DeleteService
    mov     edi, eax

    mov     rcx, rsi
    call    CloseServiceHandle
    mov     rcx, rbx
    call    CloseServiceHandle
    test    edi, edi
    jz      @ras_fail
    mov     eax, 1
    jmp     @ras_ret

@ras_missing:
    mov     rcx, rbx
    call    CloseServiceHandle
    mov     eax, 1
    jmp     @ras_ret

@ras_fail:
    xor     eax, eax
@ras_ret:
    add     rsp, 40h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
RemoveAppService endp

; ==============================================================================
; _SvcCtrlHandler  rcx=dwCtrl  rdx=dwEventType  r8=lpEventData  r9=lpContext
;                  →  rax=0
;
; Registered with RegisterServiceCtrlHandlerExW.  Handles STOP / SHUTDOWN /
; PRESHUTDOWN by transitioning to STOP_PENDING and signalling ghSvcStopEvent.
; _SvcMain's WaitForSingleObject wakes, reports STOPPED, then returns.
;
; Stack: no pushes; sub 28h; 8+40=48; 48%16=0 ✓
; ==============================================================================
_SvcCtrlHandler proc
    sub     rsp, 28h

    cmp     ecx, SERVICE_CONTROL_PRESHUTDOWN
    je      @sch_stop
    cmp     ecx, SERVICE_CONTROL_SHUTDOWN
    je      @sch_stop
    cmp     ecx, SERVICE_CONTROL_STOP
    jne     @sch_interrogate

@sch_stop:
    ; Transition to STOP_PENDING so SCM knows we heard the request
    mov     dword ptr [gSvcStatus +  4], SERVICE_STOP_PENDING
    mov     dword ptr [gSvcStatus + 20], 1
    mov     dword ptr [gSvcStatus + 24], 3000
    mov     rcx, [gSvcStatusHandle]
    lea     rdx, gSvcStatus
    call    SetServiceStatus

    ; Wake up _SvcMain → it will report STOPPED and return
    mov     rcx, [ghSvcStopEvent]
    test    rcx, rcx
    jz      @sch_ret
    call    SetEvent
    jmp     @sch_ret

@sch_interrogate:
    ; SERVICE_CONTROL_INTERROGATE or any other code: refresh status
    mov     rcx, [gSvcStatusHandle]
    lea     rdx, gSvcStatus
    call    SetServiceStatus

@sch_ret:
    xor     eax, eax
    add     rsp, 28h
    ret
_SvcCtrlHandler endp

; ==============================================================================
; _SvcMain  rcx=dwArgc  rdx=lpszArgv  →  void  (called by SCM thread)
;
; Creates stop event, registers _SvcCtrlHandler, reports SERVICE_RUNNING,
; waits until the stop event fires, reports SERVICE_STOPPED, then returns
; to StartServiceCtrlDispatcherW (which in turn returns to _SvcStart).
;
; Stack: push rbx (+8→rsp%16=0); sub 20h (+32→rsp%16=0); 8+40=48; 48%16=0 ✓
; ==============================================================================
_SvcMain proc
    push    rbx
    sub     rsp, 20h

    ; ── Create manual-reset stop event (not initially signalled) ─────────────
    ; CreateEventW(NULL, bManualReset=TRUE, bInitialState=FALSE, NULL)
    xor     r9d, r9d
    xor     r8d, r8d
    mov     edx, 1
    xor     ecx, ecx
    call    CreateEventW
    mov     [ghSvcStopEvent], rax
    mov     rbx, rax                ; save for WaitForSingleObject + CloseHandle

    ; ── Register control handler with the SCM ────────────────────────────────
    ; RegisterServiceCtrlHandlerExW(lpServiceName, lpHandlerProc, lpContext)
    xor     r8d, r8d
    lea     rdx, _SvcCtrlHandler
    lea     rcx, svc_name
    call    RegisterServiceCtrlHandlerExW
    mov     [gSvcStatusHandle], rax

    ; ── Report SERVICE_RUNNING ────────────────────────────────────────────────
    ; dwControlsAccepted = STOP (1) | SHUTDOWN (4) | PRESHUTDOWN (100h) = 105h
    mov     dword ptr [gSvcStatus +  0], SERVICE_WIN32_OWN_PROCESS
    mov     dword ptr [gSvcStatus +  4], SERVICE_RUNNING
    mov     dword ptr [gSvcStatus +  8], 105h
    mov     dword ptr [gSvcStatus + 12], 0
    mov     dword ptr [gSvcStatus + 16], 0
    mov     dword ptr [gSvcStatus + 20], 0
    mov     dword ptr [gSvcStatus + 24], 0
    mov     rcx, [gSvcStatusHandle]
    lea     rdx, gSvcStatus
    call    SetServiceStatus

    ; ── Wait until stop is signalled ─────────────────────────────────────────
    mov     edx, INFINITE
    mov     rcx, rbx
    call    WaitForSingleObject

    ; ── Report SERVICE_STOPPED ────────────────────────────────────────────────
    mov     dword ptr [gSvcStatus +  4], SERVICE_STOPPED
    mov     dword ptr [gSvcStatus +  8], 0
    mov     dword ptr [gSvcStatus + 20], 0
    mov     dword ptr [gSvcStatus + 24], 0
    mov     rcx, [gSvcStatusHandle]
    lea     rdx, gSvcStatus
    call    SetServiceStatus

    ; ── Cleanup ───────────────────────────────────────────────────────────────
    mov     rcx, rbx
    call    CloseHandle

    add     rsp, 20h
    pop     rbx
    ret
_SvcMain endp

; ==============================================================================
; _SvcStart  →  never returns  (entry for vg.exe /svcstart invoked by SCM)
;
; Builds a SERVICE_TABLE_ENTRYW[2] on the stack and calls
; StartServiceCtrlDispatcherW.  The SCM calls _SvcMain in a dedicated thread;
; StartServiceCtrlDispatcherW blocks until the service exits, then this proc
; calls ExitProcess(0).
;
; Stack: push rbx,rsi (+16); sub 58h (+88); 8+104=112; 112%16=0 ✓
; Frame layout (from rsp):
;   [rsp+00h..1Fh]  shadow space (32 B)
;   [rsp+20h..27h]  table[0].lpServiceName → svc_name
;   [rsp+28h..2Fh]  table[0].lpServiceProc → _SvcMain
;   [rsp+30h..37h]  table[1].lpServiceName = NULL (terminator)
;   [rsp+38h..3Fh]  table[1].lpServiceProc = NULL
;   [rsp+40h..57h]  pad
; ==============================================================================
PUBLIC _SvcStart
_SvcStart proc
    push    rbx
    push    rsi
    sub     rsp, 58h

    ; table[0] = { svc_name, _SvcMain }
    lea     rax, svc_name
    mov     qword ptr [rsp+20h], rax
    lea     rax, _SvcMain
    mov     qword ptr [rsp+28h], rax
    ; table[1] = { NULL, NULL }  — required SCM terminator
    mov     qword ptr [rsp+30h], 0
    mov     qword ptr [rsp+38h], 0

    lea     rcx, [rsp+20h]
    call    StartServiceCtrlDispatcherW  ; blocks until service exits

    xor     ecx, ecx
    call    ExitProcess

    add     rsp, 58h            ; unreachable — MASM requires epilogue
    pop     rsi
    pop     rbx
    ret
_SvcStart endp

end

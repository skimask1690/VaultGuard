; ==============================================================================
; Vault Guard - Drop Handler
;
; Author: Marek Wesołowski (wesmar)
; Purpose: WM_DROPFILES handler + .lnk shortcut resolution via IShellLink COM.
;
; Exported:
;   _OnDropFiles(rcx=HDROP)  → void
; ==============================================================================

option casemap:none

include consts.inc
include globals.inc

; ── Win32 ─────────────────────────────────────────────────────────────────────
EXTRN CoInitialize              :PROC
EXTRN CoUninitialize            :PROC
EXTRN CoCreateInstance          :PROC
EXTRN DragQueryFileW            :PROC
EXTRN DragFinish                :PROC

; ── Sibling modules ───────────────────────────────────────────────────────────
EXTRN wcslen_p                  :PROC   ; strutil.asm
EXTRN wcscmp_ci                 :PROC   ; strutil.asm
EXTRN RefreshLists              :PROC   ; listview.asm

EXTRN g_pendingPath             :WORD   ; handlers.asm

; ==============================================================================
; CONSTANT STRINGS
; ==============================================================================
.const

str_ext_lnk         dw '.','l','n','k',0

; COM GUIDs for Windows shortcut resolution
CLSID_ShellLink dd 00021401h
                dw 0000h, 0000h
                db 0C0h, 00h, 00h, 00h, 00h, 00h, 00h, 46h
IID_IShellLinkW dd 000214F9h
                dw 0000h, 0000h
                db 0C0h, 00h, 00h, 00h, 00h, 00h, 00h, 46h
IID_IPersistFile dd 0000010Bh
                 dw 0000h, 0000h
                 db 0C0h, 00h, 00h, 00h, 00h, 00h, 00h, 46h

; ==============================================================================
; CODE
; ==============================================================================
.code

PUBLIC _OnDropFiles

; ==============================================================================
; ResolveLnkPath  rcx=.lnk path  rdx=out target path  →  rax=1 ok / 0 fail
; Uses IShellLinkW/IPersistFile to resolve a shortcut target.
; Stack: entry rsp%16=8; push 7 regs (+56)→0; sub 70h (+112)→0 ✓
; Locals: [rsp+40h]=IShellLink*, [rsp+48h]=IPersistFile*.
; ==============================================================================
ResolveLnkPath proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 70h

    mov     r12, rcx                    ; input .lnk path
    mov     r13, rdx                    ; output target path
    xor     r15d, r15d                  ; result
    mov     word ptr [r13], 0
    mov     qword ptr [rsp+40h], 0
    mov     qword ptr [rsp+48h], 0

    xor     ecx, ecx                            ; pvReserved = NULL
    call    CoInitialize                        ; must succeed (S_OK or S_FALSE)
    test    eax, eax
    js      @rlp_done                           ; hard failure — COM unavailable

    lea     rax, [rsp+40h]
    mov     qword ptr [rsp+20h], rax            ; ppv → &IShellLink*
    lea     r9, IID_IShellLinkW
    mov     r8d, CLSCTX_INPROC_SERVER           ; in-process COM server
    xor     edx, edx                            ; pUnkOuter = NULL
    lea     rcx, CLSID_ShellLink
    call    CoCreateInstance                    ; create IShellLinkW instance
    test    eax, eax
    js      @rlp_uninit

    mov     rbx, qword ptr [rsp+40h]            ; IShellLink*
    mov     rax, qword ptr [rbx]                ; vtable ptr
    lea     r8, [rsp+48h]                       ; ppv → &IPersistFile*
    lea     rdx, IID_IPersistFile
    mov     rcx, rbx
    call    qword ptr [rax]                     ; QueryInterface(IID_IPersistFile)
    test    eax, eax
    js      @rlp_release_link

    mov     rbx, qword ptr [rsp+48h]            ; IPersistFile*
    mov     rax, qword ptr [rbx]                ; vtable ptr
    xor     r8d, r8d                            ; dwMode = STGM_READ
    mov     rdx, r12                            ; pszFileName = .lnk path
    mov     rcx, rbx
    call    qword ptr [rax+40]                  ; IPersistFile::Load — open .lnk
    test    eax, eax
    js      @rlp_release_both

    mov     rbx, qword ptr [rsp+40h]            ; IShellLink* (refetch after Load)
    mov     rax, qword ptr [rbx]                ; vtable ptr
    mov     qword ptr [rsp+20h], 0              ; fFlags = 0 (raw path)
    xor     r9d, r9d                            ; pfd = NULL (no WIN32_FIND_DATA)
    mov     r8d, MAX_PATH                       ; cch output buffer limit
    mov     rdx, r13                            ; pszFile = output buffer
    mov     rcx, rbx
    call    qword ptr [rax+24]                  ; IShellLinkW::GetPath → target
    test    eax, eax
    js      @rlp_release_both

    mov     rcx, r13
    call    wcslen_p
    test    eax, eax
    jz      @rlp_release_both
    mov     r15d, 1

@rlp_release_both:
    mov     rbx, qword ptr [rsp+48h]            ; IPersistFile*
    test    rbx, rbx
    jz      @rlp_release_link
    mov     rax, qword ptr [rbx]
    mov     rcx, rbx
    call    qword ptr [rax+16]                  ; IPersistFile::Release

@rlp_release_link:
    mov     rbx, qword ptr [rsp+40h]            ; IShellLink*
    test    rbx, rbx
    jz      @rlp_uninit
    mov     rax, qword ptr [rbx]
    mov     rcx, rbx
    call    qword ptr [rax+16]                  ; IShellLink::Release

@rlp_uninit:
    call    CoUninitialize

@rlp_done:
    mov     eax, r15d
    add     rsp, 70h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
ResolveLnkPath endp

; ==============================================================================
; _OnDropFiles  rcx=HDROP  →  void
; First dropped path becomes a pending GUI row. .lnk files are resolved.
; Stack: entry rsp%16=8; push 4 regs (+32)→8; sub 38h (+56)→0 ✓
; ==============================================================================
_OnDropFiles proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 38h

    mov     rbx, rcx                    ; HDROP

    mov     r9d, 520                    ; cch = buffer size in WCHARs
    lea     r8, g_pathBuf               ; lpszFile = output buffer
    xor     edx, edx                    ; iFile = 0 (first dropped file)
    mov     rcx, rbx
    call    DragQueryFileW              ; fetch first dropped path into g_pathBuf
    test    eax, eax
    jz      @odf_finish                 ; 0 chars returned → nothing to do

    lea     rsi, g_pathBuf              ; default: original dropped path

    lea     rcx, g_pathBuf
    call    wcslen_p
    mov     r12, rax                    ; r12 = path length in WCHARs
    cmp     r12, 4
    jl      @odf_copy_pending           ; too short to have .lnk extension

    lea     rcx, g_pathBuf
    lea     rcx, [rcx + r12*2 - 8]     ; point at last 4 WCHARs of path
    lea     rdx, str_ext_lnk            ; L".lnk\0"
    call    wcscmp_ci                   ; case-insensitive compare
    test    eax, eax
    jnz     @odf_copy_pending           ; not a .lnk → use path as-is

    lea     r8, g_statusBuf
    lea     rdx, g_tempBuf
    lea     rcx, g_pathBuf
    call    ResolveLnkPath
    test    eax, eax
    jz      @odf_copy_pending
    cmp     word ptr [g_tempBuf], 0
    je      @odf_copy_pending
    lea     rsi, g_tempBuf

@odf_copy_pending:
    lea     rdi, g_pendingPath          ; destination
    xor     ecx, ecx                    ; char index
@odf_copy_loop:
    movzx   eax, word ptr [rsi + rcx*2] ; load src WCHAR
    mov     word ptr [rdi + rcx*2], ax  ; store to g_pendingPath
    test    ax, ax
    jz      @odf_refresh                ; null terminator copied — done
    inc     ecx
    cmp     ecx, MAX_PATH
    jl      @odf_copy_loop
    mov     word ptr [rdi + rcx*2], 0   ; force-terminate at MAX_PATH

@odf_refresh:
    call    RefreshLists

@odf_finish:
    mov     rcx, rbx
    call    DragFinish

    add     rsp, 38h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_OnDropFiles endp

end

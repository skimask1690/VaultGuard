; ==============================================================================
; Vault Guard - GUI Export / Import Configuration
;
; Author: Marek Wesołowski (wesmar)
;
; File format (UTF-16 LE, BOM 0xFEFF):
;   [Paths]<CR><LF>
;   <path>=<flags_decimal><CR><LF>
;   [Trusted]<CR><LF>
;   <name>=<data_decimal><CR><LF>
;
; Exported:
;   GuiExportConfig(rcx=hwndOwner)  →  void
;   GuiImportConfig(rcx=hwndOwner)  →  void
;
; After GuiImportConfig returns, caller must call ConfigLoad + RefreshLists.
; ==============================================================================

option casemap:none

include consts.inc
include globals.inc

EXTRN GetOpenFileNameW          :PROC
EXTRN GetSaveFileNameW          :PROC
EXTRN CreateFileW               :PROC
EXTRN WriteFile                 :PROC
EXTRN ReadFile                  :PROC
EXTRN CloseHandle               :PROC
EXTRN MessageBoxW               :PROC
EXTRN RegOpenKeyExW             :PROC
EXTRN RegCreateKeyExW           :PROC
EXTRN RegEnumValueW             :PROC
EXTRN RegSetValueExW            :PROC
EXTRN RegCloseKey               :PROC

; ==============================================================================
.const

ie_str_paths_key dw 'S','o','f','t','w','a','r','e','\','V','G','\','P','a','t','h','s',0
ie_str_trust_key dw 'S','o','f','t','w','a','r','e','\','V','G','\','T','r','u','s','t','e','d',0

ie_str_sec_paths dw '[','P','a','t','h','s',']',0Dh,0Ah,0
ie_str_sec_trust dw '[','T','r','u','s','t','e','d',']',0Dh,0Ah,0

; section header tags (without CRLF, for comparison)
ie_tag_paths    dw '[','P','a','t','h','s',']',0
ie_tag_trusted  dw '[','T','r','u','s','t','e','d',']',0

ie_str_eq       dw '=',0
ie_str_crlf     dw 0Dh,0Ah,0

ie_str_ok_export dw 'S','e','t','t','i','n','g','s',' ','e','x','p','o','r','t','e','d','.',0
ie_str_ok_import dw 'S','e','t','t','i','n','g','s',' ','i','m','p','o','r','t','e','d','.',0
ie_str_caption  dw 'V','a','u','l','t','G','u','a','r','d',0

ie_str_flt_save dw 'V','G',' ','C','o','n','f','i','g',' ','(','*','.','v','g','c',')',0
                dw '*','.','v','g','c',0
                dw 0
ie_str_flt_open dw 'V','G',' ','C','o','n','f','i','g',' ','(','*','.','v','g','c',')',0
                dw '*','.','v','g','c',0
                dw 0
ie_str_ext      dw 'v','g','c',0
ie_str_ttl_save dw 'E','x','p','o','r','t',' ','s','e','t','t','i','n','g','s',0
ie_str_ttl_open dw 'I','m','p','o','r','t',' ','s','e','t','t','i','n','g','s',0

; ==============================================================================
.data
    align 8
ie_ofn  db OFN_SIZE dup(0)          ; OPENFILENAMEW struct

.data?
    align 8
    ie_file_path    dw (MAX_PATH+4) dup(?)
    ie_hkey         dq ?
    ie_disp         dd ?
    ie_type         dd ?
    ie_namelen      dd ?
    ie_datalen      dd ?
    ie_flags        dd ?
    ie_xfer         dd ?
    ie_name_buf     dw 520 dup(?)
    ie_line_buf     dw 520 dup(?)   ; import line scratch
    ie_read_buf     db 131072 dup(?); 128 KB read buffer

; ==============================================================================
.code

PUBLIC GuiExportConfig
PUBLIC GuiImportConfig

; ==============================================================================
; _IeWcLen  rcx=pWChar  →  eax=char_count (not incl. null)
; Stack: no pushes + sub 28h (40)→0; 8-40%16=8-8=0 ✓
; ==============================================================================
_IeWcLen proc
    sub     rsp, 28h
    xor     eax, eax
@wl_l:
    cmp     word ptr [rcx + rax * 2], 0
    je      @wl_d
    inc     eax
    jmp     @wl_l
@wl_d:
    add     rsp, 28h
    ret
_IeWcLen endp

; ==============================================================================
; _IeWcsEq  rcx=a  rdx=b  →  eax=1 equal / 0 not equal
; Stack: no pushes + sub 28h ✓
; ==============================================================================
_IeWcsEq proc
    push    rsi
    push    rdi
    sub     rsp, 28h
    mov     rsi, rcx
    mov     rdi, rdx
@we_l:
    mov     ax, word ptr [rsi]
    cmp     ax, word ptr [rdi]
    jne     @we_ne
    test    ax, ax
    jz      @we_eq
    add     rsi, 2
    add     rdi, 2
    jmp     @we_l
@we_eq:
    add     rsp, 28h
    pop     rdi
    pop     rsi
    mov     eax, 1
    ret
@we_ne:
    add     rsp, 28h
    pop     rdi
    pop     rsi
    xor     eax, eax
    ret
_IeWcsEq endp

; ==============================================================================
; _IeStrToDword  rcx=pWChar  →  eax=value
; Stack: no pushes + sub 28h ✓
; ==============================================================================
_IeStrToDword proc
    sub     rsp, 28h
    xor     eax, eax
@sd_l:
    movzx   edx, word ptr [rcx]
    test    dx, dx
    jz      @sd_r
    sub     edx, '0'
    cmp     edx, 9
    ja      @sd_r
    imul    eax, eax, 10
    add     eax, edx
    add     rcx, 2
    jmp     @sd_l
@sd_r:
    add     rsp, 28h
    ret
_IeStrToDword endp

; ==============================================================================
; _IeDwordToStr  rcx=outBuf  edx=value  →  void
; Writes decimal WCHAR string (null-terminated) to outBuf (needs ≥12 WCHARs).
; Stack: 2 pushes (rbx,rsi) + sub 38h (56) = 72; 8-72%16=8-8=0 ✓
; Local digit scratch at [rsp+20h..37h] = 24 bytes = 12 WCHARs
; ==============================================================================
_IeDwordToStr proc
    push    rbx
    push    rsi
    sub     rsp, 38h

    mov     rbx, rcx                ; outBuf
    mov     eax, edx                ; value
    xor     ecx, ecx                ; digit count

    test    eax, eax
    jnz     @dt_l
    mov     word ptr [rbx], '0'
    mov     word ptr [rbx+2], 0
    jmp     @dt_r

@dt_l:
    test    eax, eax
    jz      @dt_rev
    xor     edx, edx
    mov     esi, 10
    div     esi
    add     edx, '0'
    mov     word ptr [rsp+20h + rcx*2], dx ; digit (reversed order) in local area
    inc     ecx
    jmp     @dt_l

@dt_rev:
    xor     esi, esi
@dt_rl:
    test    ecx, ecx
    jz      @dt_rd
    dec     ecx
    movzx   eax, word ptr [rsp+20h + rcx*2]
    mov     word ptr [rbx + rsi*2], ax
    inc     esi
    jmp     @dt_rl
@dt_rd:
    mov     word ptr [rbx + rsi*2], 0

@dt_r:
    add     rsp, 38h
    pop     rsi
    pop     rbx
    ret
_IeDwordToStr endp

; ==============================================================================
; _IeInitOfn  rcx=hwndOwner  rdx=titlePtr  r8=filterPtr  r9=defExtPtr  →  void
; Zeroes ie_ofn and fills basic fields.
; Stack: 2 pushes + sub 28h = 56; 8-56%16=8-8=0 ✓
; ==============================================================================
_IeInitOfn proc
    push    rbx
    push    rsi
    sub     rsp, 28h

    mov     rbx, rcx
    mov     rsi, rdx            ; title
    ; r8=filter, r9=defExt (live)

    ; Zero ie_ofn
    lea     rcx, ie_ofn
    xor     eax, eax
    mov     r10d, OFN_SIZE / 8
@io_z:
    mov     qword ptr [rcx], rax
    add     rcx, 8
    dec     r10d
    jnz     @io_z

    lea     r10, ie_ofn
    mov     dword ptr [r10 + OFN_lStructSize], OFN_SIZE
    mov     qword ptr [r10 + OFN_hwndOwner],   rbx
    mov     qword ptr [r10 + OFN_lpstrFilter],  r8
    mov     qword ptr [r10 + OFN_lpstrTitle],   rsi
    mov     qword ptr [r10 + OFN_lpstrDefExt],  r9
    lea     rax, ie_file_path
    mov     word ptr [rax], 0
    mov     qword ptr [r10 + OFN_lpstrFile],   rax
    mov     dword ptr [r10 + OFN_nMaxFile],   (MAX_PATH + 4)

    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret
_IeInitOfn endp

; ==============================================================================
; _IeWriteWf  rcx=hFile  rdx=pWChar  r8d=nBytes  →  void
; Raw WriteFile wrapper. r8d=0 → write nothing.
; Stack: 3 pushes(rbx,rsi,rdi)+sub 38h=56+24=80; wait 3*8=24, 24%16=8.
; After 3 pushes: rsp%16=8-8=0. sub 38h=56, 56%16=8. 0-8=-8 mod16=8. WRONG.
; Use 4 pushes + sub 28h: 4*8=32, 32%16=0. After 4 pushes: rsp%16=8-0=8.
; sub 28h=40, 40%16=8. 8-8=0 ✓
; ==============================================================================
_IeWriteWf proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 28h        ; 4 pushes(32)+28h(40)=72; 8-72%16=8-8=0 ✓

    mov     rbx, rcx        ; hFile
    mov     rsi, rdx        ; buffer
    mov     edi, r8d        ; nBytes

    test    edi, edi
    jz      @iwf_r

    mov     qword ptr [rsp+20h], 0      ; lpOverlapped=NULL
    lea     r9, ie_xfer
    mov     r8d, edi
    mov     rdx, rsi
    mov     rcx, rbx
    call    WriteFile

@iwf_r:
    add     rsp, 28h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
_IeWriteWf endp

; ==============================================================================
; GuiExportConfig  rcx=hwndOwner  →  void
; Stack: 5 pushes + sub 60h = 40+96=136; 8-136%16=8-8=0 ✓
; Locals: [rsp+40h..5Fh] = 32B → decimal WCHAR buf at [rsp+40h] (12 WCHARs=24B)
;         [rsp+58h] = BOM WORD scratch (2B within 32B local area)
; ==============================================================================
GuiExportConfig proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    sub     rsp, 60h

    mov     rbx, rcx                ; hwndOwner

    ; Init OFN for save dialog
    mov     r9, offset ie_str_ext
    mov     r8, offset ie_str_flt_save
    mov     rdx, offset ie_str_ttl_save
    mov     rcx, rbx
    call    _IeInitOfn

    lea     r10, ie_ofn
    mov     dword ptr [r10 + OFN_Flags], (OFN_OVERWRITEPROMPT + OFN_EXPLORER + OFN_HIDEREADONLY)

    lea     rcx, ie_ofn
    call    GetSaveFileNameW
    test    eax, eax
    jz      @gec_ret

    ; CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
    mov     qword ptr [rsp+30h], 0              ; hTemplateFile
    mov     dword ptr [rsp+28h], FILE_ATTRIBUTE_NORMAL
    mov     dword ptr [rsp+20h], CREATE_ALWAYS
    xor     r9d, r9d
    xor     r8d, r8d
    mov     edx, GENERIC_WRITE
    lea     rcx, ie_file_path
    call    CreateFileW
    cmp     rax, INVALID_HANDLE_VALUE
    je      @gec_ret
    mov     rdi, rax                            ; rdi = hFile

    ; Write UTF-16 LE BOM (0xFEFF) — 2 bytes
    mov     word ptr [rsp+58h], 0FEFFh
    mov     qword ptr [rsp+20h], 0
    lea     r9, ie_xfer
    mov     r8d, 2
    lea     rdx, [rsp+58h]
    mov     rcx, rdi
    call    WriteFile

    ; ── Export Paths ──────────────────────────────────────────────────────────
    ; Write "[Paths]\r\n"
    mov     rcx, rdi
    lea     rdx, ie_str_sec_paths
    mov     r8d, 18                             ; "[Paths]\r\n" = 9 WCHARs = 18 bytes
    call    _IeWriteWf

    ; Open HKCU\Software\VG\Paths
    lea     rax, ie_hkey
    mov     qword ptr [rsp+20h], rax
    mov     r9d, KEY_READ
    xor     r8d, r8d
    lea     rdx, ie_str_paths_key
    mov     rcx, HKEY_CURRENT_USER
    call    RegOpenKeyExW
    test    eax, eax
    jnz     @gec_do_trusted

    mov     r12, qword ptr [ie_hkey]            ; r12 = hKey paths
    xor     r13d, r13d                          ; enum index

@gec_p_loop:
    mov     dword ptr [ie_namelen], 520
    mov     dword ptr [ie_datalen], 4

    lea     rax, ie_datalen
    mov     qword ptr [rsp+38h], rax            ; lpcbData
    lea     rax, ie_flags
    mov     qword ptr [rsp+30h], rax            ; lpData
    lea     rax, ie_type
    mov     qword ptr [rsp+28h], rax            ; lpType
    mov     qword ptr [rsp+20h], 0              ; lpReserved
    lea     r9, ie_namelen
    lea     r8, ie_name_buf
    mov     edx, r13d
    mov     rcx, r12
    call    RegEnumValueW
    cmp     eax, ERROR_NO_MORE_ITEMS
    je      @gec_p_done
    test    eax, eax
    jnz     @gec_p_next

    ; Write name (ie_namelen WCHARs = ie_namelen*2 bytes)
    mov     eax, dword ptr [ie_namelen]
    shl     eax, 1
    mov     rcx, rdi
    lea     rdx, ie_name_buf
    mov     r8d, eax
    call    _IeWriteWf

    ; Write "="
    mov     rcx, rdi
    lea     rdx, ie_str_eq
    mov     r8d, 2                              ; 1 WCHAR = 2 bytes
    call    _IeWriteWf

    ; Convert flags to decimal and write
    mov     edx, dword ptr [ie_flags]
    lea     rcx, [rsp+40h]
    call    _IeDwordToStr

    lea     rcx, [rsp+40h]
    call    _IeWcLen
    shl     eax, 1
    mov     rcx, rdi
    lea     rdx, [rsp+40h]
    mov     r8d, eax
    call    _IeWriteWf

    ; Write "\r\n"
    mov     rcx, rdi
    lea     rdx, ie_str_crlf
    mov     r8d, 4                              ; 2 WCHARs = 4 bytes
    call    _IeWriteWf

@gec_p_next:
    inc     r13d
    jmp     @gec_p_loop

@gec_p_done:
    mov     rcx, r12
    call    RegCloseKey

    ; ── Export Trusted ────────────────────────────────────────────────────────
@gec_do_trusted:
    ; Write "[Trusted]\r\n"
    mov     rcx, rdi
    lea     rdx, ie_str_sec_trust
    mov     r8d, 22                             ; "[Trusted]\r\n" = 11 WCHARs = 22 bytes
    call    _IeWriteWf

    lea     rax, ie_hkey
    mov     qword ptr [rsp+20h], rax
    mov     r9d, KEY_READ
    xor     r8d, r8d
    lea     rdx, ie_str_trust_key
    mov     rcx, HKEY_CURRENT_USER
    call    RegOpenKeyExW
    test    eax, eax
    jnz     @gec_close_file

    mov     r12, qword ptr [ie_hkey]
    xor     r13d, r13d

@gec_t_loop:
    mov     dword ptr [ie_namelen], 520
    mov     dword ptr [ie_datalen], 4

    lea     rax, ie_datalen
    mov     qword ptr [rsp+38h], rax
    lea     rax, ie_flags
    mov     qword ptr [rsp+30h], rax
    lea     rax, ie_type
    mov     qword ptr [rsp+28h], rax
    mov     qword ptr [rsp+20h], 0
    lea     r9, ie_namelen
    lea     r8, ie_name_buf
    mov     edx, r13d
    mov     rcx, r12
    call    RegEnumValueW
    cmp     eax, ERROR_NO_MORE_ITEMS
    je      @gec_t_done
    test    eax, eax
    jnz     @gec_t_next

    mov     eax, dword ptr [ie_namelen]
    shl     eax, 1
    mov     rcx, rdi
    lea     rdx, ie_name_buf
    mov     r8d, eax
    call    _IeWriteWf

    mov     rcx, rdi
    lea     rdx, ie_str_eq
    mov     r8d, 2
    call    _IeWriteWf

    mov     edx, dword ptr [ie_flags]
    lea     rcx, [rsp+40h]
    call    _IeDwordToStr

    lea     rcx, [rsp+40h]
    call    _IeWcLen
    shl     eax, 1
    mov     rcx, rdi
    lea     rdx, [rsp+40h]
    mov     r8d, eax
    call    _IeWriteWf

    mov     rcx, rdi
    lea     rdx, ie_str_crlf
    mov     r8d, 4
    call    _IeWriteWf

@gec_t_next:
    inc     r13d
    jmp     @gec_t_loop

@gec_t_done:
    mov     rcx, r12
    call    RegCloseKey

@gec_close_file:
    mov     rcx, rdi
    call    CloseHandle

    mov     r9d, MB_OK + MB_ICONINFORMATION
    lea     r8, ie_str_caption
    lea     rdx, ie_str_ok_export
    mov     rcx, rbx
    call    MessageBoxW

@gec_ret:
    add     rsp, 60h
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
GuiExportConfig endp

; ==============================================================================
; GuiImportConfig  rcx=hwndOwner  →  void
; Reads a .vgc file (UTF-16 LE) and writes all entries to the registry.
; Stack: 5 pushes + sub 60h = 136; 8-136%16=8-8=0 ✓
; Locals: [rsp+40h..5Fh] = 32B
;   r13 = hRegKey for current section (or 0)
;   [rsp+40h] DWORD = section mode (0=none, 1=paths, 2=trusted)
; ==============================================================================
GuiImportConfig proc
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    sub     rsp, 60h

    mov     rbx, rcx                ; hwndOwner
    xor     r13d, r13d              ; hRegKey = NULL (none open)

    ; Init OFN for open dialog
    mov     r9, offset ie_str_ext
    mov     r8, offset ie_str_flt_open
    mov     rdx, offset ie_str_ttl_open
    mov     rcx, rbx
    call    _IeInitOfn

    lea     r10, ie_ofn
    mov     dword ptr [r10 + OFN_Flags], (OFN_PATHMUSTEXIST + OFN_FILEMUSTEXIST + OFN_EXPLORER + OFN_HIDEREADONLY)

    lea     rcx, ie_ofn
    call    GetOpenFileNameW
    test    eax, eax
    jz      @gic_ret

    ; Open file for reading
    mov     qword ptr [rsp+30h], 0
    mov     dword ptr [rsp+28h], FILE_ATTRIBUTE_NORMAL
    mov     dword ptr [rsp+20h], OPEN_EXISTING
    xor     r9d, r9d
    xor     r8d, r8d
    mov     edx, GENERIC_READ
    lea     rcx, ie_file_path
    call    CreateFileW
    cmp     rax, INVALID_HANDLE_VALUE
    je      @gic_ret
    mov     rdi, rax                ; rdi = hFile

    ; Read file into ie_read_buf (up to 128 KB)
    mov     qword ptr [rsp+20h], 0
    lea     r9, ie_xfer
    mov     r8d, 131072
    lea     rdx, ie_read_buf
    mov     rcx, rdi
    call    ReadFile

    mov     rcx, rdi
    call    CloseHandle

    ; Check how many bytes were read
    mov     eax, dword ptr [ie_xfer]
    test    eax, eax
    jz      @gic_close_keys
    and     eax, 0FFFFFFFEh     ; round down to WCHAR boundary

    ; rsi = current WCHAR ptr
    ; rdi = end WCHAR ptr
    lea     rsi, ie_read_buf
    lea     rdi, ie_read_buf
    shr     eax, 1              ; byte count → WCHAR count
    lea     rdi, [rdi + rax*2]  ; rdi = past last WCHAR

    ; Skip BOM if present
    cmp     word ptr [rsi], 0FEFFh
    jne     @gic_parse
    add     rsi, 2

@gic_parse:
    ; For each line in the file:
    ;   copy to ie_line_buf, null-terminate, trim \r
    ;   check for section header or key=value
    cmp     rsi, rdi
    jae     @gic_close_keys

    ; Copy line to ie_line_buf
    lea     r12, ie_line_buf
    xor     r8d, r8d            ; line WCHAR count
@gic_copy_line:
    cmp     rsi, rdi
    jae     @gic_line_end
    movzx   eax, word ptr [rsi]
    add     rsi, 2
    cmp     eax, 0Ah            ; '\n'
    je      @gic_line_end
    cmp     eax, 0Dh            ; '\r' — skip
    je      @gic_copy_line
    test    eax, eax
    jz      @gic_line_end
    cmp     r8d, 519
    jge     @gic_copy_line
    mov     word ptr [r12 + r8*2], ax
    inc     r8d
    jmp     @gic_copy_line
@gic_line_end:
    mov     word ptr [r12 + r8*2], 0    ; null-terminate

    ; Skip blank lines
    test    r8d, r8d
    jz      @gic_parse

    ; Check: section header?
    cmp     word ptr [ie_line_buf], '['
    jne     @gic_keyval

    ; Is it "[Paths]"?
    lea     rcx, ie_line_buf
    lea     rdx, ie_tag_paths
    call    _IeWcsEq
    test    eax, eax
    jz      @gic_try_trusted

    ; Close previous section key if open
    test    r13, r13
    jz      @gic_open_paths
    mov     rcx, r13
    call    RegCloseKey
    xor     r13d, r13d

@gic_open_paths:
    ; Create/open Paths key for writing
    lea     rax, ie_disp
    mov     qword ptr [rsp+40h], rax            ; arg9: lpdwDisposition
    lea     rax, ie_hkey
    mov     qword ptr [rsp+38h], rax            ; arg8: phkResult
    mov     qword ptr [rsp+30h], 0              ; arg7: lpSecurityAttributes=NULL
    mov     dword ptr [rsp+28h], KEY_ALL_ACCESS ; arg6: samDesired
    mov     dword ptr [rsp+20h], REG_OPTION_NON_VOLATILE ; arg5: dwOptions
    xor     r9d, r9d                            ; arg4: lpClass=NULL
    xor     r8d, r8d                            ; arg3: Reserved=0
    lea     rdx, ie_str_paths_key
    mov     rcx, HKEY_CURRENT_USER
    call    RegCreateKeyExW
    test    eax, eax
    jnz     @gic_parse
    mov     r13, qword ptr [ie_hkey]
    jmp     @gic_parse

@gic_try_trusted:
    lea     rcx, ie_line_buf
    lea     rdx, ie_tag_trusted
    call    _IeWcsEq
    test    eax, eax
    jz      @gic_parse          ; unknown section header, skip

    test    r13, r13
    jz      @gic_open_trusted
    mov     rcx, r13
    call    RegCloseKey
    xor     r13d, r13d

@gic_open_trusted:
    lea     rax, ie_disp
    mov     qword ptr [rsp+40h], rax            ; arg9: lpdwDisposition
    lea     rax, ie_hkey
    mov     qword ptr [rsp+38h], rax            ; arg8: phkResult
    mov     qword ptr [rsp+30h], 0              ; arg7: lpSecurityAttributes=NULL
    mov     dword ptr [rsp+28h], KEY_ALL_ACCESS ; arg6: samDesired
    mov     dword ptr [rsp+20h], REG_OPTION_NON_VOLATILE ; arg5: dwOptions
    xor     r9d, r9d                            ; arg4: lpClass=NULL
    xor     r8d, r8d                            ; arg3: Reserved=0
    lea     rdx, ie_str_trust_key
    mov     rcx, HKEY_CURRENT_USER
    call    RegCreateKeyExW
    test    eax, eax
    jnz     @gic_parse
    mov     r13, qword ptr [ie_hkey]
    jmp     @gic_parse

@gic_keyval:
    ; No open section key → skip
    test    r13, r13
    jz      @gic_parse

    ; Find '=' in ie_line_buf → split name and value
    lea     r12, ie_line_buf
    xor     r8d, r8d
@gic_find_eq:
    movzx   eax, word ptr [r12 + r8*2]
    test    eax, eax
    jz      @gic_parse          ; no '=' found → skip line
    cmp     eax, '='
    je      @gic_split
    inc     r8d
    jmp     @gic_find_eq

@gic_split:
    ; r8d = index of '='
    mov     word ptr [r12 + r8*2], 0    ; null-terminate name in place
    inc     r8d                          ; advance past '='
    lea     rcx, [r12 + r8*2]           ; value string ptr
    call    _IeStrToDword               ; eax = parsed value
    mov     dword ptr [ie_flags], eax

    ; RegSetValueExW(r13=hKey, r12=nameBuf, 0, REG_DWORD, &ie_flags, 4)
    mov     dword ptr [rsp+28h], 4
    lea     rax, ie_flags
    mov     qword ptr [rsp+20h], rax
    mov     r9d, REG_DWORD
    xor     r8d, r8d
    mov     rdx, r12
    mov     rcx, r13
    call    RegSetValueExW

    jmp     @gic_parse

@gic_close_keys:
    test    r13, r13
    jz      @gic_notify
    mov     rcx, r13
    call    RegCloseKey

@gic_notify:
    mov     r9d, MB_OK + MB_ICONINFORMATION
    lea     r8, ie_str_caption
    lea     rdx, ie_str_ok_import
    mov     rcx, rbx
    call    MessageBoxW

@gic_ret:
    add     rsp, 60h
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
GuiImportConfig endp

end

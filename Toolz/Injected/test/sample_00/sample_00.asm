option casemap :none

IFDEF RAX

extrn ExitProcess: PROC
extrn MessageBoxA: PROC

; FAKE
extern __imp_GetMessageA            : PROC
extern __imp_CreateProcessA         : PROC
extern __imp_DeleteObject           : PROC
extern __imp_GetStockObject         : PROC
extern __imp_SelectObject           : PROC
extern __imp_GetModuleInformation   : PROC
extern __imp_GetProcessMemoryInfo   : PROC
extern __imp_EmptyWorkingSet        : PROC
extern __imp_LeaveCriticalSection   : PROC
extern __imp_SHGetMalloc            : PROC
extern __imp_SHGetFileInfoW         : PROC

ELSE

.486
.model flat, stdcall

ExitProcess PROTO STDCALL :DWORD
MessageBoxA PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD

; FAKE
extern _imp__GetMessageA@16             : PROC
extern _imp__CreateProcessA@40          : PROC
extern _imp__DeleteObject@4             : PROC
extern _imp__GetStockObject@4           : PROC
extern _imp__SelectObject@8             : PROC
extern _imp__GetModuleInformation@16    : PROC
extern _imp__GetProcessMemoryInfo@12    : PROC
extern _imp__EmptyWorkingSet@4          : PROC
extern _imp__LeaveCriticalSection@4     : PROC
extern _imp__SHGetMalloc@4              : PROC
extern _imp__SHGetFileInfoW@20          : PROC

ENDIF

.data

caption db 'caption', 0
text    db 'moo', 0

.code

start PROC

    IFDEF RAX

    sub     rsp, 28h
    xor     r9, r9
    lea     r8, caption
    lea     rdx, text
    xor     rcx, rcx

    ELSE

    push    0h
    push    offset caption
    push    offset text
    push    0h

    ENDIF
    call    MessageBoxA
    xor     eax, eax
    jnz     nevercalled
    call    ExitProcess

nevercalled:
    call    ITReconstrutTest

start ENDP

ITReconstrutTest PROC

    nop
    nop
    nop

    IFDEF RAX
    mov     rcx, qword ptr [__imp_CreateProcessA]
    ; mov     rcx, qword ptr [rip + 11121314h]
    db      48h, 8bh, 0dh, 14h, 13h, 12h, 11h
    mov     rdx, qword ptr [__imp_GetMessageA]
    ; mov     rdx, qword ptr [rip + 21222324h]
    db      48h, 8bh, 15h, 24h, 23h, 22h, 21h
    mov     rbx, qword ptr [__imp_DeleteObject]
    ; mov     rbx, qword ptr [rip + 31323334h]
    db      48h, 8bh, 1dh, 34h, 33h, 32h, 31h
    mov     rsp, qword ptr [__imp_GetStockObject]
    ; mov     rsp, qword ptr [rip + 41424344h]
    db      48h, 8bh, 25h, 44h, 43h, 42h, 41h
    mov     rbp, qword ptr [__imp_SelectObject]
    ; mov     rbp, qword ptr [rip + 51525354h]
    db      48h, 8bh, 2dh, 54h, 53h, 52h, 51h
    mov     rsi, qword ptr [__imp_GetModuleInformation]
    ; mov     rsi, qword ptr [rip + 61626364h]
    db      48h, 8bh, 35h, 64h, 63h, 62h, 61h
    mov     rdi, qword ptr [__imp_GetProcessMemoryInfo]
    ; mov     rdi, qword ptr [rip+71727374h]
    db      48h, 8bh, 3dh, 74h, 73h, 72h, 71h
    mov     rax, qword ptr [__imp_EmptyWorkingSet]
    ; mov     rax, qword ptr [rip+01020304h]
    db      48h, 8bh, 05h, 04h, 03h, 02h, 01h
    call    qword ptr [__imp_LeaveCriticalSection]
    xchg    rax, rax
    push    qword ptr [__imp_SHGetFileInfoW]
    xor     rax, rax
    jnz     itnevercalled
    jmp     qword ptr [__imp_SHGetMalloc]
itnevercalled:
    mov     rax, qword ptr [__imp_CreateProcessA]
    ; mov     rax, qword ptr [rip+01020304h]
    db      48h, 8bh, 05h, 04h, 03h, 02h, 01h
    ELSE
    mov     ecx, dword ptr ds:[_imp__CreateProcessA@40]
    mov     ecx, dword ptr ds:[11121314h]
    mov     edx, dword ptr ds:[_imp__GetMessageA@16]
    mov     edx, dword ptr ds:[21222324h]
    mov     ebx, dword ptr ds:[_imp__DeleteObject@4]
    mov     ebx, dword ptr ds:[31323334h]
    mov     esp, dword ptr ds:[_imp__GetStockObject@4]
    mov     esp, dword ptr ds:[41424344h]
    mov     ebp, dword ptr ds:[_imp__SelectObject@8]
    mov     ebp, dword ptr ds:[51525354h]
    mov     esi, dword ptr ds:[_imp__GetModuleInformation@16]
    mov     esi, dword ptr ds:[61626364h]
    mov     edi, dword ptr ds:[_imp__GetProcessMemoryInfo@12]
    mov     edi, dword ptr ds:[71727374h]
    mov     eax, dword ptr ds:[_imp__EmptyWorkingSet@4]
    mov     eax, dword ptr ds:[81828384h]
    call    dword ptr ds:[_imp__LeaveCriticalSection@4]
    xchg    eax, eax
    push    dword ptr ds:[_imp__SHGetFileInfoW@20]
    xor     eax, eax
    jnz     itnevercalled
    jmp     dword ptr ds:[_imp__SHGetMalloc@4]
itnevercalled:
    mov     eax, dword ptr ds:[_imp__CreateProcessA@40]
    mov     eax, dword ptr ds:[91929394h]
    ENDIF

    nop
    nop
    nop
    ret

ITReconstrutTest ENDP

End
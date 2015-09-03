#ifndef __HOOKSTUFF_H__
#define __HOOKSTUFF_H__

#include <windows.h>
#include <Dbghelp.h>

#include "dbg.h"

#if _WIN64
    #define LDE_X86 64
#else
    #define LDE_X86 0
#endif

#ifdef __cplusplus
extern "C"
#endif
int __stdcall LDE(void* address , DWORD type);

#if _WIN64
typedef struct _PUSHED_REGS {
    DWORD64 R15;
    DWORD64 R14;
    DWORD64 R13;
    DWORD64 R12;
    DWORD64 R11;
    DWORD64 R10;
    DWORD64 R9;
    DWORD64 R8;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 Rbp;
    DWORD64 Rdx;
    DWORD64 Rcx;
    DWORD64 Rbx;
    DWORD64 Rax;
    DWORD64 Rsp;
} PUSHED_REGS, *PPUSHED_REGS;
#else
typedef struct _PUSHED_REGS {
    DWORD Edi;
    DWORD Esi;
    DWORD Ebp;
    DWORD Esp;
    DWORD Ebx;
    DWORD Edx;
    DWORD Ecx;
    DWORD Eax;
} PUSHED_REGS, *PPUSHED_REGS;
#endif

BOOL SetupIATHook(ULONG_PTR BaseAddress, LPCSTR ModName, LPCSTR ProcName, PROC pfnNew);
BOOL ReplaceIATEntryInMod(ULONG_PTR BaseAddress, LPCSTR ModName, PROC pfnCurrent, PROC pfnNew);

/*
DWORD __declspec (naked) HookScriptEntry(VOID)
{
    __asm
    {
        pushad
        lea     eax, [esp]
        push    eax
        call    ScriptEntry
        add     esp, 4
        popad
        jmp     ResumeScriptEntry
    }
}
*/

#endif // __HOOKSTUFF_H__

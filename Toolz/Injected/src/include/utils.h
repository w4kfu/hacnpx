#ifndef __UTILS_H__
#define __UTILS_H__

#include <windows.h>

#include "dbg.h"
#include "pestuff.h"

typedef struct _PE_INFO {
    ULONG_PTR ModuleBase;
    DWORD ModuleSize;
    ULONG_PTR ModuleSections;
    DWORD EntryPoint;
    DWORD ModuleNbSections;
    ULONG_PTR ModuleInjectedBase;
    DWORD ModuleInjectedSize;
} PE_INFO, *PPE_INFO;

#if _WIN64
#define GET_IP(ExceptionInfo) (ExceptionInfo->ContextRecord->Rip)
#else
#define GET_IP(ExceptionInfo) (ExceptionInfo->ContextRecord->Eip)
#endif

#if _WIN64
#define GET_RETURN_ADDR(pRegs) (*(DWORD64*)(pRegs->Rsp))
#else
#define GET_RETURN_ADDR(pRegs) (*(DWORD*)(pRegs->Esp))
#endif

VOID FillPeInfo(VOID);
VOID PrintPeInfo(VOID);
BOOL IsWindows8orLater(void);

#endif // __UTILS_H__

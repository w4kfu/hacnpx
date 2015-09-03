#ifndef __BREAKPOINT_H__
#define __BREAKPOINT_H__

#include <windows.h>

#include "dbg.h"
#include "pestuff.h"
#include "utils.h"

typedef struct _BPINFO
{
    ULONG_PTR Addr;
    BYTE OriginalByte;
    PVECTORED_EXCEPTION_HANDLER VectoredHandler;
} BPINFO, *PBPINFO;

typedef struct _GUARDINFO
{
    ULONG_PTR StartAddr;
    DWORD SectionSize;
    ULONG_PTR EndAddr;
    PVECTORED_EXCEPTION_HANDLER VectoredHandler;
} GUARDINFO, *PGUARDINFO;

VOID AddBreakpoint(ULONG_PTR Addr, PVECTORED_EXCEPTION_HANDLER VectoredHandler);
VOID AddBreakpointAtEP(PVECTORED_EXCEPTION_HANDLER VectoredHandler);
BOOL RemoveBreakpoint(ULONG_PTR Addr);
VOID GuardUntilExecSection(const char *Name, PVECTORED_EXCEPTION_HANDLER VectoredHandler);

#endif // __BREAKPOINT_H__

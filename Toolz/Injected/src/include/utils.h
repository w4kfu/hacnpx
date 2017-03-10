#ifndef __UTILS_H__
#define __UTILS_H__

#include "injected.h"

typedef struct _PE_INFO {
    ULONG_PTR ModuleBase;
    DWORD ModuleSize;
    ULONG_PTR ModuleSections;
    DWORD EntryPoint;
    DWORD ModuleNbSections;
    ULONG_PTR ModuleInjectedBase;
    DWORD ModuleInjectedSize;
    std::list<PMODULE> lModule;
    IMPORTER Importer;
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

#define GET_RETURN_ADDR_POST    GetValue();

#if _WIN64
#define GET_ARG_1(pRegs) (pRegs->Rcx)
#else
#define GET_ARG_1(pRegs) (*(DWORD*)(pRegs->Esp + 0x04))
#endif

#if _WIN64
#define GET_ARG_2(pRegs) (pRegs->Rdx)
#else
#define GET_ARG_2(pRegs) (*(DWORD*)(pRegs->Esp + 0x08))
#endif

#if _WIN64
#define GET_ARG_3(pRegs) (pRegs->R8)
#else
#define GET_ARG_3(pRegs) (*(DWORD*)(pRegs->Esp + 0x0C))
#endif

#if _WIN64
#define GET_ARG_4(pRegs) (pRegs->R9)
#else
#define GET_ARG_4(pRegs) (*(DWORD*)(pRegs->Esp + 0x10))
#endif

#if _WIN64
#define GET_ARG_5(pRegs) (*(DWORD64*)(pRegs->Rsp + 0x28 + 0x00))
#else
#define GET_ARG_5(pRegs) (*(DWORD*)(pRegs->Esp + 0x10))
#endif

#if _WIN64
#define GET_ARG_6(pRegs) (*(DWORD64*)(pRegs->Rsp + 0x28 + 0x08))
#else
#define GET_ARG_6(pRegs) (*(DWORD*)(pRegs->Esp + 0x10))
#endif

#if _WIN64
#define GET_ARG_7(pRegs) (*(DWORD64*)(pRegs->Rsp + 0x28 + 0x10))
#else
#define GET_ARG_7(pRegs) (*(DWORD*)(pRegs->Esp + 0x10))
#endif

#if _WIN64
#define GET_ARG_8(pRegs) (*(DWORD64*)(pRegs->Rsp + 0x28 + 0x18))
#else
#define GET_ARG_8(pRegs) (*(DWORD*)(pRegs->Esp + 0x10))
#endif

VOID FillPeInfo(VOID);
BOOL IsWindows8orLater(void);
BOOL CheckIfTwiceFreq(std::map<ULONG_PTR, int> &ModuleBaseMap, int max);
void *memmem(const void *l, size_t l_len, const void *s, size_t s_len);
VOID HideIt(VOID);

#endif // __UTILS_H__

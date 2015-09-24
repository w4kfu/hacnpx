#ifndef __MODULES_H__
#define __MODULES_H__

#include "injected.h"

enum CHAMP_MODULE
{
    MOD_BASE = 0,
    MOD_SIZE,
};

PVOID GetModuleInfo(ULONG_PTR Addr, DWORD dwChamp);
BOOL MyRtlPcToFileHeader(ULONG_PTR Addr, PULONG_PTR BaseOfImage);
std::list<PMODULE> GetModuleList(VOID);
PMODULE GetModule(ULONG_PTR Addr);

#endif // __MODULES_H__

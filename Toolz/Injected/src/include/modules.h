#ifndef __MODULES_H__
#define __MODULES_H__

#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>

enum CHAMP_MODULE
{
    MOD_BASE = 0,
    MOD_SIZE,
};

PVOID GetModuleInfo(ULONG_PTR Addr, DWORD dwChamp);
BOOL MyRtlPcToFileHeader(ULONG_PTR Addr, PULONG_PTR BaseOfImage);

#endif // __MODULES_H__

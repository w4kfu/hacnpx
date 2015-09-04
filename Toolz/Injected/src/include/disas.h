#ifndef __DISAS_H__
#define __DISAS_H__

#include <windows.h>

#include "capstone/capstone.h"

#include "dbg.h"

#ifdef _WIN64
#define PrintInstru(ModName, Address, Mnemonic, Op_str)                                                 \
    if (Modname)                                                                                        \
        DbgMsg("%s:0x%016llX\t%s\t%s\n", Modname, Address, Mnemonic, Op_str);                           \
    else                                                                                                \
        DbgMsg("0x%016llX\t%s\t%s\n", Address, Mnemonic, Op_str);
#else
#define PrintInstru(ModName, Address, Mnemonic, Op_str)                                                 \
    if (Modname)                                                                                        \
        DbgMsg("%s:0x%08X\t%s\t%s\n", Modname, (DWORD)(Address & 0xFFFFFFFF), Mnemonic, Op_str);        \
    else                                                                                                \
        DbgMsg("0x%08X\t%s\t%s\n", (DWORD)(Address & 0xFFFFFFFF), Mnemonic, Op_str);
#endif

VOID DisasAt(PBYTE bCode, DWORD dwSize, ULONG_PTR dwAddr, LPCSTR Modname = NULL);

#endif // __DISAS_H__

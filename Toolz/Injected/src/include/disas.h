#ifndef __DISAS_H__
#define __DISAS_H__

#include "injected.h"

#ifdef _WIN64
#define PrintInstru(ModName, Address, Mnemonic, Op_str)                                                 \
    if (Modname)                                                                                        \
        DbgMsg("%s:0x%016llX    %s    %s\n", Modname, Address, Mnemonic, Op_str);                           \
    else                                                                                                \
        DbgMsg("0x%016llX    %s    %s\n", Address, Mnemonic, Op_str);
#else
#define PrintInstru(ModName, Address, Mnemonic, Op_str)                                                 \
    if (Modname)                                                                                        \
        DbgMsg("%s:0x%08X    %s    %s\n", Modname, (DWORD)(Address & 0xFFFFFFFF), Mnemonic, Op_str);        \
    else                                                                                                \
        DbgMsg("0x%08X    %s    %s\n", (DWORD)(Address & 0xFFFFFFFF), Mnemonic, Op_str);
#endif

VOID DisasOne(PBYTE bCode, ULONG_PTR dwAddr, LPCSTR Modname = NULL);
VOID DisasAt(PBYTE bCode, DWORD dwSize, ULONG_PTR dwAddr, LPCSTR Modname = NULL);

#endif // __DISAS_H__

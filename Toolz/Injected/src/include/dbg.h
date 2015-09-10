#ifndef __DBG_H__
#define __DBG_H__

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "pestuff.h"
#include "utils.h"

#define FILE_DBG "dbg_msg.txt"

#if _WIN64
    #define HEX_FORMAT  "0x%016llX"
#else
    #define HEX_FORMAT  "0x%08X"
#endif

VOID MakeConsole(VOID);
VOID HexDump(PVOID *data, SSIZE_T size);
VOID DbgMsg(LPCSTR szFormat, ...);
VOID PrintExportEntry(std::list<PEXPORTENTRY> lExport);
VOID PrintPeInfo(VOID);
VOID PrintModuleInfo(VOID);
VOID PrintInfoImporter(PIMPORTER Importer);

#endif // __DBG_H__

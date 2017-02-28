#ifndef __DBG_H__
#define __DBG_H__

#include "injected.h"

#define FILE_DBG "dbg_msg.txt"

#if _WIN64
    #define HEX_FORMAT "0x%016llX"
#else
    #define HEX_FORMAT "0x%08X"
#endif

VOID MakeConsole(VOID);
VOID DbgPrintContext(PCONTEXT pContext, BOOL bDisas);
VOID HexDump(PVOID data, SSIZE_T size);
VOID HexDumpPrintf(PVOID data, SSIZE_T size);
VOID DbgMsg(LPCSTR szFormat, ...);
VOID PrintExportEntry(std::list<PEXPORTENTRY> lExport);
VOID PrintPeInfo(VOID);
VOID PrintModuleInfo(VOID);
VOID PrintInfoImporter(PIMPORTER Importer);
VOID Write2File(PVOID data, SSIZE_T size);

#endif // __DBG_H__

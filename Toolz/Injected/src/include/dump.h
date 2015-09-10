#ifndef __DUMP_H__
#define __DUMP_H__

#include <windows.h>

#include "dbg.h"
#include "pestuff.h"

BOOL DumpPE(ULONG_PTR ImageBase, LPCSTR dumpFileName, ULONG_PTR dwEntryPoint = 0, BOOL ImportRec = FALSE);
BOOL PrepareDumpPE(ULONG_PTR ImageBase, PBYTE *pDump, PULONG_PTR AllocSize);
BOOL PrepareReconstruct(PBYTE *pDump, PULONG_PTR AllocSize);

#endif // __DUMP_H__

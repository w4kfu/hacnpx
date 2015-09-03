#ifndef __DUMP_H__
#define __DUMP_H__

#include <windows.h>

#include "dbg.h"
#include "pestuff.h"

BOOL DumpPE(ULONG_PTR ImageBase, LPCSTR dumpFileName);

#endif // __DUMP_H__

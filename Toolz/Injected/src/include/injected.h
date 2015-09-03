#ifndef __INJECTED_H__
#define __INJECTED_H__

#include <windows.h>

#include "breakpoint.h"
#include "dbg.h"
#include "dump.h"
#include "injected.h"
#include "memory.h"
#include "modules.h"
#include "pestuff.h"
#include "utils.h"
#include "hookstuff.h"

#ifdef _WIN64
    typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
    typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;
#else
    typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS;
    typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;
#endif

VOID StartInjected(VOID);

#endif // __INJECTED_H__

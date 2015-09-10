#ifndef __INJECTED_H__
#define __INJECTED_H__

#include <windows.h>
#include <tlhelp32.h>

#include <list>

typedef struct _EXPORTENTRY {
    WORD Ordinal;
    ULONG_PTR FunctionVA;
    ULONG_PTR FunctionRVA;
    CHAR FunctionName[256];
    ULONG_PTR RVA;
} EXPORTENTRY, *PEXPORTENTRY;

typedef struct _MODULE {
    DWORD dwSize;
    DWORD th32ModuleID;
    DWORD th32ProcessID;
    DWORD GlblcntUsage;
    DWORD ProccntUsage;
    BYTE *modBaseAddr;
    DWORD modBaseSize;
    HMODULE hModule;
    TCHAR szModule[MAX_MODULE_NAME32 + 1];
    TCHAR szExePath[MAX_PATH];
    std::list<PEXPORTENTRY> lExport;
} MODULE, *PMODULE;

typedef struct _IMPORTER
{
    std::list<PMODULE> lModule;
    ULONG_PTR StartIATRVA;
    ULONG_PTR ModulesNameLength;
    ULONG_PTR APIsNameLength;
    DWORD TotalSizeIT;
    ULONG_PTR NbTotalApis;
} IMPORTER, *PIMPORTER;

#include "breakpoint.h"
#include "dbg.h"
#include "disas.h"
#include "dump.h"
#include "hookstuff.h"
#include "iatstuff.h"
#include "injected.h"
#include "memory.h"
#include "modules.h"
#include "pestuff.h"
#include "utils.h"

#ifdef _WIN64
    typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
    typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;
#else
    typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS;
    typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;
#endif

VOID StartInjected(VOID);

#endif // __INJECTED_H__

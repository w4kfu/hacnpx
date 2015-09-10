#ifndef __IATSTUFF_H__
#define __IATSTUFF_H__

#include <windows.h>

#include "injected.h"

#ifdef _WIN64
#define SIZE_IMPORT_ENTRY 8
#else
#define SIZE_IMPORT_ENTRY 4
#endif

BOOL InitIATStuff(VOID);

BOOL SearchAutoIAT(ULONG_PTR BaseAddress, ULONG_PTR OEP);
BOOL SearchAutoIAT(ULONG_PTR BaseAddress, ULONG_PTR SearchStart, DWORD SearchSize);

ULONG_PTR SearchIATStart(ULONG_PTR BaseAddress, ULONG_PTR SearchStart);
ULONG_PTR SearchIATEnd(ULONG_PTR BaseAddress, ULONG_PTR SearchStart);

VOID AddNewModule(PIMPORTER Importer, PMODULE Module);
VOID AddNewApi(PMODULE Module, PEXPORTENTRY Export, ULONG_PTR RVA);
VOID AddNewModuleApi(PIMPORTER Importer, PMODULE Module, PEXPORTENTRY Export, ULONG_PTR RVA);
VOID ComputeAllITSize(PIMPORTER Importer);

VOID BuildIT(PBYTE pDump, ULONG_PTR RVAIT);

#endif // __IATSTUFF_H__

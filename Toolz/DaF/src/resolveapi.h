#ifndef __RESOLVEAPI_H__
#define __RESOLVEAPI_H__

#include <Windows.h>
#include <psapi.h>

#include "af.h"

VOID ResolveApi64_(std::list<struct Module*> &lMod, ULONG_PTR apiAddress, PIMPORT_STRUCT pImport);
ULONG ResolveApi64(DWORD pid, ULONG_PTR apiAddress, PIMPORT_STRUCT pImport);

#endif // __RESOLVEAPI_H__
#ifndef __PESTUFF_H__
#define __PESTUFF_H__

#include <windows.h>
#include <list>

#include "modules.h"

enum CHAMP_PE
{
    EXPORT_TABLE,
    EXPORT_TABLE_SIZE,
    SIZE_OF_IMAGE,
    NB_SECTIONS,
    PE_SECTIONS,
    ENTRY_POINT
};

enum CHAMP_SECTION
{
    SEC_NAME = 0,
    SEC_VIRT_SIZE,
    SEC_VIRT_ADDR,
    SEC_RAW_SIZE,
    SEC_RAW_ADDR,
    SEC_CHARAC
};

typedef struct _EXPORTENTRY
{
    WORD Ordinal;
    ULONG_PTR FunctionVA;
    ULONG_PTR FunctionRVA;
    CHAR FunctionName[256];
} EXPORTENTRY, *PEXPORTENTRY;

BOOL ValidateHeader(ULONG_PTR BaseAddress);
PVOID ParsePE(ULONG_PTR BaseAddress, DWORD dwChamp);
PVOID GetSectionInfo(ULONG_PTR BaseAddress, DWORD dwAddr, DWORD dwChamp);
PVOID GetSectionInfo(ULONG_PTR BaseAddress, const char *Name, DWORD dwChamp);
DWORD RVA2Offset(ULONG_PTR BaseAddress, DWORD dwVA);
std::list<EXPORTENTRY> GetExport(ULONG_PTR BaseAddress);

#endif // __PESTUFF_H__

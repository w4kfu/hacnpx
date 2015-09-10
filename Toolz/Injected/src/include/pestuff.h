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
    ENTRY_POINT,
    IMPORT_TABLE,
    IMPORT_TABLE_SIZE,
    IMPORT_ADDRESS_TABLE,
    IMPORT_ADDRESS_TABLE_SIZE
};

enum CHAMP_DIRECTORY
{
    DIR_VIRTUAL_ADDRESS,
    DIR_SIZE
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

BOOL ValidateHeader(ULONG_PTR BaseAddress);
PVOID ParsePE(ULONG_PTR BaseAddress, DWORD dwChamp);
PVOID GetSectionInfo(ULONG_PTR BaseAddress, ULONG_PTR dwAddr, DWORD dwChamp);
PVOID GetSectionInfo(ULONG_PTR BaseAddress, const char *Name, DWORD dwChamp);
DWORD RVA2Offset(ULONG_PTR BaseAddress, DWORD dwVA);
std::list<PEXPORTENTRY> GetExportList(ULONG_PTR BaseAddress);
PEXPORTENTRY GetExport(PMODULE Module, ULONG_PTR BaseAddress);
VOID AddPESection(ULONG_PTR ImageBase, LPCSTR Name, DWORD PtrRawData, DWORD VirtualSize, DWORD VA, DWORD SizeSection, DWORD Characteristics = 0xE0000060);
BOOL EditPE(ULONG_PTR BaseAddress, DWORD dwChamp, PVOID Value);
VOID FixSectionSizeOffset(ULONG_PTR BaseAddress);

#endif // __PESTUFF_H__

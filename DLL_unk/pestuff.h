#ifndef __PESTUFF_H__
#define __PESTUFF_H__

#include <windows.h>

enum CHAMP_SECTION
{
    SEC_NAME = 0,
    SEC_VIRT_SIZE,
    SEC_VIRT_ADDR,
    SEC_RAW_SIZE,
    SEC_RAW_ADDR,
    SEC_CHARAC
};

enum CHAMP_PE
{
    EXPORT_TABLE,
    EXPORT_TABLE_SIZE
};

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);

BOOL IsRealBadReadPtr(void* address, int size);
void* ParseSection(PIMAGE_SECTION_HEADER pSection, DWORD dwChamp);
void* GetSectionInfo(BYTE* hMod, char *name, DWORD dwChamp);
void* ParsePE(BYTE* hMod, DWORD dwChamp);

DWORD GetTextAddress(HMODULE hModule);
DWORD FindCode(const LPSTR pSig, const DWORD dwSize, const DWORD dwAddress, const DWORD dwLength);
DWORD GetTextSize(HMODULE hModule);

#endif // __PESTUFF_H__
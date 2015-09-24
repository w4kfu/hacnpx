#include "utils.h"

PE_INFO pinfo = {0};

VOID FillPeInfo(VOID)
{
    pinfo.ModuleBase = (ULONG_PTR)GetModuleHandleA(NULL);
    pinfo.ModuleSize = (DWORD)ParsePE(pinfo.ModuleBase, SIZE_OF_IMAGE);
    pinfo.ModuleNbSections = (DWORD)ParsePE(pinfo.ModuleBase, NB_SECTIONS);
    pinfo.ModuleSections = (ULONG_PTR)ParsePE(pinfo.ModuleBase, PE_SECTIONS);
    pinfo.EntryPoint = (DWORD)ParsePE(pinfo.ModuleBase, ENTRY_POINT);
    MyRtlPcToFileHeader((ULONG_PTR)&pinfo, &pinfo.ModuleInjectedBase);
    pinfo.ModuleInjectedSize = (DWORD)ParsePE(pinfo.ModuleInjectedBase, SIZE_OF_IMAGE);
    PrintPeInfo();
}

BOOL IsWindows8orLater(void)
{
    OSVERSIONINFO osvi;
    BOOL bIsWindows8orLater;

    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);
    bIsWindows8orLater =
       ((osvi.dwMajorVersion > 6) ||
       ((osvi.dwMajorVersion == 6) && (osvi.dwMinorVersion >= 2) ));
    return (bIsWindows8orLater);
}

BOOL CheckIfTwiceFreq(std::map<ULONG_PTR, int> &ModuleBaseMap, int max)
{
    int nb_occur = 0;

    for (std::map<ULONG_PTR, int>::iterator it = ModuleBaseMap.begin(); it != ModuleBaseMap.end(); ++it) {
        if (it->second == max)
            nb_occur = nb_occur + 1;
    }
    return (nb_occur > 1);
}
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

// MEMDIFF
// int i = 0;
// int nb = 0;
// ULONG_PTR idiff = 0;
// PBYTE pBinCurrent = (PBYTE)GetModuleHandleA(NULL);
// while (i < SizeOfImage) {
//     if (i == 0x5ba9598) {
//         i = i + 4;
//     }
//     nb = 0;
//     idiff = i;
//     while (pBinCurrent[i] != pBinAllocated[i]) {
//         nb = nb + 1;
//         i = i + 1;
//     }
//     if (nb != 0) {
//         LOG_FUNC("Found %d bytes diff at " HEX_FORMAT "\n", nb, pBinCurrent + idiff);
//         HexDump(pBinCurrent + idiff, nb);
//         LOG_FUNC("\n");
//         HexDump(pBinAllocated + idiff, nb);
//         LOG_FUNC("-------\n");
//     }
//     i = i + 1;
// }

void *memmem(const void *l, size_t l_len, const void *s, size_t s_len)
{
    register char *cur, *last;
    const char *cl = (const char *)l;
    const char *cs = (const char *)s;
    
    /* we need something to compare */
    if (l_len == 0 || s_len == 0)
        return NULL;
    
    /* "s" must be smaller or equal to "l" */
    if (l_len < s_len)
        return NULL;
    
    /* special case where s_len == 1 */
    if (s_len == 1)
        return (void*)memchr(l, (int)*cs, l_len);
    
    /* the last position where its possible to find "s" in "l" */
    last = (char *)cl + l_len - s_len;
    
    for (cur = (char *)cl; cur <= last; cur++)
        if (cur[0] == cs[0] && memcmp(cur, cs, s_len) == 0)
            return cur;
    
    return NULL;
}
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

/* TODO FIX THIS 

Use _KUSER_SHARED_DATA

*/
#pragma warning (push)
#pragma warning (disable:4996)
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
#pragma warning (pop)

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

VOID CreateDump(PEXCEPTION_POINTERS ExceptionInfo)
{
    MINIDUMP_EXCEPTION_INFORMATION miniexceptionInfo;
    miniexceptionInfo.ThreadId = GetCurrentThreadId();
    miniexceptionInfo.ExceptionPointers = ExceptionInfo;
    miniexceptionInfo.ClientPointers = FALSE;
    BOOL bWait = TRUE;

    HANDLE hFile = CreateFileA("moo.dmp", GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, MiniDumpWithFullMemory, &miniexceptionInfo, NULL, NULL) == FALSE) {
        DbgMsg("[-] MiniDumpWriteDump failed : %lu\n", GetLastError());
    }
    DbgMsg("[+] Waiting ... (minidump has been created)\n");
    while (bWait == TRUE) {
        Sleep(0x1000);
    }
}

VOID MemsetBytes(LPVOID Addr, int c, size_t n)
{
    DWORD dwOldProt;

    if (!VirtualProtect(Addr, n, PAGE_EXECUTE_READWRITE, &dwOldProt)) {
        DbgMsg("[-] MemsetBytes - VirtualProtect(" HEX_FORMAT ", ...) failed for : %lu\n", (ULONG_PTR)Addr, GetLastError());
        ExitProcess(42);
    }
    else {
        memset(Addr, c, n);
    }
}

VOID MemcpyBytes(LPVOID Addr, PVOID src, size_t n)
{
    DWORD dwOldProt;

    if (!VirtualProtect(Addr, n, PAGE_EXECUTE_READWRITE, &dwOldProt)) {
        DbgMsg("[-] MemcpyBytes - VirtualProtect(" HEX_FORMAT ", ...) failed for : %lu\n", (ULONG_PTR)Addr, GetLastError());
        ExitProcess(42);
    }
    else {
        memcpy(Addr, src, n);
    }
}

PPEB GetPeb(VOID)
{
    PPEB Peb = 0;
#ifdef _WIN64
    Peb = (PPEB)__readgsqword(0x60);
#else
    Peb = (PPEB)__readfsdword(0x30);
#endif
    return Peb;
}

FORCEINLINE BOOLEAN MyRemoveEntryList(IN PLIST_ENTRY Entry)
{
    PLIST_ENTRY OldFlink;
    PLIST_ENTRY OldBlink;

    OldFlink = Entry->Flink;
    OldBlink = Entry->Blink;
    OldFlink->Blink = OldBlink;
    OldBlink->Flink = OldFlink;
    return (BOOLEAN)(OldFlink == OldBlink);
}

BOOL HideFromInLoadOrderModuleList(PLIST_ENTRY ModuleListHead, ULONG_PTR BaseOfImage)
{
    PLIST_ENTRY ModuleListEntry = NULL;
    PLDR_DATA_TABLE_ENTRY LdrDataEntry = NULL;

    ModuleListEntry = ModuleListHead->Flink;
    while (ModuleListEntry != ModuleListHead) {
        LdrDataEntry = CONTAINING_RECORD(ModuleListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if ((ULONG_PTR)LdrDataEntry->BaseAddress == BaseOfImage) {
            MyRemoveEntryList(ModuleListEntry);
            return TRUE;
        }
        ModuleListEntry = ModuleListEntry->Flink;
    }
    return FALSE;
}

BOOL HideFromInMemoryOrderModuleList(PLIST_ENTRY ModuleListHead, ULONG_PTR BaseOfImage)
{
    PLIST_ENTRY ModuleListEntry = NULL;
    PLDR_DATA_TABLE_ENTRY LdrDataEntry = NULL;

    ModuleListEntry = ModuleListHead->Flink;
    while (ModuleListEntry != ModuleListHead) {
        LdrDataEntry = CONTAINING_RECORD(ModuleListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if ((ULONG_PTR)LdrDataEntry->BaseAddress == BaseOfImage) {
            MyRemoveEntryList(ModuleListEntry);
            return TRUE;
        }
        ModuleListEntry = ModuleListEntry->Flink;
    }
    return FALSE;
}

BOOL HideFromInInitializationOrderModuleList(PLIST_ENTRY ModuleListHead, ULONG_PTR BaseOfImage)
{
    PLIST_ENTRY ModuleListEntry = NULL;
    PLDR_DATA_TABLE_ENTRY LdrDataEntry = NULL;

    ModuleListEntry = ModuleListHead->Flink;
    while (ModuleListEntry != ModuleListHead) {
        LdrDataEntry = CONTAINING_RECORD(ModuleListEntry, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
        if ((ULONG_PTR)LdrDataEntry->BaseAddress == BaseOfImage) {
            MyRemoveEntryList(ModuleListEntry);
            return TRUE;
        }
        ModuleListEntry = ModuleListEntry->Flink;
    }
    return FALSE;
}

VOID HideIt(VOID)
{
    ULONG_PTR BaseOfImage = 0x00;
    PPEB_LDR_DATA PedLdrData = NULL;
    PPEB Peb = NULL;

    if (MyRtlPcToFileHeader((ULONG_PTR)&HideIt, &BaseOfImage) == FALSE) {
        DbgMsg("[-] MyRtlPcToFileHeader failed\n");
    }
    Peb = GetPeb();
    PedLdrData = Peb->Ldr;
    HideFromInLoadOrderModuleList(&PedLdrData->InLoadOrderLinks, BaseOfImage);
    HideFromInMemoryOrderModuleList(&PedLdrData->InMemoryOrderLinks, BaseOfImage);
    HideFromInInitializationOrderModuleList(&PedLdrData->InInitializationOrderLinks, BaseOfImage);
}
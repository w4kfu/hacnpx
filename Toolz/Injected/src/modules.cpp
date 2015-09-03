#include "modules.h"

BOOL MyRtlPcToFileHeader(ULONG_PTR Addr, PULONG_PTR BaseOfImage)
{
    ULONG_PTR ResBaseOfImage;

    ResBaseOfImage = (ULONG_PTR)GetModuleInfo(Addr, MOD_BASE);
    if (ResBaseOfImage == NULL) {
        return FALSE;
    }
    *BaseOfImage = ResBaseOfImage;
    return TRUE;
}

PVOID GetModuleInfo(ULONG_PTR Addr, DWORD dwChamp)
{
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32 me;

    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hModuleSnap == INVALID_HANDLE_VALUE) {
        printf("[-] CreateToolhelp32Snapshot failed\n");
        return NULL;
    }
    me.dwSize = sizeof (MODULEENTRY32);
    if (!Module32First(hModuleSnap, &me)) {
        printf("[-] Module32First failed\n");
        CloseHandle(hModuleSnap);
        return NULL;
    }
    if (Addr >= (ULONG_PTR)me.modBaseAddr || Addr <= (ULONG_PTR)(me.modBaseAddr + me.modBaseSize)) {
        switch(dwChamp) {
            case MOD_BASE:
                return (PVOID)me.modBaseAddr;
            case MOD_SIZE:
                return (PVOID)me.modBaseSize;
        }
    }
    return NULL;
}
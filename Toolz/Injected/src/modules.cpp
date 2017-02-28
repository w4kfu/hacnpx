#include "modules.h"

extern PE_INFO pinfo;

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
        DbgMsg("[-] GetModuleInfo - CreateToolhelp32Snapshot failed\n");
        return NULL;
    }
    me.dwSize = sizeof (MODULEENTRY32);
    if (!Module32First(hModuleSnap, &me)) {
        DbgMsg("[-] GetModuleInfo - Module32First failed\n");
        CloseHandle(hModuleSnap);
        return NULL;
    }
    do
    {
        if ((Addr >= (ULONG_PTR)me.modBaseAddr) && (Addr < (ULONG_PTR)(me.modBaseAddr + me.modBaseSize))) {
            switch (dwChamp) {
                case MOD_BASE:
                    return (PVOID)me.modBaseAddr;
                case MOD_SIZE:
                    return (PVOID)((ULONG_PTR)me.modBaseSize);
            }
        }
    } while (Module32Next(hModuleSnap, &me));
    DbgMsg("[+] GetModuleInfo failed : " HEX_FORMAT "\n", Addr);
    return NULL;
}

std::list<PMODULE> GetModuleList(VOID)
{
    MODULEENTRY32 me;
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    std::list<PMODULE> lModule;
    PMODULE mo;

    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hModuleSnap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] GetModuleList - CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        return lModule;
    }
    me.dwSize = sizeof (MODULEENTRY32);
    if (!Module32First(hModuleSnap, &me)) {
        DbgMsg("[-] GetModuleInfo - Module32First failed\n");
        CloseHandle(hModuleSnap);
        return lModule;
    }
    do
    {
        if (me.modBaseAddr == (PBYTE)GetModuleHandleA(NULL))
            continue;
        mo = new MODULE();
        if (mo == NULL) {
            DbgMsg("[-] GetModuleList - malloc failed\n");
            ExitProcess(42);
        }
        mo->dwSize = me.dwSize;
        mo->th32ModuleID = me.th32ModuleID;
        mo->th32ProcessID = me.th32ProcessID;
        mo->GlblcntUsage = me.GlblcntUsage;
        mo->ProccntUsage = me.ProccntUsage;
        mo->modBaseAddr = me.modBaseAddr;
        mo->modBaseSize = me.modBaseSize;
        mo->hModule = me.hModule;
        memcpy(mo->szModule, me.szModule, sizeof (me.szModule));
        _strlwr_s(mo->szModule, sizeof (mo->szModule) - 1);
        memcpy(mo->szExePath, me.szExePath, sizeof (me.szExePath));
        DbgMsg("[+] Working on %s\n", mo->szModule);
        mo->lExport = GetExportList((ULONG_PTR)mo->modBaseAddr);
        lModule.push_back(mo);
    } while (Module32Next(hModuleSnap, &me));
    return lModule;
}

PMODULE GetModuleRedirect(ULONG_PTR Addr)
{
    std::list<PMODULE>::const_iterator it_mod;
    std::list<PEXPORTENTRY>::const_iterator it_exp;

    for (it_mod = pinfo.lModule.begin(); it_mod != pinfo.lModule.end(); ++it_mod) {
        for (it_exp = (*it_mod)->lExport.begin(); it_exp != (*it_mod)->lExport.end(); ++it_exp) {
            if ((*it_exp)->isRedirect == TRUE && (*it_exp)->FunctionVA == Addr) {
                return (*it_mod);
            }
        }
    }
    return NULL;
}

PMODULE GetModule(ULONG_PTR Addr)
{
    std::list<PMODULE>::const_iterator it;
    PMODULE Module;

    Module = GetModuleRedirect(Addr);
    if (Module != NULL)
        return Module;
    for (it = pinfo.lModule.begin(); it != pinfo.lModule.end(); ++it) {
        if (Addr >= (ULONG_PTR)((*it)->modBaseAddr) && Addr <= (ULONG_PTR)((*it)->modBaseAddr + (*it)->modBaseSize)) {
            return (*it);
        }
    }
    return NULL;
}
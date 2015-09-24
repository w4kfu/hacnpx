#include "breakpoint.h"

PVOID protVectoredHandlerEP = NULL;
extern PE_INFO pinfo;
std::list<BPINFO> lBPInfo;
GUARDINFO GuardInfo = {0};

LONG CALLBACK ProtectionFaultVectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    std::list<BPINFO>::const_iterator it;
    static BOOL bStepInto = FALSE;
    DWORD dwOldProt;

    /* Manage Breakpoints */
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT) {
        for (it = lBPInfo.begin(); it != lBPInfo.end(); ++it) {
            if ((*it).Addr == GET_IP(ExceptionInfo)) {
                if ((*it).VectoredHandler(ExceptionInfo) == EXCEPTION_CONTINUE_EXECUTION)
                    return EXCEPTION_CONTINUE_EXECUTION;
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }
    }
    /* Manage PAGE GUARD */
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        ULONG_PTR Address = (ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress;
        if (!(Address >= GuardInfo.StartAddr) && (Address < GuardInfo.EndAddr)) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        VirtualProtect((LPVOID)GuardInfo.StartAddr, GuardInfo.SectionSize, PAGE_EXECUTE_READWRITE, &dwOldProt);
        if (GET_IP(ExceptionInfo) == Address && (Address >= GuardInfo.StartAddr) && (Address < GuardInfo.EndAddr)) {
            GuardInfo.VectoredHandler(ExceptionInfo);
        }
        else {
            bStepInto = TRUE;
            ExceptionInfo->ContextRecord->EFlags |= 0x100;
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    /* Manage TF for PAGE GUARD */
    if ((ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) && (bStepInto)) {
        VirtualProtect((LPVOID)GuardInfo.StartAddr, GuardInfo.SectionSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &dwOldProt);
        bStepInto = FALSE;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

VOID AddBreakpoint(ULONG_PTR Addr, PVECTORED_EXCEPTION_HANDLER VectoredHandler)
{
    DWORD dwOldProt;
    BPINFO BpInfo;

    if (protVectoredHandlerEP == NULL) {
        protVectoredHandlerEP = AddVectoredExceptionHandler(0, ProtectionFaultVectoredHandler);
        if (protVectoredHandlerEP == NULL) {
            DbgMsg("[-] AddBreakpoint - AddVectoredExceptionHandler failed : %lu\n", GetLastError());
            return;
        }
    }
    BpInfo.Addr = Addr;
    BpInfo.VectoredHandler = VectoredHandler;
    if (!VirtualProtect((LPVOID)Addr, 0x1, PAGE_EXECUTE_READWRITE, &dwOldProt)) {
        DbgMsg("[-] AddBreakpoint - VirtualProtect failed : %lu\n", GetLastError());
        return;
    }
    BpInfo.OriginalByte = *(PBYTE)Addr;
    *(PBYTE)Addr = 0xCC;
    if (!VirtualProtect((LPVOID)Addr, 0x1, dwOldProt, &dwOldProt)) {
        DbgMsg("[-] AddBreakpoint - VirtualProtect failed : %lu\n", GetLastError());
        return;
    }
    lBPInfo.push_back(BpInfo);
}

VOID AddBreakpointAtEP(PVECTORED_EXCEPTION_HANDLER VectoredHandler)
{
    AddBreakpoint(pinfo.EntryPoint + pinfo.ModuleBase, VectoredHandler);
}

BOOL RemoveBreakpoint(ULONG_PTR Addr)
{
    DWORD dwOldProt;
    std::list<BPINFO>::const_iterator it;

    for (it = lBPInfo.begin(); it != lBPInfo.end(); ++it) {
        if ((*it).Addr == Addr) {
            if (!VirtualProtect((LPVOID)Addr, 0x1, PAGE_EXECUTE_READWRITE, &dwOldProt)) {
                DbgMsg("[-] RemoveBreakpoint - VirtualProtect failed : %lu\n", GetLastError());
                return FALSE;
            }
            *(PBYTE)Addr = (*it).OriginalByte;
            if (!VirtualProtect((LPVOID)Addr, 0x1, dwOldProt, &dwOldProt)) {
                DbgMsg("[-] RemoveBreakpoint - VirtualProtect failed : %lu\n", GetLastError());
                return FALSE;
            }
            lBPInfo.erase (it);
            return TRUE;
        }
    }
    return FALSE;
}

VOID GuardUntilExecSection(const char *Name, PVECTORED_EXCEPTION_HANDLER VectoredHandler)
{
    ULONG_PTR ModuleBase = 0;
    DWORD dwSectionBase = 0;
    DWORD dwSectionSize = 0;
    DWORD dwOldProt;

    ModuleBase = (ULONG_PTR)GetModuleHandleA(NULL);
    dwSectionBase = (DWORD)GetSectionInfo(ModuleBase, Name, SEC_VIRT_ADDR);
    dwSectionSize = (DWORD)GetSectionInfo(ModuleBase, Name, SEC_VIRT_SIZE /* SEC_RAW_SIZE */);
    if (dwSectionBase == 0 || dwSectionSize == 0) {
        DbgMsg("[-] GuardUntilExecSection- GetSectionInfo (%s) failed : dwSectionBase = 0x%08X ; dwSectionSize = 0x%08X\n", Name, dwSectionBase, dwSectionSize);
        return;
    }
    GuardInfo.StartAddr = ModuleBase + dwSectionBase;
    GuardInfo.SectionSize = dwSectionSize;
    GuardInfo.EndAddr = ModuleBase + dwSectionBase + dwSectionSize;
    GuardInfo.VectoredHandler = VectoredHandler;
    VirtualProtect((LPVOID)GuardInfo.StartAddr, dwSectionSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &dwOldProt);
}
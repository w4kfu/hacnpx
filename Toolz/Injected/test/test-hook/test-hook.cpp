#include "test-hook.h"

#include <list>

extern PE_INFO pinfo;

VOID HookMessageBoxA(PPUSHED_REGS pRegs)
{
    DbgMsg("[+] HookMessageBoxA - MessageBoxA! called from " HEX_FORMAT "\n", GET_RETURN_ADDR(pRegs));
}

VOID HookInlineMesssageBoxA(PPUSHED_REGS pRegs)
{
    DbgMsg("[+] HookInlineMesssageBoxA - MessageBoxA! called from " HEX_FORMAT "\n", GET_RETURN_ADDR(pRegs));
}

LONG CALLBACK CallBackEP(PEXCEPTION_POINTERS ExceptionInfo)
{
    DbgMsg("[+] CallBackEP\n");
    DbgMsg("[+] EP : " HEX_FORMAT "\n", (ULONG_PTR)GET_IP(ExceptionInfo));
    RemoveBreakpoint((ULONG_PTR)GET_IP(ExceptionInfo));
    SetupPreMadeHookVirtualProtect();
    return EXCEPTION_CONTINUE_EXECUTION;
}

VOID HookInlinePreVirtualAlloc(PPUSHED_REGS pRegs)
{
    ULONG_PTR RetAddr;

    RetAddr = (ULONG_PTR)GET_RETURN_ADDR(pRegs);
    if (RetAddr >= pinfo.ModuleInjectedBase && RetAddr <= (pinfo.ModuleInjectedBase + pinfo.ModuleInjectedSize)) {
        return;
    }
    DbgMsg("[+] VirtualAlloc(@ = " HEX_FORMAT ", size = " HEX_FORMAT ", ...) called from " HEX_FORMAT "\n", GET_ARG_1(pRegs), GET_ARG_2(pRegs), RetAddr);
}

VOID HookInlinePostVirtualAlloc(PPUSHED_REGS pRegs)
{
    ULONG_PTR RetAddr;

    RetAddr = (ULONG_PTR)GET_RETURN_ADDR_POST;
    if (RetAddr >= pinfo.ModuleInjectedBase && RetAddr <= (pinfo.ModuleInjectedBase + pinfo.ModuleInjectedSize)) {
        return;
    }
#if _WIN64
    DbgMsg("[+] VirtualAlloc => " HEX_FORMAT "\n", pRegs->Rax);
#else
    DbgMsg("[+] VirtualAlloc => " HEX_FORMAT "\n", pRegs->Eax);
#endif
}

VOID HookInlinePreCreateFileA(PPUSHED_REGS pRegs)
{
    ULONG_PTR RetAddr;

    RetAddr = (ULONG_PTR)GET_RETURN_ADDR(pRegs);
    if (RetAddr >= pinfo.ModuleInjectedBase && RetAddr <= (pinfo.ModuleInjectedBase + pinfo.ModuleInjectedSize)) {
        return;
    }
    DbgMsg("[+] CreateFileA(" HEX_FORMAT ", " HEX_FORMAT ", ...) called from " HEX_FORMAT "\n", GET_ARG_1(pRegs), GET_ARG_2(pRegs), RetAddr);
}

VOID HookInlinePostCreateFileA(PPUSHED_REGS pRegs)
{
    ULONG_PTR RetAddr;

    RetAddr = (ULONG_PTR)GET_RETURN_ADDR_POST;
    if (RetAddr >= pinfo.ModuleInjectedBase && RetAddr <= (pinfo.ModuleInjectedBase + pinfo.ModuleInjectedSize)) {
        return;
    }
#if _WIN64
    DbgMsg("[+] CreateFileA => " HEX_FORMAT "\n", pRegs->Rax);
#else
    DbgMsg("[+] CreateFileA => " HEX_FORMAT "\n", pRegs->Eax);
#endif
}

VOID PrintModuleInformation(std::list<PMODULE> lModule)
{
    std::list<PMODULE>::const_iterator it;

#if _WIN64
    DbgMsg("Name                           ModuleBase         ModuleSize NbExports\n");
    DbgMsg("============================== ================== ========== =========\n");
#else
    DbgMsg("Name                           ModuleBase ModuleSize NbExports\n");
    DbgMsg("============================== ========== ========== =========\n");
#endif
    for (it = lModule.begin(); it != lModule.end(); ++it) {
        DbgMsg("%-30s " HEX_FORMAT " 0x%08X %d\n", (*it)->szModule, (*it)->modBaseAddr, (*it)->modBaseSize, (*it)->lExport.size());
    }
#if _WIN64
    DbgMsg("============================== ================== ========== =========\n");
#else
    DbgMsg("============================== ========== ========== =========\n");
#endif
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    (void)hinstDLL;
    (void)lpReserved;
    std::list<PMODULE> lbefore;
    std::list<PMODULE> lafter;

    if (fdwReason == DLL_PROCESS_ATTACH) {
        StartInjected();
        lbefore = GetModuleList();
        PrintModuleInformation(lbefore);
        HideIt();
        lafter = GetModuleList();
        PrintModuleInformation(lafter);
        //LoadLibraryA("USER32.dll");
        //if (SetupIATHook((ULONG_PTR)GetModuleHandleA(NULL), "USER32.dll", "MessageBoxA", (PROC)HookMessageBoxA) == FALSE) {
        //    DbgMsg("[-] SetupIATHook failed!\n");
        //}
        //if (SetupInlineHook("USER32.dll", "MessageBoxA", (PROC)HookInlineMesssageBoxA) == FALSE) {
        //    DbgMsg("[-] SetupInlineHook failed!\n");
        //}
        // SetupPreMadeHookVirtualProtect();
        //SetupPreMadeHookSocket();
        //SetupPreMadeHookRecv();
        //SetupPreMadeHookSend();
        //SetupPreMadeHookSendto();
        //SetupPreMadeHookConnect();
        //SetupPreMadeHookWSASend();
        //SetupPreMadeHookWSASendTo();
        //SetupPreMadeHookWSAConnect();
        //AddBreakpointAtEP(CallBackEP);
        
        if (SetupPrePostInlineHook((ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileA"), (PROC)HookInlinePreCreateFileA, (PROC)HookInlinePostCreateFileA) == FALSE) {
            DbgMsg("[-] main - SetupInlineHook failed!\n");
        }
        if (SetupPrePostInlineHook((ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc"), (PROC)HookInlinePreVirtualAlloc, (PROC)HookInlinePostVirtualAlloc) == FALSE) {
            DbgMsg("[-] main - SetupInlineHook failed!\n");
        }
    }
    return TRUE;
}
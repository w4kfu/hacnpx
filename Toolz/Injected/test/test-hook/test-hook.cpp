#include "test-hook.h"

VOID HookMessageBoxA(PPUSHED_REGS pRegs)
{
    DbgMsg("[+] HookMessageBoxA - MessageBoxA! called from "HEX_FORMAT"\n", GET_RETURN_ADDR(pRegs));
}

VOID HookInlineMesssageBoxA(PPUSHED_REGS pRegs)
{
    DbgMsg("[+] HookInlineMesssageBoxA - MessageBoxA! called from "HEX_FORMAT"\n", GET_RETURN_ADDR(pRegs));
}

LONG CALLBACK CallBackEP(PEXCEPTION_POINTERS ExceptionInfo)
{
    DbgMsg("[+] CallBackEP\n");
    DbgMsg("[+] EP : "HEX_FORMAT"\n", (ULONG_PTR)GET_IP(ExceptionInfo));
    RemoveBreakpoint((ULONG_PTR)GET_IP(ExceptionInfo));
    SetupPreMadeHookVirtualProtect();
    return EXCEPTION_CONTINUE_EXECUTION;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    (void)hinstDLL;
    (void)lpReserved;

    if (fdwReason == DLL_PROCESS_ATTACH) {
        StartInjected();
        //LoadLibraryA("USER32.dll");
        //if (SetupIATHook((ULONG_PTR)GetModuleHandleA(NULL), "USER32.dll", "MessageBoxA", (PROC)HookMessageBoxA) == FALSE) {
        //    DbgMsg("[-] SetupIATHook failed!\n");
        //}
        //if (SetupInlineHook("USER32.dll", "MessageBoxA", (PROC)HookInlineMesssageBoxA) == FALSE) {
        //    DbgMsg("[-] SetupInlineHook failed!\n");
        //}
        // SetupPreMadeHookVirtualProtect();
        SetupPreMadeHookSocket();
        SetupPreMadeHookRecv();
        SetupPreMadeHookSend();
        SetupPreMadeHookSendto();
        SetupPreMadeHookConnect();
        SetupPreMadeHookWSASend();
        SetupPreMadeHookWSASendTo();
        SetupPreMadeHookWSAConnect();
        //AddBreakpointAtEP(CallBackEP);
    }
    return TRUE;
}
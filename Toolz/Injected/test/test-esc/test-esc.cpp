#include "test-esc.h"

LONG CALLBACK CallBackNearOEP(PEXCEPTION_POINTERS ExceptionInfo)
{
    DbgMsg("[+] CallBackNearOEP\n");
    DbgMsg("[+] IP : "HEX_FORMAT"\n", GET_IP(ExceptionInfo));
    //DumpPE((ULONG_PTR)GetModuleHandle(NULL), "test_dumped.exe");
    DebugBreak();
    return EXCEPTION_CONTINUE_EXECUTION;
    //ExitProcess(42);
}

VOID HookMessageBoxA(PPUSHED_REGS pRegs)
{
    DbgMsg("[+] MessageBoxA! called from "HEX_FORMAT"\n", GET_RETURN_ADDR(pRegs));
}

LONG CALLBACK CallBackEP(PEXCEPTION_POINTERS ExceptionInfo)
{
    DbgMsg("[+] CallBackEP\n");
    DbgMsg("[+] EP : "HEX_FORMAT"\n", (ULONG_PTR)GET_IP(ExceptionInfo));
    /* RemoveBreakpoint((ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress); */
    RemoveBreakpoint((ULONG_PTR)GET_IP(ExceptionInfo));
    //GuardUntilExecSection("<", CallBackNearOEP);
    //DumpPE((ULONG_PTR)GetModuleHandle(NULL), "test_dumped.exe");
    return EXCEPTION_CONTINUE_EXECUTION;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    (void)hinstDLL;
    (void)lpReserved;

    if (fdwReason == DLL_PROCESS_ATTACH) {
        StartInjected();
        AddBreakpointAtEP(CallBackEP);
        LoadLibraryA("USER32.dll");
        if (SetupIATHook((ULONG_PTR)GetModuleHandleA(NULL), "USER32.dll", "MessageBoxA", (PROC)HookMessageBoxA) == FALSE) {
            DbgMsg("[-] SetupIATHook failed!\n");
        }
    }
    return TRUE;
}
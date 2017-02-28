#include "test-pespin.h"

LONG CALLBACK CallBackNearOEP(PEXCEPTION_POINTERS ExceptionInfo)
{
    DbgMsg("[+] CallBackNearOEP\n");
    DbgMsg("[+] IP : " HEX_FORMAT "\n", GET_IP(ExceptionInfo));
    DisasAt((PBYTE)GET_IP(ExceptionInfo), 0x40, GET_IP(ExceptionInfo));
    SearchAutoIAT((ULONG_PTR)GetModuleHandle(NULL), GET_IP(ExceptionInfo));
    DumpPE((ULONG_PTR)GetModuleHandle(NULL), "test_dumped.exe", (ULONG_PTR)GET_IP(ExceptionInfo) - (ULONG_PTR)GetModuleHandle(NULL), TRUE);
    return EXCEPTION_CONTINUE_EXECUTION;
}

LONG CALLBACK CallBackEP(PEXCEPTION_POINTERS ExceptionInfo)
{
    DbgMsg("[+] CallBackEP\n");
    DbgMsg("[+] EP : " HEX_FORMAT "\n", (ULONG_PTR)GET_IP(ExceptionInfo));
    RemoveBreakpoint((ULONG_PTR)GET_IP(ExceptionInfo));
    GuardUntilExecSection(".text", CallBackNearOEP);
    return EXCEPTION_CONTINUE_EXECUTION;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    (void)hinstDLL;
    (void)lpReserved;

    if (fdwReason == DLL_PROCESS_ATTACH) {
        StartInjected();
        AddBreakpointAtEP(CallBackEP);
    }
    return TRUE;
}
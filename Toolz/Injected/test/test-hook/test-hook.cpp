#include "test-hook.h"

VOID HookMessageBoxA(PPUSHED_REGS pRegs)
{
    DbgMsg("[+] MessageBoxA! called from "HEX_FORMAT"\n", GET_RETURN_ADDR(pRegs));
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    (void)hinstDLL;
    (void)lpReserved;

    if (fdwReason == DLL_PROCESS_ATTACH) {
        StartInjected();
        LoadLibraryA("USER32.dll");
        if (SetupIATHook((ULONG_PTR)GetModuleHandleA(NULL), "USER32.dll", "MessageBoxA", (PROC)HookMessageBoxA) == FALSE) {
            DbgMsg("[-] SetupIATHook failed!\n");
        }
    }
    return TRUE;
}
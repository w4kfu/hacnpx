#include "injected.h"

VOID StartInjected(VOID)
{
    MakeConsole();
    DbgMsg("[+] DLL Injected\n");
    FillPeInfo();
}
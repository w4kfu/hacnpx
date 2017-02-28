#include "injected.h"

VOID StartInjected(VOID)
{
    PCHAR CmdLine = NULL;

    MakeConsole();
    DbgMsg("[+] DLL Injected\n");
    CmdLine = GetCommandLineA();
    if (CmdLine) {
        DbgMsg("[+] CmdLine : %s\n", CmdLine);
    }
    FillPeInfo();
}
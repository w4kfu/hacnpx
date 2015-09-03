#include <windows.h>
#include <stdio.h>

#include "modules.h"
#include "dbg.h"
#include "pestuff.h"
#include "memory.h"
#include "dump.h"

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    ULONG_PTR BaseOfImage = 0;
    HMODULE hMod = NULL;
    std::list<EXPORTENTRY> lExport;
    
    DbgMsg("[+] Launching test\n");
    MyRtlPcToFileHeader((ULONG_PTR)main, &BaseOfImage);
    DbgMsg("[+] BaseOfImage : "HEX_FORMAT"\n", BaseOfImage);
    PCHAR pName = (PCHAR)GetSectionInfo(BaseOfImage, 0x2000, SEC_NAME);
    DbgMsg("[+] pName : %s\n", pName);
    DbgMsg("[+] SizeOfImage : %08X\n", ParsePE(BaseOfImage, SIZE_OF_IMAGE));
    DbgMsg("[+] NumberOfSections : %d\n", ParsePE(BaseOfImage, NB_SECTIONS));
    DbgMsg("[+] IsBadReadMemory(main) : %d\n", IsBadReadMemory(main, 0));
    DbgMsg("[+] IsBadReadMemory(0x42424242) : %d\n", IsBadReadMemory((void*)0x42424242, 0));
    hMod = GetModuleHandleA("kernel32.dll");
    DbgMsg("[+] hMod : "HEX_FORMAT"\n", hMod);
    lExport = GetExport((ULONG_PTR)hMod);
    PrintExportEntry(lExport);
    DumpPE((ULONG_PTR)GetModuleHandle(NULL), "test_dumped.exe");
    //DebugBreak();
}
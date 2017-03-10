#include "injected.h"

extern PE_INFO pinfo;

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

int main(int argc, char *argv[])
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    //ULONG_PTR BaseOfImage = 0;
    //HMODULE hMod = NULL;
    std::list<PEXPORTENTRY> lExport;

    //StartInjected();
    //DbgMsg("[+] Launching test\n");
    //MyRtlPcToFileHeader((ULONG_PTR)main, &BaseOfImage);
    //DbgMsg("[+] BaseOfImage : " HEX_FORMAT "\n", BaseOfImage);
    //PCHAR pName = (PCHAR)GetSectionInfo(BaseOfImage, 0x2000, SEC_NAME);
    //DbgMsg("[+] pName : %s\n", pName);
    //DbgMsg("[+] SizeOfImage : %08X\n", ParsePE(BaseOfImage, SIZE_OF_IMAGE));
    //DbgMsg("[+] NumberOfSections : %d\n", ParsePE(BaseOfImage, NB_SECTIONS));
    //DbgMsg("[+] IsBadReadMemory(main) : %d\n", IsBadReadMemory(main, 0));
    //DbgMsg("[+] IsBadReadMemory(0x42424242) : %d\n", IsBadReadMemory((void*)0x42424242, 0));
    //hMod = GetModuleHandleA("kernel32.dll");
    //DbgMsg("[+] hMod : " HEX_FORMAT "\n", hMod);
    //lExport = GetExportList((ULONG_PTR)hMod);
    //PrintExportEntry(lExport);
    //DumpPE((ULONG_PTR)GetModuleHandle(NULL), "test_dumped.exe");
    
    //DebugBreak();
    
    LoadLibraryA("test-hook.dll");
    
    //DbgMsg("SUCE\n");
    
    //if (SetupPrePostInlineHook((ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc"), (PROC)HookInlinePreVirtualAlloc, (PROC)HookInlinePostVirtualAlloc) == FALSE) {
    //    DbgMsg("[-] main - SetupInlineHook failed!\n");
    //}
    //
    //for (int i = 0; i < 0x100; i++) {
    VirtualAlloc((LPVOID)0x42424242, 0x42424242, 0x42424242, 0x42424242);
    CreateFileA((LPCTSTR)NULL, 0x42424242, 0x42424242, (LPSECURITY_ATTRIBUTES)0x42424242, 0x42424242, 0x42424242, (HANDLE)0x42424242);
    
    system("pause");
    
    //}
    //
    //
    //if (SetupPrePostInlineHook((ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileA"), (PROC)HookInlinePreCreateFileA, (PROC)HookInlinePostCreateFileA) == FALSE) {
    //    DbgMsg("[-] main - SetupInlineHook failed!\n");
    //}
    //
    //for (int i = 0; i < 0x100; i++) {
    //    VirtualAlloc((LPVOID)0x42424242, 0x42424242, 0x42424242, 0x42424242);
    //    CreateFileA((LPCTSTR)NULL, 0x42424242, 0x42424242, (LPSECURITY_ATTRIBUTES)0x42424242, 0x42424242, 0x42424242, (HANDLE)0x42424242);
    //}
    //DebugBreak();
}
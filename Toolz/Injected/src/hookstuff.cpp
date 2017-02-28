#include "hookstuff.h"

extern PE_INFO pinfo;

#ifdef _WIN64
BYTE GenericTrampo[] =  "\x54"                                      // push    rsp
                        "\x50"                                      // push    rax
                        "\x53"                                      // push    rbx
                        "\x51"                                      // push    rcx
                        "\x52"                                      // push    rdx
                        "\x55"                                      // push    rbp
                        "\x57"                                      // push    rdi
                        "\x56"                                      // push    rsi
                        "\x41\x50"                                  // push    r8
                        "\x41\x51"                                  // push    r9
                        "\x41\x52"                                  // push    r10
                        "\x41\x53"                                  // push    r11
                        "\x41\x54"                                  // push    r12
                        "\x41\x55"                                  // push    r13
                        "\x41\x56"                                  // push    r14
                        "\x41\x57"                                  // push    r15
                        "\x48\x8B\xCC"                              // mov     rcx, rsp
                        "\x48\x83\xEC\x28"                          // sub     rsp, 28h
                        "\xFF\x15\x36\x00\x00\x00"                  // call    cs:HookFunc
                        "\x48\x83\xC4\x28"                          // add     rsp, 28h
                        "\x41\x5F"                                  // pop     r15
                        "\x41\x5E"                                  // pop     r14
                        "\x41\x5D"                                  // pop     r13
                        "\x41\x5C"                                  // pop     r12
                        "\x41\x5B"                                  // pop     r11
                        "\x41\x5A"                                  // pop     r10
                        "\x41\x59"                                  // pop     r9
                        "\x41\x58"                                  // pop     r8
                        "\x5E"                                      // pop     rsi
                        "\x5F"                                      // pop     rdi
                        "\x5D"                                      // pop     rbp
                        "\x5A"                                      // pop     rdx
                        "\x59"                                      // pop     rcx
                        "\x5B"                                      // pop     rbx
                        "\x58"                                      // pop     rax
                        "\x5C"                                      // pop     rsp
                        "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"  // place for instructions to restore
                        "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
                        "\xFF\x25\x08\x00\x00\x00"                  // jmp     cs:Mm
                        "\x48\x47\x46\x45\x44\x43\x42\x41"          // HookFunc dq 4142434445464748h
                        "\x48\x47\x46\x45\x44\x43\x42\x41";         // Mm dq 4142434445464748h
#else
BYTE GenericTrampo[] = "\x60"                                       // pushad
                       "\x8B\xCC"                                   // mov ecx, esp
                       "\xE8\x00\x00\x00\x00"                       // call $+5
                       "\x5B"                                       // pop ebx
                       "\x8B\x43\x25"                               // mov eax, [ebx + 0x25]
                       "\x51"                                       // push ecx
                       "\xFF\xD0"                                   // call eax
                       "\x83\xC4\x04"                               // add esp, 0x4
                       "\x61"                                       // popad
                       "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"   // place for instructions to restore
                       "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"   //
                       "\xFF\x25\x43\x43\x43\x43"                   // jmp [????]
                       "\x41\x41\x41\x41"                           // 0x41414141
                       "\x42\x42\x42\x42";                          // 0x42424242
#endif

BOOL SetupIATHook(ULONG_PTR BaseAddress, LPCSTR ModName, LPCSTR ProcName, PROC pfnNew)
{
    PVOID Trampo = NULL;
    PROC pfnCurrent = NULL;

    pfnCurrent = GetProcAddress(GetModuleHandleA(ModName), ProcName);
    if (pfnCurrent == NULL) {
        DbgMsg("[+] SetupIATHook - GetProcAddress failed : %lu\n", GetLastError());
    }
    if (pfnNew == NULL) {
        DbgMsg("[+] SetupIATHook - pfnNew NULL\n");
    }
    Trampo = VirtualAlloc(0, sizeof (GenericTrampo), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (Trampo == NULL) {
        DbgMsg("[-] SetupIATHook - VirtualAlloc failed : %lu\n", GetLastError());
        return FALSE;
    }
    memcpy(Trampo, GenericTrampo, sizeof (GenericTrampo));
    *(ULONG_PTR*)((ULONG_PTR)Trampo + sizeof (GenericTrampo) - sizeof (ULONG_PTR) - 1) = (ULONG_PTR)pfnCurrent;
    *(ULONG_PTR*)((ULONG_PTR)Trampo + sizeof (GenericTrampo) - (sizeof (ULONG_PTR) * 2) - 1) = (ULONG_PTR)pfnNew;
    #ifndef _WIN64
        *(ULONG_PTR*)((ULONG_PTR)Trampo + sizeof (GenericTrampo) - (sizeof (ULONG_PTR) * 3) - 1) = (ULONG_PTR)Trampo + (ULONG_PTR)sizeof (GenericTrampo) - 1 - sizeof (ULONG_PTR);
    #endif
    return ReplaceIATEntryInMod(BaseAddress, ModName, pfnCurrent, (PROC)Trampo);
}

BOOL ReplaceIATEntryInMod(ULONG_PTR BaseAddress, LPCSTR ModName, PROC pfnCurrent, PROC pfnNew)
{
    ULONG Size = 0;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = NULL;
    PIMAGE_THUNK_DATA pThunk = NULL;
    DWORD dwOldProt = 0;
    PROC* ppfn = NULL;
    LPCSTR ActualModName;

    pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx((PVOID)BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &Size, NULL);
    if (pImportDesc == NULL) {
        DbgMsg("[-] ReplaceIATEntryInMod - ImageDirectoryEntryToDataEx failed : %lu\n", GetLastError());
        return FALSE;
    }
    for (; pImportDesc->Name; pImportDesc++) {
        ActualModName = (LPCSTR)((PBYTE)BaseAddress + pImportDesc->Name);
        if (lstrcmpiA(ActualModName, ModName) == 0)
            break;
    }
    if (pImportDesc->Name == 0) {
        DbgMsg("[-] ReplaceIATEntryInMod - no import found for %s\n", ModName);
        return FALSE;
    }
    pThunk = (PIMAGE_THUNK_DATA)((PBYTE)BaseAddress + pImportDesc->FirstThunk);
    for (; pThunk->u1.Function; pThunk++) {
        ppfn = (PROC*)&pThunk->u1.Function;
        if (*ppfn == pfnCurrent) {
            VirtualProtect(ppfn, sizeof(pfnNew), PAGE_EXECUTE_READWRITE, &dwOldProt);
            *ppfn = pfnNew;
            VirtualProtect(ppfn, sizeof(pfnNew), dwOldProt, &dwOldProt);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL SetupInlineHook(LPCSTR ModName, LPCSTR ProcName, PROC pfnNew)
{
    HMODULE hModule = NULL;
    ULONG_PTR Addr = 0;

    if (ModName == NULL || ProcName == NULL) {
        return FALSE;
    }
    hModule = GetModuleHandleA(ModName);
    if (hModule == NULL) {
        DbgMsg("[-] SetupInlineHook - GetModuleHandleA failed : %lu\n", GetLastError());
        return FALSE;
    }
    Addr = (ULONG_PTR)GetProcAddress(hModule, ProcName);
    if (Addr == 0) {
        DbgMsg("[-] SetupInlineHook - GetProcAddress failed : %lu\n", GetLastError());
        return FALSE;
    }
    return SetupInlineHook(Addr, pfnNew);
}

ULONG_PTR FindPrevFreeRegion(LPVOID pAddress, LPVOID pMinAddr, DWORD dwAllocationGranularity)
{
    ULONG_PTR tryAddr = (ULONG_PTR)pAddress;

    tryAddr -= tryAddr % dwAllocationGranularity;
    tryAddr -= dwAllocationGranularity;
    while (tryAddr >= (ULONG_PTR)pMinAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPVOID)tryAddr, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == 0) {
            DbgMsg("[-] FindPrevFreeRegion - VirtualQuery failed : %lu\n", GetLastError());
            break;
        }
        if (mbi.State == MEM_FREE) {
            return tryAddr;
        }
        if ((ULONG_PTR)mbi.AllocationBase < dwAllocationGranularity) {
            break;
        }
        tryAddr = (ULONG_PTR)mbi.AllocationBase - dwAllocationGranularity;
    }
    return NULL;
}

ULONG_PTR FindFreeMemory(ULONG_PTR pOrigin)
{
    SYSTEM_INFO si;
    ULONG_PTR minAddr;
    ULONG_PTR maxAddr;
    ULONG_PTR pAlloc = pOrigin;
    LPVOID pBlock = NULL;
    
    GetSystemInfo(&si);
    minAddr = (ULONG_PTR)si.lpMinimumApplicationAddress;
    maxAddr = (ULONG_PTR)si.lpMaximumApplicationAddress;
    while ((ULONG_PTR)pAlloc >= minAddr) {
        pAlloc = FindPrevFreeRegion((LPVOID)pAlloc, (LPVOID)minAddr, si.dwAllocationGranularity);
        if (pAlloc == NULL) {
            break;
        }
        pBlock = VirtualAlloc((LPVOID)pAlloc, 0x20, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (pBlock != NULL) {
            break;
        }
    }
    if (pBlock == NULL) {
        DbgMsg("[-] FindFreeMemory - ERROR!\n");
        exit(EXIT_FAILURE);
    }
    //printf("[+] NEW ADDR : " HEX_FORMAT "\n", pBlock);
    return (ULONG_PTR)pBlock;
}

BOOL SetupInlineHookOld(ULONG_PTR Addr, PROC pfnNew)
{
    PVOID Trampo = NULL;
    DWORD dwLen = 0;
    DWORD dwOldProt = 0;
    ULONG_PTR Dst;

    if (Addr == 0) {
        return FALSE;
    }
    Trampo = VirtualAlloc(0, sizeof (GenericTrampo), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (Trampo == NULL) {
        DbgMsg("[-] SetupIATHook - VirtualAlloc failed : %lu\n", GetLastError());
        return FALSE;
    }
    memcpy(Trampo, GenericTrampo, sizeof (GenericTrampo));
    while (GetJmpIndirect((PBYTE)Addr, &Dst) == TRUE) {
        Addr = Dst;
    }
#if _WIN64
    while (dwLen < 14) {
#else
    while (dwLen < 5) {
#endif
        //dwLen += LDE((PVOID)(Addr + dwLen), LDE_X86);
        dwLen += DisasLength((PBYTE)(Addr + dwLen));
    }
    memcpy((PBYTE)Trampo + sizeof (GenericTrampo) - (sizeof (ULONG_PTR) * 2) - 1 - 26, (PVOID)Addr, dwLen);
    VirtualProtect((LPVOID)Addr, dwLen, PAGE_EXECUTE_READWRITE, &dwOldProt);
#if _WIN64
    *(PBYTE)Addr = 0xFF;
    *(PBYTE)((PBYTE)Addr + 1) = 0x25;
    *(PDWORD)((PBYTE)Addr + 2) = (DWORD)0;
    *(PDWORD64)((PBYTE)Addr + 6) = (DWORD64)Trampo;
#else
    *(PBYTE)Addr = 0xE9;
    *(PDWORD)((PBYTE)Addr + 1) = (BYTE*)Trampo - (BYTE*)Addr - 5;
#endif
    *(ULONG_PTR*)((ULONG_PTR)Trampo + sizeof (GenericTrampo) - sizeof (ULONG_PTR) - 1) = (ULONG_PTR)Addr + dwLen;
    *(ULONG_PTR*)((ULONG_PTR)Trampo + sizeof (GenericTrampo) - (sizeof (ULONG_PTR) * 2) - 1) = (ULONG_PTR)pfnNew;
    #ifndef _WIN64
        *(ULONG_PTR*)((ULONG_PTR)Trampo + sizeof (GenericTrampo) - (sizeof (ULONG_PTR) * 3) - 1) = (ULONG_PTR)Trampo + (ULONG_PTR)sizeof (GenericTrampo) - 1 - sizeof (ULONG_PTR);
    #endif
    VirtualProtect((LPVOID)Addr, dwLen, dwOldProt, &dwOldProt);
    return TRUE;
}

BOOL SetupInlineHook(ULONG_PTR Addr, PROC pfnNew)
{
    PVOID Trampo = NULL;
    DWORD dwLen = 0;
    DWORD dwOldProt = 0;
    ULONG_PTR Dst;
    
    if (Addr == 0) {
        return FALSE;
    }
    Trampo = VirtualAlloc(0, sizeof (GenericTrampo), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (Trampo == NULL) {
        DbgMsg("[-] SetupInlineHook - VirtualAlloc failed : %lu\n", GetLastError());
        return FALSE;
    }
    memcpy(Trampo, GenericTrampo, sizeof (GenericTrampo));
    while (GetJmpIndirect((PBYTE)Addr, &Dst) == TRUE) {
        Addr = Dst;
    }
//#if _WIN64
//    while (dwLen < 14) {
//#else
    while (dwLen < 5) {
//#endif
        //dwLen += LDE((PVOID)(Addr + dwLen), LDE_X86);
        dwLen += DisasLength((PBYTE)(Addr + dwLen));
    }
    memcpy((PBYTE)Trampo + sizeof (GenericTrampo) - (sizeof (ULONG_PTR) * 2) - 1 - 26, (PVOID)Addr, dwLen);
    if (!VirtualProtect((LPVOID)Addr, dwLen, PAGE_EXECUTE_READWRITE, &dwOldProt)) {
        DbgMsg("[-] SetupInlineHook - VirtualProtect failed : %lu\n", GetLastError());
        return FALSE;
    }
#if _WIN64
    ULONG_PTR RelayFunc = FindFreeMemory(Addr);
    if (RelayFunc == NULL) {
        return FALSE;
    }
    *(PBYTE)RelayFunc = 0xFF;
    *(PBYTE)((PBYTE)RelayFunc + 1) = 0x25;
    *(PDWORD)((PBYTE)RelayFunc + 2) = (DWORD)0;
    *(PDWORD64)((PBYTE)RelayFunc + 6) = (DWORD64)Trampo;
    *(PBYTE)Addr = 0xE9;
    *(PDWORD)((PBYTE)Addr + 1) = (DWORD)((BYTE*)RelayFunc - (BYTE*)Addr - 5);
#else
    *(PBYTE)Addr = 0xE9;
    *(PDWORD)((PBYTE)Addr + 1) = (BYTE*)Trampo - (BYTE*)Addr - 5;
#endif
    *(ULONG_PTR*)((ULONG_PTR)Trampo + sizeof (GenericTrampo) - sizeof (ULONG_PTR) - 1) = (ULONG_PTR)Addr + dwLen;
    *(ULONG_PTR*)((ULONG_PTR)Trampo + sizeof (GenericTrampo) - (sizeof (ULONG_PTR) * 2) - 1) = (ULONG_PTR)pfnNew;
    #ifndef _WIN64
        *(ULONG_PTR*)((ULONG_PTR)Trampo + sizeof (GenericTrampo) - (sizeof (ULONG_PTR) * 3) - 1) = (ULONG_PTR)Trampo + (ULONG_PTR)sizeof (GenericTrampo) - 1 - sizeof (ULONG_PTR);
    #endif
    VirtualProtect((LPVOID)Addr, dwLen, dwOldProt, &dwOldProt);
    FlushInstructionCache(GetCurrentProcess(), (LPCVOID)Addr, 0x06);
    return TRUE;
}

/* kernel32.dll!VirtualProtect */

VOID PreMadeHookVirtualProtect(PPUSHED_REGS pRegs)
{
    ULONG_PTR RetAddr;

    RetAddr = GET_RETURN_ADDR(pRegs);
    if (RetAddr >= pinfo.ModuleInjectedBase && (RetAddr < (pinfo.ModuleInjectedBase + pinfo.ModuleInjectedSize)))
        return;
    DbgMsg("[+] VirtualProtect(" HEX_FORMAT ", 0x%08X, 0x%08X, 0x%08X); => " HEX_FORMAT "\n", GET_ARG_1(pRegs), GET_ARG_2(pRegs), GET_ARG_3(pRegs), GET_ARG_4(pRegs), RetAddr);
}

VOID SetupPreMadeHookVirtualProtect(VOID)
{
    if (SetupInlineHook("kernel32.dll", "VirtualProtect", (PROC)PreMadeHookVirtualProtect) == FALSE) {
        DbgMsg("[-] SetupPreMadeHookVirtualProtect - SetupInlineHook failed!\n");
    }
}

/* Ws2_32.dll!socket */

VOID PreMadeHookSocket(PPUSHED_REGS pRegs)
{
    ULONG_PTR RetAddr;

    RetAddr = GET_RETURN_ADDR(pRegs);
    if (RetAddr >= pinfo.ModuleInjectedBase && (RetAddr < (pinfo.ModuleInjectedBase + pinfo.ModuleInjectedSize)))
        return;
    DbgMsg("[+] socket(0x%08X, 0x%08X, 0x%08X); => " HEX_FORMAT "\n", GET_ARG_1(pRegs), GET_ARG_2(pRegs), GET_ARG_3(pRegs), RetAddr);
}

VOID SetupPreMadeHookSocket(VOID)
{
    if (LoadLibraryA("Ws2_32.dll") == NULL) {
        DbgMsg("[-] SetupPreMadeHookSocket - LoadLibraryA failed : %lu\n", GetLastError());
        return;
    }
    if (SetupInlineHook("Ws2_32.dll", "socket", (PROC)PreMadeHookSocket) == FALSE) {
        DbgMsg("[-] SetupPreMadeHookSocket - SetupInlineHook failed!\n");
    }
}

/* Ws2_32.dll!recv */

VOID PreMadeHookRecv(PPUSHED_REGS pRegs)
{
    ULONG_PTR RetAddr;

    RetAddr = GET_RETURN_ADDR(pRegs);
    if (RetAddr >= pinfo.ModuleInjectedBase && (RetAddr < (pinfo.ModuleInjectedBase + pinfo.ModuleInjectedSize)))
        return;
    DbgMsg("[+] recv(0x%08X, " HEX_FORMAT ", 0x%08X, 0x%08X); => " HEX_FORMAT "\n", GET_ARG_1(pRegs), GET_ARG_2(pRegs), GET_ARG_3(pRegs), GET_ARG_4(pRegs), RetAddr);
}

VOID SetupPreMadeHookRecv(VOID)
{
    if (LoadLibraryA("Ws2_32.dll") == NULL) {
        DbgMsg("[-] SetupPreMadeHookRecv - LoadLibraryA failed : %lu\n", GetLastError());
        return;
    }
    if (SetupInlineHook("Ws2_32.dll", "recv", (PROC)PreMadeHookRecv) == FALSE) {
        DbgMsg("[-] SetupPreMadeHookRecv - SetupInlineHook failed!\n");
    }
}

/* Ws2_32.dll!send */

VOID PreMadeHookSend(PPUSHED_REGS pRegs)
{
    ULONG_PTR RetAddr;

    RetAddr = GET_RETURN_ADDR(pRegs);
    if (RetAddr >= pinfo.ModuleInjectedBase && (RetAddr < (pinfo.ModuleInjectedBase + pinfo.ModuleInjectedSize)))
        return;
    DbgMsg("[+] send(0x%08X, " HEX_FORMAT ", 0x%08X, 0x%08X); => " HEX_FORMAT "\n", GET_ARG_1(pRegs), GET_ARG_2(pRegs), GET_ARG_3(pRegs), GET_ARG_4(pRegs), RetAddr);
}

VOID SetupPreMadeHookSend(VOID)
{
    if (LoadLibraryA("Ws2_32.dll") == NULL) {
        DbgMsg("[-] SetupPreMadeHookSend - LoadLibraryA failed : %lu\n", GetLastError());
        return;
    }
    if (SetupInlineHook("Ws2_32.dll", "send", (PROC)PreMadeHookSend) == FALSE) {
        DbgMsg("[-] SetupPreMadeHookSend - SetupInlineHook failed!\n");
    }
}

/* Ws2_32.dll!sendto */

VOID PreMadeHookSendto(PPUSHED_REGS pRegs)
{
    ULONG_PTR RetAddr;

    RetAddr = GET_RETURN_ADDR(pRegs);
    if (RetAddr >= pinfo.ModuleInjectedBase && (RetAddr < (pinfo.ModuleInjectedBase + pinfo.ModuleInjectedSize)))
        return;
    DbgMsg("[+] sendto(0x%08X, " HEX_FORMAT ", 0x%08X, 0x%08X, ...); => " HEX_FORMAT "\n", GET_ARG_1(pRegs), GET_ARG_2(pRegs), GET_ARG_3(pRegs), GET_ARG_4(pRegs), RetAddr);
    HexDump((PVOID)GET_ARG_2(pRegs), GET_ARG_3(pRegs) < 0x100 ? GET_ARG_3(pRegs) : 0x100); 
}

VOID SetupPreMadeHookSendto(VOID)
{
    if (LoadLibraryA("Ws2_32.dll") == NULL) {
        DbgMsg("[-] SetupPreMadeHookSendto - LoadLibraryA failed : %lu\n", GetLastError());
        return;
    }
    if (SetupInlineHook("Ws2_32.dll", "sendto", (PROC)PreMadeHookSendto) == FALSE) {
        DbgMsg("[-] SetupPreMadeHookSendto - SetupInlineHook failed!\n");
    }
}

/* Ws2_32.dll!connect */

VOID PreMadeHookConnect(PPUSHED_REGS pRegs)
{
    ULONG_PTR RetAddr;

    RetAddr = GET_RETURN_ADDR(pRegs);
    if (RetAddr >= pinfo.ModuleInjectedBase && (RetAddr < (pinfo.ModuleInjectedBase + pinfo.ModuleInjectedSize)))
        return;
    DbgMsg("[+] connect(0x%08X, " HEX_FORMAT ", 0x%08X); => " HEX_FORMAT "\n", GET_ARG_1(pRegs), GET_ARG_2(pRegs), GET_ARG_3(pRegs), RetAddr);
}

VOID SetupPreMadeHookConnect(VOID)
{
    if (LoadLibraryA("Ws2_32.dll") == NULL) {
        DbgMsg("[-] SetupPreMadeHookConnect - LoadLibraryA failed : %lu\n", GetLastError());
        return;
    }
    if (SetupInlineHook("Ws2_32.dll", "connect", (PROC)PreMadeHookConnect) == FALSE) {
        DbgMsg("[-] SetupPreMadeHookConnect - SetupInlineHook failed!\n");
    }
}

/* Ws2_32.dll!WSAConnect */

VOID PreMadeHookWSAConnect(PPUSHED_REGS pRegs)
{
    ULONG_PTR RetAddr;

    RetAddr = GET_RETURN_ADDR(pRegs);
    if (RetAddr >= pinfo.ModuleInjectedBase && (RetAddr < (pinfo.ModuleInjectedBase + pinfo.ModuleInjectedSize)))
        return;
    DbgMsg("[+] WSAConnect(...); => " HEX_FORMAT "\n", RetAddr);
}

VOID SetupPreMadeHookWSAConnect(VOID)
{
    if (LoadLibraryA("Ws2_32.dll") == NULL) {
        DbgMsg("[-] SetupPreMadeHookWSAConnect - LoadLibraryA failed : %lu\n", GetLastError());
        return;
    }
    if (SetupInlineHook("Ws2_32.dll", "WSAConnect", (PROC)PreMadeHookWSAConnect) == FALSE) {
        DbgMsg("[-] SetupPreMadeHookWSAConnect - SetupInlineHook failed!\n");
    }
}

/* Ws2_32.dll!WSASend */

VOID PreMadeHookWSASend(PPUSHED_REGS pRegs)
{
    ULONG_PTR RetAddr;
    LPWSABUF lpBuffers;
    DWORD dwBufferCount;

    RetAddr = GET_RETURN_ADDR(pRegs);
    if (RetAddr >= pinfo.ModuleInjectedBase && (RetAddr < (pinfo.ModuleInjectedBase + pinfo.ModuleInjectedSize)))
        return;
    lpBuffers = (LPWSABUF)GET_ARG_2(pRegs);
    dwBufferCount = (DWORD)GET_ARG_3(pRegs);
    if (dwBufferCount > 1) {
        DbgMsg("[-] PreMadeHookWSASend - dwBufferCount > 1\n");
    }
    DbgMsg("[+] WSASend(" HEX_FORMAT ", 0x%08X); => " HEX_FORMAT "\n", lpBuffers[0].buf, lpBuffers[0].len, RetAddr);
    HexDump(lpBuffers[0].buf, lpBuffers[0].len < 0x100 ? lpBuffers[0].len : 0x100); 
}

VOID SetupPreMadeHookWSASend(VOID)
{
    if (LoadLibraryA("Ws2_32.dll") == NULL) {
        DbgMsg("[-] SetupPreMadeHookWSASend - LoadLibraryA failed : %lu\n", GetLastError());
        return;
    }
    if (SetupInlineHook("Ws2_32.dll", "WSASend", (PROC)PreMadeHookWSASend) == FALSE) {
        DbgMsg("[-] SetupPreMadeHookWSASend - SetupInlineHook failed!\n");
    }
}

/* Ws2_32.dll!WSASendTo */

VOID PreMadeHookWSASendTo(PPUSHED_REGS pRegs)
{
    ULONG_PTR RetAddr;
    LPWSABUF lpBuffers;
    DWORD dwBufferCount;

    RetAddr = GET_RETURN_ADDR(pRegs);
    if (RetAddr >= pinfo.ModuleInjectedBase && (RetAddr < (pinfo.ModuleInjectedBase + pinfo.ModuleInjectedSize)))
        return;
    lpBuffers = (LPWSABUF)GET_ARG_2(pRegs);
    dwBufferCount = (DWORD)GET_ARG_3(pRegs);
    if (dwBufferCount > 1) {
        DbgMsg("[-] PreMadeHookWSASend - dwBufferCount > 1\n");
    }
    DbgMsg("[+] WSASendTo(" HEX_FORMAT ", 0x%08X); => " HEX_FORMAT "\n", lpBuffers[0].buf, lpBuffers[0].len, RetAddr);
    HexDump(lpBuffers[0].buf, lpBuffers[0].len < 0x100 ? lpBuffers[0].len : 0x100); 
}


VOID SetupPreMadeHookWSASendTo(VOID)
{
    if (LoadLibraryA("Ws2_32.dll") == NULL) {
        DbgMsg("[-] SetupPreMadeHookWSASendTo - LoadLibraryA failed : %lu\n", GetLastError());
        return;
    }
    if (SetupInlineHook("Ws2_32.dll", "WSASendTo", (PROC)PreMadeHookWSASendTo) == FALSE) {
        DbgMsg("[-] SetupPreMadeHookWSASendTo - SetupInlineHook failed!\n");
    }
}

#ifdef _WIN64
BYTE GenericRetTrampo[] =  "\x54"                                      // push    rsp
                        "\x50"                                      // push    rax
                        "\x53"                                      // push    rbx
                        "\x51"                                      // push    rcx
                        "\x52"                                      // push    rdx
                        "\x55"                                      // push    rbp
                        "\x57"                                      // push    rdi
                        "\x56"                                      // push    rsi
                        "\x41\x50"                                  // push    r8
                        "\x41\x51"                                  // push    r9
                        "\x41\x52"                                  // push    r10
                        "\x41\x53"                                  // push    r11
                        "\x41\x54"                                  // push    r12
                        "\x41\x55"                                  // push    r13
                        "\x41\x56"                                  // push    r14
                        "\x41\x57"                                  // push    r15
                        "\x48\x8B\xCC"                              // mov     rcx, rsp
                        "\x48\x83\xEC\x20"                          // sub     rsp, 20h         // 28 -> 20 because 16 ALIGN FUCKED MMX ETC
                        "\xFF\x15\x36\x00\x00\x00"                  // call    cs:HookFunc
                        "\x48\x83\xC4\x20"                          // add     rsp, 20h
                        "\x41\x5F"                                  // pop     r15
                        "\x41\x5E"                                  // pop     r14
                        "\x41\x5D"                                  // pop     r13
                        "\x41\x5C"                                  // pop     r12
                        "\x41\x5B"                                  // pop     r11
                        "\x41\x5A"                                  // pop     r10
                        "\x41\x59"                                  // pop     r9
                        "\x41\x58"                                  // pop     r8
                        "\x5E"                                      // pop     rsi
                        "\x5F"                                      // pop     rdi
                        "\x5D"                                      // pop     rbp
                        "\x5A"                                      // pop     rdx
                        "\x59"                                      // pop     rcx
                        "\x5B"                                      // pop     rbx
                        "\x58"                                      // pop     rax
                        "\x5C"                                      // pop     rsp
                        "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"  // place for instructions to restore
                        "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
                        "\xFF\x25\x08\x00\x00\x00"                  // jmp     cs:Mm
                        "\x48\x47\x46\x45\x44\x43\x42\x41"          // HookFunc dq 4142434445464748h
                        "\x48\x47\x46\x45\x44\x43\x42\x41";         // Mm dq 4142434445464748h
#else
BYTE GenericRetTrampo[] = "\x60"                                      // pushad
                       "\x8B\xCC"                                   // mov ecx, esp
                       "\xE8\x00\x00\x00\x00"                       // call $+5
                       "\x5B"                                       // pop ebx
                       "\x8B\x43\x25"                               // mov eax, [ebx + 0x25]
                       "\x51"                                       // push ecx
                       "\xFF\xD0"                                   // call eax
                       "\x83\xC4\x04"                               // add esp, 0x4
                       "\x61"                                       // popad
                       "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"   // place for instructions to restore
                       "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"   //
                       "\xFF\x25\x43\x43\x43\x43"                   // jmp [????]
                       "\x41\x41\x41\x41"                           // 0x41414141
                       "\x42\x42\x42\x42";                          // 0x42424242
#endif

VOID SetupHookRetAddr(PPUSHED_REGS pRegs, PROC pfnNew)
{
    PVOID Trampo = NULL;

    Trampo = VirtualAlloc(0x00, sizeof (GenericRetTrampo), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (Trampo == NULL) {
        DbgMsg("[-] SetupHookReturnAddr - VirtualAlloc failed : %lu\n", GetLastError());
        return;
    }
    memcpy(Trampo, GenericRetTrampo, sizeof (GenericRetTrampo));
    *(ULONG_PTR*)((ULONG_PTR)Trampo + sizeof (GenericRetTrampo) - sizeof (ULONG_PTR) - 1) = (ULONG_PTR)GET_RETURN_ADDR(pRegs);
    *(ULONG_PTR*)((ULONG_PTR)Trampo + sizeof (GenericRetTrampo) - (sizeof (ULONG_PTR) * 2) - 1) = (ULONG_PTR)pfnNew;
    #ifndef _WIN64
        *(ULONG_PTR*)((ULONG_PTR)Trampo + sizeof (GenericRetTrampo) - (sizeof (ULONG_PTR) * 3) - 1) = (ULONG_PTR)Trampo + (ULONG_PTR)sizeof (GenericRetTrampo) - 1 - sizeof (ULONG_PTR);
    #endif
    GET_RETURN_ADDR(pRegs) = (ULONG_PTR)Trampo;
}
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

#ifdef _WIN64

BYTE RealGenericRetTrampo[] = "\x54\x50\x53\x51\x52\x55\x57\x56\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x48\x89\xE1\x48\x83\xEC\x28\xFF\x15\xBD\x00\x00\x00\x48\x83\xC4\x28\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5E\x5F\x5D\x5A\x59\x5B\x58\x5C\x50\x53\x65\x48\x8B\x04\x25\x30\x00\x00\x00\x48\x8B\x5C\x24\x10\x48\x05\x42\x42\x42\x42\x48\x89\x18\x48\x8D\x05\x28\x00\x00\x00\x48\x89\x44\x24\x10\x5B\x58\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xFF\x25\x69\x00\x00\x00\x54\x50\x53\x51\x52\x55\x57\x56\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x48\x89\xE1\x48\x83\xEC\x20\xFF\x15\x3C\x00\x00\x00\x48\x83\xC4\x20\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5E\x5F\x5D\x5A\x59\x5B\x58\x5C\x50\x65\x48\x8B\x04\x25\x30\x00\x00\x00\x48\x05\x42\x42\x42\x42\x48\x8B\x00\x48\x87\x04\x24\xC3\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";

// 0:  54                      push   rsp
// 1:  50                      push   rax
// 2:  53                      push   rbx
// 3:  51                      push   rcx
// 4:  52                      push   rdx
// 5:  55                      push   rbp
// 6:  57                      push   rdi
// 7:  56                      push   rsi
// 8:  41 50                   push   r8
// a:  41 51                   push   r9
// c:  41 52                   push   r10
// e:  41 53                   push   r11
// 10: 41 54                   push   r12
// 12: 41 55                   push   r13
// 14: 41 56                   push   r14
// 16: 41 57                   push   r15
// 18: 48 89 e1                mov    rcx,rsp
// 1b: 48 83 ec 28             sub    rsp,0x28
// 1f: ff 15 bd 00 00 00       call   QWORD PTR [rip+0xbd]        # e2 <HookFunc_pre>
// 25: 48 83 c4 28             add    rsp,0x28
// 29: 41 5f                   pop    r15
// 2b: 41 5e                   pop    r14
// 2d: 41 5d                   pop    r13
// 2f: 41 5c                   pop    r12
// 31: 41 5b                   pop    r11
// 33: 41 5a                   pop    r10
// 35: 41 59                   pop    r9
// 37: 41 58                   pop    r8
// 39: 5e                      pop    rsi
// 3a: 5f                      pop    rdi
// 3b: 5d                      pop    rbp
// 3c: 5a                      pop    rdx
// 3d: 59                      pop    rcx
// 3e: 5b                      pop    rbx
// 3f: 58                      pop    rax
// 40: 5c                      pop    rsp
// 41: 50                      push   rax
// 42: 53                      push   rbx
// 43: 65 48 8b 04 25 30 00    mov    rax,QWORD PTR gs:0x30
// 4a: 00 00
// 4c: 48 8b 5c 24 10          mov    rbx,QWORD PTR [rsp+0x10]
// 51: 48 05 42 42 42 42       add    rax,0x42424242
// 57: 48 89 18                mov    QWORD PTR [rax],rbx
// 5a: 48 8d 05 28 00 00 00    lea    rax,[rip+0x28]        # 89 <next_step>
// 61: 48 89 44 24 10          mov    QWORD PTR [rsp+0x10],rax
// 66: 5b                      pop    rbx
// 67: 58                      pop    rax
// 68: 90                      nop
// 69: 90                      nop
// 6a: 90                      nop
// 6b: 90                      nop
// 6c: 90                      nop
// 6d: 90                      nop
// 6e: 90                      nop
// 6f: 90                      nop
// 70: 90                      nop
// 71: 90                      nop
// 72: 90                      nop
// 73: 90                      nop
// 74: 90                      nop
// 75: 90                      nop
// 76: 90                      nop
// 77: 90                      nop
// 78: 90                      nop
// 79: 90                      nop
// 7a: 90                      nop
// 7b: 90                      nop
// 7c: 90                      nop
// 7d: 90                      nop
// 7e: 90                      nop
// 7f: 90                      nop
// 80: 90                      nop
// 81: 90                      nop
// 82: 90                      nop
// 83: ff 25 69 00 00 00       jmp    QWORD PTR [rip+0x69]        # f2 <Mm>
// 0000000000000089 <next_step>:
// 89: 54                      push   rsp
// 8a: 50                      push   rax
// 8b: 53                      push   rbx
// 8c: 51                      push   rcx
// 8d: 52                      push   rdx
// 8e: 55                      push   rbp
// 8f: 57                      push   rdi
// 90: 56                      push   rsi
// 91: 41 50                   push   r8
// 93: 41 51                   push   r9
// 95: 41 52                   push   r10
// 97: 41 53                   push   r11
// 99: 41 54                   push   r12
// 9b: 41 55                   push   r13
// 9d: 41 56                   push   r14
// 9f: 41 57                   push   r15
// a1: 48 89 e1                mov    rcx,rsp
// a4: 48 83 ec 20             sub    rsp,0x20
// a8: ff 15 3c 00 00 00       call   QWORD PTR [rip+0x3c]        # ea <HookFunc_post>
// ae: 48 83 c4 20             add    rsp,0x20
// b2: 41 5f                   pop    r15
// b4: 41 5e                   pop    r14
// b6: 41 5d                   pop    r13
// b8: 41 5c                   pop    r12
// ba: 41 5b                   pop    r11
// bc: 41 5a                   pop    r10
// be: 41 59                   pop    r9
// c0: 41 58                   pop    r8
// c2: 5e                      pop    rsi
// c3: 5f                      pop    rdi
// c4: 5d                      pop    rbp
// c5: 5a                      pop    rdx
// c6: 59                      pop    rcx
// c7: 5b                      pop    rbx
// c8: 58                      pop    rax
// c9: 5c                      pop    rsp
// ca: 50                      push   rax
// cb: 65 48 8b 04 25 30 00    mov    rax,QWORD PTR gs:0x30
// d2: 00 00
// d4: 48 05 42 42 42 42       add    rax,0x42424242
// da: 48 8b 00                mov    rax,QWORD PTR [rax]
// dd: 48 87 04 24             xchg   QWORD PTR [rsp],rax
// e1: c3                      ret
// 00000000000000e2 <HookFunc_pre>:
// e2: 90                      nop
// e3: 90                      nop
// e4: 90                      nop
// e5: 90                      nop
// e6: 90                      nop
// e7: 90                      nop
// e8: 90                      nop
// e9: 90                      nop
// 00000000000000ea <HookFunc_post>:
// ea: 90                      nop
// eb: 90                      nop
// ec: 90                      nop
// ed: 90                      nop
// ee: 90                      nop
// ef: 90                      nop
// f0: 90                      nop
// f1: 90                      nop
// 00000000000000f2 <Mm>:
// f2: 90                      nop
// f3: 90                      nop
// f4: 90                      nop
// f5: 90                      nop
// f6: 90                      nop
// f7: 90                      nop
// f8: 90                      nop
// f9: 90                      no

#define OFFSET_REP_INSTRU       0x68
#define OFFSET_HOOK_FUNC_PRE    0xE2
#define OFFSET_HOOK_FUNC_POST   0xEA
#define OFFSET_HOOK_MM          0xF2
#define OFFSET_REGION_SIZE_00   (0x51 + 2)
#define OFFSET_REGION_SIZE_01   (0xD4 + 2)

#else

BYTE RealGenericRetTrampo[] = "\x60\x89\xE1\xE8\x00\x00\x00\x00\x5B\x8B\x83\x7C\x00\x00\x00\x51\xFF\xD0\x83\xC4\x04\x61\x50\x53\x64\xA1\x18\x00\x00\x00\x8B\x5C\x24\x08\x05\x42\x42\x42\x42\x89\x18\xE8\x00\x00\x00\x00\x58\x8D\x80\x2E\x00\x00\x00\x89\x44\x24\x08\x5B\x58\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xFF\x25\x42\x42\x42\x42\x60\x89\xE1\xE8\x00\x00\x00\x00\x5B\x8B\x83\x24\x00\x00\x00\x51\xFF\xD0\x83\xC4\x04\x61\x50\x64\xA1\x18\x00\x00\x00\x05\x42\x42\x42\x42\x8B\x00\x87\x04\x24\xC3\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";

// 0:  60                      pusha
// 1:  89 e1                   mov    ecx,esp
// 3:  e8 00 00 00 00          call   8 <get_pc_00>
// 00000008 <get_pc_00>:
// 8:  5b                      pop    ebx
// 9:  8b 83 7c 00 00 00       mov    eax,DWORD PTR [ebx+0x7c]
// f:  51                      push   ecx
// 10: ff d0                   call   eax
// 12: 83 c4 04                add    esp,0x4
// 15: 61                      popa
// 16: 50                      push   eax
// 17: 53                      push   ebx
// 18: 64 a1 18 00 00 00       mov    eax,fs:0x18
// 1e: 8b 5c 24 08             mov    ebx,DWORD PTR [esp+0x8]
// 22: 05 42 42 42 42          add    eax,0x42424242
// 27: 89 18                   mov    DWORD PTR [eax],ebx
// 29: e8 00 00 00 00          call   2e <get_pc_01>
// 0000002e <get_pc_01>:
// 2e: 58                      pop    eax
// 2f: 8d 80 2e 00 00 00       lea    eax,[eax+0x2e]
// 35: 89 44 24 08             mov    DWORD PTR [esp+0x8],eax
// 39: 5b                      pop    ebx
// 3a: 58                      pop    eax
// 0000003b <restore_intru>:
// 3b: 90                      nop
// 3c: 90                      nop
// 3d: 90                      nop
// 3e: 90                      nop
// 3f: 90                      nop
// 40: 90                      nop
// 41: 90                      nop
// 42: 90                      nop
// 43: 90                      nop
// 44: 90                      nop
// 45: 90                      nop
// 46: 90                      nop
// 47: 90                      nop
// 48: 90                      nop
// 49: 90                      nop
// 4a: 90                      nop
// 4b: 90                      nop
// 4c: 90                      nop
// 4d: 90                      nop
// 4e: 90                      nop
// 4f: 90                      nop
// 50: 90                      nop
// 51: 90                      nop
// 52: 90                      nop
// 53: 90                      nop
// 54: 90                      nop
// 55: 90                      nop
// 56: ff 25 42 42 42 42       jmp    DWORD PTR ds:0x42424242
// 0000005c <next_step>:
// 5c: 60                      pusha
// 5d: 89 e1                   mov    ecx,esp
// 5f: e8 00 00 00 00          call   64 <get_pc_02>
// 00000064 <get_pc_02>:
// 64: 5b                      pop    ebx
// 65: 8b 83 24 00 00 00       mov    eax,DWORD PTR [ebx+0x24]
// 6b: 51                      push   ecx
// 6c: ff d0                   call   eax
// 6e: 83 c4 04                add    esp,0x4
// 71: 61                      popa
// 72: 50                      push   eax
// 73: 64 a1 18 00 00 00       mov    eax,fs:0x18
// 79: 05 42 42 42 42          add    eax,0x42424242
// 7e: 8b 00                   mov    eax,DWORD PTR [eax]
// 80: 87 04 24                xchg   DWORD PTR [esp],eax
// 83: c3                      ret
// 00000084 <HookFunc_pre>:
// 84: 90                      nop
// 85: 90                      nop
// 86: 90                      nop
// 87: 90                      nop
// 00000088 <HookFunc_post>:
// 88: 90                      nop
// 89: 90                      nop
// 8a: 90                      nop
// 8b: 90                      nop
// 0000008c <Mm>:
// 8c: 90                      nop
// 8d: 90                      nop
// 8e: 90                      nop
// 8f: 90                      nop

#define OFFSET_JMP_IND          (0x56 + 2)
#define OFFSET_REP_INSTRU       0x3B
#define OFFSET_HOOK_FUNC_PRE    0x84
#define OFFSET_HOOK_FUNC_POST   0x88
#define OFFSET_HOOK_MM          0x8C
#define OFFSET_REGION_SIZE_00   (0x22 + 1)
#define OFFSET_REGION_SIZE_01   (0x79 + 1)

#endif

PVOID GetTIB(VOID)
{
#ifdef _WIN64
    return (PVOID)__readgsqword(0x30);
#else
    return (PVOID)__readfsdword(0x18);
#endif
}
 
SIZE_T OffsetStore = 0x00;
 
VOID InitOffsetStore(VOID)
{
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR pTIB = (ULONG_PTR)GetTIB();
 
    if (VirtualQuery((LPCVOID)pTIB, &mbi, sizeof(mbi)) == 0) {
        ExitProcess(42);
    }
    OffsetStore = mbi.RegionSize;
}
 
PVOID GetValue(VOID)
{
    ULONG_PTR pTIB = (ULONG_PTR)GetTIB();
 
    if (OffsetStore == 0) {
        InitOffsetStore();
    }
    return (PVOID)(*(ULONG_PTR*)(pTIB + OffsetStore - sizeof(ULONG_PTR)));
}
 
VOID StoreValue(PVOID v)
{
    ULONG_PTR pTIB = (ULONG_PTR)GetTIB();
 
    if (OffsetStore == 0) {
        InitOffsetStore();
    }
    *(ULONG_PTR*)(pTIB + OffsetStore - sizeof (ULONG_PTR)) = (ULONG_PTR)v;
}

VOID DUMMY(VOID)
{
    
}

BOOL SetupPreInlineHook(LPCSTR ModName, LPCSTR ProcName, PROC pfnNewPre)
{
    return SetupPrePostInlineHook(ModName, ProcName, pfnNewPre, (PROC)DUMMY);
}

BOOL SetupPostInlineHook(LPCSTR ModName, LPCSTR ProcName, PROC pfnNewPost)
{
    return SetupPrePostInlineHook(ModName, ProcName, (PROC)DUMMY, pfnNewPost);
}

BOOL SetupPrePostInlineHook(LPCSTR ModName, LPCSTR ProcName, PROC pfnNewPre, PROC pfnNewPost)
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
    return SetupPrePostInlineHook(Addr, pfnNewPre, pfnNewPost);
}

BOOL SetupPrePostInlineHook(ULONG_PTR Addr, PROC pfnNewPre, PROC pfnNewPost)
{
    PVOID Trampo = NULL;
    ULONG_PTR RelayFunc = 0x00;
    DWORD dwLen = 0x00;
    DWORD dwOldProt = 0x00;
    ULONG_PTR Dst = 0x00;

    if (Addr == 0) {
        return FALSE;
    }
    if (OffsetStore == 0) {
        InitOffsetStore();
    }
    Trampo = VirtualAlloc(0, sizeof (RealGenericRetTrampo), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (Trampo == NULL) {
        DbgMsg("[-] SetupPrePostInlineHook - VirtualAlloc failed : %lu\n", GetLastError());
        return FALSE;
    }
    memcpy(Trampo, RealGenericRetTrampo, sizeof (RealGenericRetTrampo));
    while (GetJmpIndirect((PBYTE)Addr, &Dst) == TRUE) {
        Addr = Dst;
    }
#if _WIN64
    RelayFunc = FindFreeMemory(Addr);
#endif
    while (GetJmpIndirect((PBYTE)Addr, &Dst) == TRUE) {
        Addr = Dst;
    }
#if _WIN64
    if (RelayFunc == NULL) {
        while (dwLen < 14) {
            dwLen += DisasLength((PBYTE)(Addr + dwLen));
        }
    }
    else {
        while (dwLen < 5) {
            dwLen += DisasLength((PBYTE)(Addr + dwLen));
        }
    }
#else
    while (dwLen < 5) {
        dwLen += DisasLength((PBYTE)(Addr + dwLen));
    }
#endif
    memcpy((PBYTE)Trampo + OFFSET_REP_INSTRU, (PVOID)Addr, dwLen);
    if (!VirtualProtect((LPVOID)Addr, dwLen, PAGE_EXECUTE_READWRITE, &dwOldProt)) {
        DbgMsg("[-] SetupPrePostInlineHook - VirtualProtect failed : %lu\n", GetLastError());
        return FALSE;
    }
    *(DWORD*)((PBYTE)Trampo + OFFSET_REGION_SIZE_00) = (OffsetStore - sizeof (ULONG_PTR)) & 0xFFFFFFFF;
    *(DWORD*)((PBYTE)Trampo + OFFSET_REGION_SIZE_01) = (OffsetStore - sizeof (ULONG_PTR)) & 0xFFFFFFFF;
#if _WIN64
    if (RelayFunc == NULL) {
        *(PBYTE)Addr = 0xFF;
        *(PBYTE)((PBYTE)Addr + 1) = 0x25;
        *(PDWORD)((PBYTE)Addr + 2) = (DWORD)0;
        *(PDWORD64)((PBYTE)Addr + 6) = (DWORD64)Trampo;
    }
    else {
        *(PBYTE)RelayFunc = 0xFF;
        *(PBYTE)((PBYTE)RelayFunc + 1) = 0x25;
        *(PDWORD)((PBYTE)RelayFunc + 2) = (DWORD)0;
        *(PDWORD64)((PBYTE)RelayFunc + 6) = (DWORD64)Trampo;
        *(PBYTE)Addr = 0xE9;
        *(PDWORD)((PBYTE)Addr + 1) = (DWORD)((BYTE*)RelayFunc - (BYTE*)Addr - 5);
    }
#else
    *(PBYTE)Addr = 0xE9;
    *(PDWORD)((PBYTE)Addr + 1) = (BYTE*)Trampo - (BYTE*)Addr - 5;
    *(ULONG_PTR*)((ULONG_PTR)Trampo + OFFSET_JMP_IND) = (ULONG_PTR)Trampo + OFFSET_HOOK_MM;
#endif
    *(ULONG_PTR*)((ULONG_PTR)Trampo + OFFSET_HOOK_MM) = (ULONG_PTR)Addr + dwLen;
    *(ULONG_PTR*)((ULONG_PTR)Trampo + OFFSET_HOOK_FUNC_PRE) = (ULONG_PTR)pfnNewPre;
    *(ULONG_PTR*)((ULONG_PTR)Trampo + OFFSET_HOOK_FUNC_POST) = (ULONG_PTR)pfnNewPost;
    VirtualProtect((LPVOID)Addr, dwLen, dwOldProt, &dwOldProt);
    FlushInstructionCache(GetCurrentProcess(), (LPCVOID)Addr, 0x06);
    return TRUE;
}
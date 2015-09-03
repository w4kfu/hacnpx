#include "hookstuff.h"

#ifdef _WIN64
BYTE GenericTrampo[] =  //"\xCC"
                        "\x54"                      // push    rsp
                        "\x50"                      // push    rax
                        "\x53"                      // push    rbx
                        "\x51"                      // push    rcx
                        "\x52"                      // push    rdx
                        "\x55"                      // push    rbp
                        "\x57"                      // push    rdi
                        "\x56"                      // push    rsi
                        "\x41\x50"                  // push    r8
                        "\x41\x51"                  // push    r9
                        "\x41\x52"                  // push    r10
                        "\x41\x53"                  // push    r11
                        "\x41\x54"                  // push    r12
                        "\x41\x55"                  // push    r13
                        "\x41\x56"                  // push    r14
                        "\x41\x57"                  // push    r15
                        "\x48\x8B\xCC"              // mov     rcx, rsp
                        "\x48\x83\xEC\x28"          // sub     rsp, 28h
                        "\xFF\x15\x22\x00\x00\x00"  // call    cs:HookFunc
                        "\x48\x83\xC4\x28"          // add     rsp, 28h
                        "\x41\x5F"                  // pop     r15
                        "\x41\x5E"                  // pop     r14
                        "\x41\x5D"                  // pop     r13
                        "\x41\x5C"                  // pop     r12
                        "\x41\x5B"                  // pop     r11
                        "\x41\x5A"                  // pop     r10
                        "\x41\x59"                  // pop     r9
                        "\x41\x58"                  // pop     r8
                        "\x5E"                      // pop     rsi
                        "\x5F"                      // pop     rdi
                        "\x5D"                      // pop     rbp
                        "\x5A"                      // pop     rdx
                        "\x59"                      // pop     rcx
                        "\x5B"                      // pop     rbx
                        "\x58"                      // pop     rax
                        "\x5C"                      // pop     rsp
                        "\xFF\x25\x08\x00\x00\x00"  // jmp     cs:Mm
                        "\x48\x47\x46\x45\x44\x43\x42\x41"  // HookFunc dq 4142434445464748h
                        "\x48\x47\x46\x45\x44\x43\x42\x41"; // Mm dq 4142434445464748h
#else
BYTE GenericTrampo[] = "\x60"                                   // pushad
                       "\x8B\xCC"                               // mov ecx, esp
                       "\xE8\x00\x00\x00\x00"                   // call $+5
                       "\x5B"                                   // pop ebx
                       "\x8B\x43\x11"                           // mov eax, [ebx + 0x11]
                       "\x51"                                   // push ecx
                       "\xFF\xD0"                               // call eax
                       "\x83\xC4\x04"                           // add esp, 0x4
                       "\x61"                                   // popad
                       "\xFF\x25\x43\x43\x43\x43"               // jmp [????]
                       "\x41\x41\x41\x41"                       // 0x41414141
                       "\x42\x42\x42\x42";                      // 0x42424242
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
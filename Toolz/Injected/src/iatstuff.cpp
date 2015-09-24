#include "iatstuff.h"

extern PE_INFO pinfo;

BOOL InitIATStuff(VOID)
{
    pinfo.lModule = GetModuleList();
    PrintModuleInfo();
    return TRUE;
}

ULONG_PTR ImportEntryModule(ULONG_PTR Start)
{
    ULONG_PTR Current;
    std::map<ULONG_PTR, int> ModuleBaseMap;
    ULONG_PTR BaseAddr = 0;
    int max = 0;

    for (Current = Start; *(PULONG_PTR)Current != 0; Current += SIZE_IMPORT_ENTRY) {
        if (!IsBadReadMemory((PVOID)Current, SIZE_IMPORT_ENTRY) && !IsBadReadMemory((PVOID)*(PULONG_PTR)Current, SIZE_IMPORT_ENTRY)) {
            DbgMsg("[+] "HEX_FORMAT"\n", *(PULONG_PTR)Current);
            if (MyRtlPcToFileHeader(*(PULONG_PTR)Current, &BaseAddr) == TRUE) {
                ModuleBaseMap[BaseAddr] += 1;
            }
        }
    }
    for (std::map<ULONG_PTR, int>::iterator it = ModuleBaseMap.begin(); it != ModuleBaseMap.end(); ++it) {
        if (it->second > max)
            max = it->second;
            BaseAddr = it->first;
    }
    if (CheckIfTwiceFreq(ModuleBaseMap, max) == TRUE) {
        DbgMsg("[-] ImportEntryModule - NEED TO FIX MANUALLY\n");
        ExitProcess(42);
    }
    return BaseAddr;
}

VOID BuildNewImport(ULONG_PTR IATStart, ULONG_PTR IATEnd)
{
    ULONG_PTR Current;
    PMODULE ActualModule = NULL;
    PEXPORTENTRY ActualExport = NULL;

    ImportEntryModule(IATStart);
    for (Current = IATStart; Current <= IATEnd; Current += SIZE_IMPORT_ENTRY) {
        if (!IsBadReadMemory((PVOID)Current, SIZE_IMPORT_ENTRY) && !IsBadReadMemory((PVOID)*(PULONG_PTR)Current, SIZE_IMPORT_ENTRY)) {
            if ((ActualModule = GetModule((ULONG_PTR)*(PVOID*)Current)) != NULL) {
                if ((ActualExport = GetExport(ActualModule, (ULONG_PTR)*(PVOID*)Current)) != NULL) {
                    AddNewModuleApi(&pinfo.Importer, ActualModule, ActualExport, Current - (ULONG_PTR)GetModuleHandle(NULL));
                }
                else {
                    DbgMsg("[-] Meh can't find exports?!\n");
                    ExitProcess(42);
                }
            }
        }
    }
    PrintInfoImporter(&pinfo.Importer);
    ComputeAllITSize(&pinfo.Importer);
}

BOOL SearchAutoIAT(ULONG_PTR BaseAddress, ULONG_PTR OEP)
{
    DWORD VirtualAddr;
    DWORD VirtualSize;

    if (pinfo.lModule.size() == 0) {
        InitIATStuff();
        SearchBinaryAllCall(BaseAddress, OEP);
    }
    VirtualAddr = (DWORD)GetSectionInfo(BaseAddress, OEP - BaseAddress, SEC_VIRT_ADDR);
    if (VirtualAddr == 0) {
        DbgMsg("[-] SearchAutoIAT - GetSectionInfo failed\n");
        return FALSE;
    }
    VirtualSize = (DWORD)GetSectionInfo(BaseAddress, OEP - BaseAddress, SEC_VIRT_SIZE);
    if (VirtualSize == 0) {
        DbgMsg("[-] SearchAutoIAT - GetSectionInfo failed\n");
        return FALSE;
    }
    return SearchAutoIAT(BaseAddress, VirtualAddr + BaseAddress, VirtualSize);
}

BOOL SearchBinaryAllCall(ULONG_PTR BaseAddress, ULONG_PTR OEP)
{
    DWORD VirtualAddr;
    DWORD VirtualSize;
    PBYTE pActual;

    if (pinfo.lModule.size() == 0) {
        InitIATStuff();
    }
    VirtualAddr = (DWORD)GetSectionInfo(BaseAddress, OEP - BaseAddress, SEC_VIRT_ADDR);
    if (VirtualAddr == 0) {
        DbgMsg("[-] SearchAutoIAT - GetSectionInfo failed\n");
        return FALSE;
    }
    VirtualSize = (DWORD)GetSectionInfo(BaseAddress, OEP - BaseAddress, SEC_VIRT_SIZE);
    if (VirtualSize == 0) {
        DbgMsg("[-] SearchAutoIAT - GetSectionInfo failed\n");
        return FALSE;
    }
    for (pActual = (PBYTE)(BaseAddress + VirtualAddr); pActual < (PBYTE)(BaseAddress + VirtualAddr + VirtualSize); pActual++) {
        LookIndirectCallImport(pActual);
        LookDirectCallImport(pActual);
    }
    return TRUE;
}

/*
    ==== 32 ====
    8B 0D XX XX XX XX  mov ecx, [address]
    8B 15 XX XX XX XX  mov edx, [address]
    8B 1D XX XX XX XX  mov ebx, [address]
    8B 25 XX XX XX XX  mov esp, [address]
    8B 2D XX XX XX XX  mov ebp, [address]
    8B 35 XX XX XX XX  mov esi, [address]
    8B 3D XX XX XX XX  mov edi, [address]
    A1 XX XX XX XX     mov eax, [address]

    ==== 64 ====
    48 8B 0D XX XX XX XX    mov     rcx, [rip + delta]
    48 8B 15 XX XX XX XX    mov     rdx, [rip + delta]
    48 8B 1D XX XX XX XX    mov     rbx, [rip + delta]
    48 8B 25 XX XX XX XX    mov     rsp, [rip + delta]
    48 8B 2D XX XX XX XX    mov     rbp, [rip + delta]
    48 8B 35 XX XX XX XX    mov     rsi, [rip + delta]
    48 8B 3D XX XX XX XX    mov     rdi, [rip + delta]
    48 8B 05 XX XX XX XX    mov     rax, [rip + delta]
*/
VOID LookIndirectCallImport(PBYTE pActual)
{
    ULONG_PTR Addr;
    ULONG_PTR DestAddr;

    #ifdef _WIN64
    if ((pActual[0] == 0x48) && (pActual[1] == 0x8B) &&
        ((pActual[2] == 0x0D) ||
         (pActual[2] == 0x15) ||
         (pActual[2] == 0x1D) ||
         (pActual[2] == 0x25) ||
         (pActual[2] == 0x2D) ||
         (pActual[2] == 0x35) ||
         (pActual[2] == 0x3D) ||
         (pActual[2] == 0x05))) {
         Addr = *(PDWORD)(pActual + 3) + (ULONG_PTR)pActual + 7;
    #else
    if ((pActual[0] == 0xA1) ||
        ((pActual[0] == 0x8B) &&
        ((pActual[2] == 0x0D) ||
         (pActual[2] == 0x15) ||
         (pActual[2] == 0x1D) ||
         (pActual[2] == 0x25) ||
         (pActual[2] == 0x2D) ||
         (pActual[2] == 0x35) ||
         (pActual[2] == 0x3D)))) {
        Addr = *(PDWORD)(pActual + 2);
    #endif
        if ((!IsBadReadMemory((PVOID)Addr, sizeof (ULONG_PTR))) && (!IsBadReadMemory((PVOID)*(PULONG_PTR)Addr, sizeof (ULONG_PTR)))) {
            DestAddr = *(PULONG_PTR)Addr;
            if (IsAnExport(DestAddr) == TRUE) {
                DisasOne(pActual, (ULONG_PTR)pActual);
            }
        }
    }
}

/*
    ==== 32 ====
    FF 15 XX XX XX XX call  [address]
    FF 25 XX XX XX XX jmp   [address]
    FF 35 XX XX XX XX push  [address]
    ==== 64 ====
    FF 15 XX XX XX XX call  [rip + delta]
    FF 25 XX XX XX XX jmp   [rip + delta]
    FF 35 XX XX XX XX push  [rip + delta]
*/
VOID LookDirectCallImport(PBYTE pActual)
{
    ULONG_PTR Addr;
    ULONG_PTR DestAddr;

    if ((pActual[0] == 0xFF) && ((pActual[1] == 0x25) || (pActual[1] == 0x15) || (pActual[1] == 0x35))) {
    #ifdef _WIN64
        Addr = *(PDWORD)(pActual + 2) + (ULONG_PTR)pActual + 6;
    #else
        Addr = *(PDWORD)(pActual + 2);
    #endif
        if ((!IsBadReadMemory((PVOID)Addr, sizeof (ULONG_PTR))) && (!IsBadReadMemory((PVOID)*(PULONG_PTR)Addr, sizeof (ULONG_PTR)))) {
            DestAddr = *(PULONG_PTR)Addr;
            if (IsAnExport(DestAddr) == TRUE) {
                DisasOne(pActual, (ULONG_PTR)pActual);
            }
        }
    }
}

BOOL SearchAutoIAT(ULONG_PTR BaseAddress, ULONG_PTR SearchStart, DWORD SearchSize)
{
    PBYTE pActual;
    ULONG_PTR Addr;
    ULONG_PTR DestAddr;
    ULONG_PTR IATStart;
    ULONG_PTR IATEnd;

    for (pActual = (PBYTE)SearchStart; pActual < (PBYTE)(SearchStart + SearchSize - 1); pActual++) {
        #ifdef _WIN64
        if ((pActual[0] == 0xFF) && ((pActual[1] == 0x25) || (pActual[1] == 0x15) || (pActual[1] == 0x35))) {
            /*
                call qword ptr[rip+delta]
                jmp  qword ptr[rip+delta]
                push qword ptr[rip+delta]
            */
            Addr = *(PDWORD)(pActual + 2) + (ULONG_PTR)pActual + 6;
        #else
        if ((pActual[0] == 0xFF) && ((pActual[1] == 0x25)  || (pActual[1] == 0x15))) {
            Addr = *(PDWORD)(pActual + 2);
        #endif
            if ((!IsBadReadMemory((PVOID)Addr, sizeof (ULONG_PTR))) && (!IsBadReadMemory((PVOID)*(PULONG_PTR)Addr, sizeof (ULONG_PTR)))) {
                DestAddr = *(PULONG_PTR)Addr;
                if (IsAnExport(DestAddr) == TRUE) {
                    DisasOne(pActual, (ULONG_PTR)pActual, NULL);
                    IATStart = SearchIATStart(BaseAddress, Addr);
                    DbgMsg("[+] IATStart : "HEX_FORMAT"\n", IATStart);
                    IATEnd = SearchIATEnd(BaseAddress, Addr);
                    DbgMsg("[+] IATEnd : "HEX_FORMAT"\n", IATEnd);
                    DbgMsg("[+] windbg : dps "HEX_FORMAT" L((("HEX_FORMAT" - "HEX_FORMAT") / %d) + 1)\n", IATStart, IATEnd, IATStart, sizeof (ULONG_PTR));
                    pinfo.Importer.StartIATRVA = (IATStart - BaseAddress);
                    BuildNewImport(IATStart, IATEnd);
                    //DebugBreak();
                    break;
                }
            }
        }

    }
    return TRUE;
}

ULONG_PTR SearchIATStart(ULONG_PTR BaseAddress, ULONG_PTR SearchStart)
{
    DWORD VirtualAddr;
    ULONG_PTR SectionStart;
    DWORD dwBlankSpace = 0;

    VirtualAddr = (DWORD)GetSectionInfo(BaseAddress, SearchStart - BaseAddress, SEC_VIRT_ADDR);
    if (VirtualAddr == 0) {
        DbgMsg("[-] SearchIATStart - GetSectionInfo failed\n");
        return 0;
    }
    SectionStart = VirtualAddr + BaseAddress;
    while (SearchStart > SectionStart) {
        if (dwBlankSpace == 2)
            break;
        SearchStart = SearchStart - SIZE_IMPORT_ENTRY;
        if (!IsBadReadMemory((PVOID)SearchStart, SIZE_IMPORT_ENTRY)) {
            if (IsBadReadMemory(*(PVOID*)SearchStart, SIZE_IMPORT_ENTRY)) {
                dwBlankSpace += 1;
                continue;
            }
            dwBlankSpace = 0;
        }
        else {
            break;
        }
    }
    if (SearchStart == SectionStart)
        return SearchStart;
    return SearchStart + (SIZE_IMPORT_ENTRY * 2);
}

ULONG_PTR SearchIATEnd(ULONG_PTR BaseAddress, ULONG_PTR SearchStart)
{
    DWORD VirtualAddr;
    DWORD VirtualSize;
    ULONG_PTR SectionEnd;
    DWORD dwBlankSpace = 0;

    VirtualAddr = (DWORD)GetSectionInfo(BaseAddress, SearchStart - BaseAddress, SEC_VIRT_ADDR);
    if (VirtualAddr == 0) {
        DbgMsg("[-] SearchIATStart - GetSectionInfo failed\n");
        return 0;
    }
    VirtualSize = (DWORD)GetSectionInfo(BaseAddress, SearchStart - BaseAddress, SEC_VIRT_SIZE);
    if (VirtualSize == 0) {
        DbgMsg("[-] SearchIATStart - GetSectionInfo failed\n");
        return 0;
    }
    SectionEnd = VirtualAddr + BaseAddress + VirtualSize;
    while (SearchStart < SectionEnd) {
        if (dwBlankSpace == 2)
            break;
        SearchStart = SearchStart + SIZE_IMPORT_ENTRY;
        if (!IsBadReadMemory((PVOID)SearchStart, SIZE_IMPORT_ENTRY)) {
            if (IsBadReadMemory(*(PVOID*)SearchStart, SIZE_IMPORT_ENTRY)) {
                dwBlankSpace += 1;
                continue;
            }
            dwBlankSpace = 0;
        }
        else {
            break;
        }
    }
    if (SearchStart == SectionEnd)
        return SearchStart;
    return SearchStart - (SIZE_IMPORT_ENTRY * 2);
}

VOID AddNewModule(PIMPORTER Importer, PMODULE Module)
{
    std::list<PMODULE>::const_iterator it;
    BOOL Found = FALSE;
    PMODULE mo;

    for (it = Importer->lModule.begin(); it != Importer->lModule.end(); ++it) {
        if (Module->modBaseAddr == (*it)->modBaseAddr) {
            Found = TRUE;
            break;
        }
    }
    if (Found == FALSE) {
        mo = new MODULE();
        if (mo == NULL) {
            DbgMsg("[-] AddNewModule - malloc failed\n");
            ExitProcess(42);
        }
        mo->dwSize = Module->dwSize;
        mo->th32ModuleID = Module->th32ModuleID;
        mo->th32ProcessID = Module->th32ProcessID;
        mo->GlblcntUsage = Module->GlblcntUsage;
        mo->ProccntUsage = Module->ProccntUsage;
        mo->modBaseAddr = Module->modBaseAddr;
        mo->modBaseSize = Module->modBaseSize;
        mo->hModule = Module->hModule;
        memcpy(mo->szModule, Module->szModule, sizeof (Module->szModule));
        memcpy(mo->szExePath, Module->szExePath, sizeof (Module->szExePath));
        Importer->lModule.push_back(mo);
    }
}

VOID AddNewApi(PMODULE Module, PEXPORTENTRY Export, ULONG_PTR RVA)
{
    std::list<PEXPORTENTRY>::const_iterator it;
    BOOL Found = FALSE;
    PEXPORTENTRY Exp;

    for (it = Module->lExport.begin(); it != Module->lExport.end(); ++it) {
        if (Export->FunctionVA == (*it)->FunctionVA) {
            Found = TRUE;
            break;
        }
    }
    if (Found == FALSE) {
        Exp = new EXPORTENTRY();
        if (Exp == NULL) {
            DbgMsg("[-] AddNewApi - malloc failed\n");
            ExitProcess(42);
        }
        Exp->Ordinal = Export->Ordinal;
        Exp->FunctionRVA = Export->FunctionRVA;
        Exp->FunctionVA = Export->FunctionVA;
        Exp->isRedirect = Export->isRedirect;
        Exp->RVA = RVA;
        memcpy(Exp->FunctionName, Export->FunctionName, sizeof (Export->FunctionName));
        Module->lExport.push_back(Exp);
    }
}

VOID AddNewModuleApi(PIMPORTER Importer, PMODULE Module, PEXPORTENTRY Export, ULONG_PTR RVA)
{
    std::list<PMODULE>::const_iterator it;

    AddNewModule(Importer, Module);
    for (it = Importer->lModule.begin(); it != Importer->lModule.end(); ++it) {
        if (Module->modBaseAddr == (*it)->modBaseAddr) {
            AddNewApi((*it), Export, RVA);
        }
    }
}

VOID ComputeAllITSize(PIMPORTER Importer)
{
    std::list<PMODULE>::const_iterator it_mod;
    std::list<PEXPORTENTRY>::const_iterator it_exp;
    ULONG_PTR ModuleNameLength = 0;
    ULONG_PTR ApiNameLength = 0;

    Importer->NbTotalApis = 0;
    for (it_mod = Importer->lModule.begin(); it_mod != Importer->lModule.end(); ++it_mod) {
        ModuleNameLength += strlen((*it_mod)->szModule) + 1;
        for (it_exp = (*it_mod)->lExport.begin(); it_exp != (*it_mod)->lExport.end(); ++it_exp) {
            if (!strncmp((*it_exp)->FunctionName, "Ordinal_0x", strlen("Ordinal_0x"))) {
                DbgMsg("[-] ORDINAL : TODO %s!%s ; 0x%08X ; "HEX_FORMAT" ; "HEX_FORMAT" at "HEX_FORMAT"\n", (*it_mod)->szModule, (*it_exp)->FunctionName, (*it_exp)->Ordinal, (*it_exp)->FunctionRVA, (*it_exp)->FunctionVA, (*it_exp)->RVA);
                //DebugBreak();
                //ExitProcess(42);
            }
            Importer->NbTotalApis += 1;
            ApiNameLength += strlen((*it_exp)->FunctionName) + 1 + sizeof (WORD);
        }
    }
    Importer->ModulesNameLength = ModuleNameLength;
    Importer->APIsNameLength = ApiNameLength;
    Importer->TotalSizeIT = (DWORD)(Importer->ModulesNameLength + Importer->APIsNameLength + ((Importer->lModule.size() + 1) * sizeof (IMAGE_IMPORT_DESCRIPTOR)));
    DbgMsg("[+] Importer->ModulesNameLength : 0x%08X (%d)\n", Importer->ModulesNameLength, Importer->ModulesNameLength);
    DbgMsg("[+] Importer->APIsNameLength    : 0x%08X (%d)\n", Importer->APIsNameLength, Importer->APIsNameLength);
    DbgMsg("[+] Importer->TotalSizeIT       : 0x%08X (%d)\n", Importer->TotalSizeIT, Importer->TotalSizeIT);
}

VOID BuildIT(PBYTE pDump, ULONG_PTR RVAIT)
{
    std::list<PMODULE>::const_iterator it_mod;
    std::list<PEXPORTENTRY>::const_iterator it_exp;
    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
    PBYTE ModuleName;
    ULONG_PTR RVAModuleName;
    DWORD dwStartIAT;

    ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pDump + RVAIT);
    ModuleName = (pDump + RVAIT) + (sizeof (IMAGE_IMPORT_DESCRIPTOR) * (pinfo.Importer.lModule.size() + 1));
    RVAModuleName = RVAIT + (sizeof (IMAGE_IMPORT_DESCRIPTOR) * (pinfo.Importer.lModule.size() + 1));
    dwStartIAT = (DWORD)pinfo.Importer.StartIATRVA;
    for (it_mod = pinfo.Importer.lModule.begin(); it_mod != pinfo.Importer.lModule.end(); ++it_mod) {
        ImportDescriptor->Name = (DWORD)RVAModuleName;
        ImportDescriptor->OriginalFirstThunk = 0;
        ImportDescriptor->TimeDateStamp = 0;
        ImportDescriptor->ForwarderChain = 0;
        ImportDescriptor->FirstThunk = dwStartIAT;
        memcpy(ModuleName, (*it_mod)->szModule, strlen((*it_mod)->szModule));
        ModuleName += strlen((*it_mod)->szModule) + 1;
        RVAModuleName += (DWORD)strlen((*it_mod)->szModule) + 1;
        for (it_exp = (*it_mod)->lExport.begin(); it_exp != (*it_mod)->lExport.end(); ++it_exp) {
            if (*(PULONG_PTR)(pDump + dwStartIAT) == 0) {
                DbgMsg("[-] BuildIT - Entry NULL at "HEX_FORMAT"\n", pDump + dwStartIAT);
                ExitProcess(42);
            }
            if (*(PULONG_PTR)(pDump + dwStartIAT) != (*it_exp)->FunctionVA) {
                DbgMsg("[-] BuildIT - Fail FunctionVA at "HEX_FORMAT"\n", pDump + dwStartIAT);
                ExitProcess(42);
            }
            if (!strncmp((*it_exp)->FunctionName, "Ordinal_0x", strlen("Ordinal_0x"))) {
                #ifdef _WIN64
                    *(PULONG_PTR)(pDump + dwStartIAT) = (((ULONG_PTR)1u << 63) | (*it_exp)->Ordinal);
                #else
                    *(PULONG_PTR)(pDump + dwStartIAT) = (((ULONG_PTR)1u << 31) | (*it_exp)->Ordinal);
                #endif
            }
            else {
                *(PULONG_PTR)(pDump + dwStartIAT) = RVAModuleName;
            }
            memcpy(ModuleName, &(*it_exp)->Ordinal, 2);
            ModuleName += 2;
            RVAModuleName += 2;
            memcpy(ModuleName, (*it_exp)->FunctionName, strlen((*it_exp)->FunctionName));
            ModuleName += strlen((*it_exp)->FunctionName) + 1;
            RVAModuleName += strlen((*it_exp)->FunctionName) + 1;
            dwStartIAT += sizeof (ULONG_PTR);
        }
        ImportDescriptor++;
        dwStartIAT += sizeof (ULONG_PTR);
    }
}
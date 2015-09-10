#include "iatstuff.h"

extern PE_INFO pinfo;

BOOL InitIATStuff(VOID)
{
    pinfo.lModule = GetModuleList();
    PrintModuleInfo();
    return TRUE;
}

VOID BuildNewImport(ULONG_PTR IATStart, ULONG_PTR IATEnd)
{
    ULONG_PTR Current;
    PMODULE ActualModule = NULL;
    PEXPORTENTRY ActualExport = NULL;

    for (Current = IATStart; Current <= IATEnd; Current += SIZE_IMPORT_ENTRY) {
        if (!IsBadReadMemory((PVOID)Current, SIZE_IMPORT_ENTRY) && !IsBadReadMemory((PVOID)*(PULONG_PTR)Current, SIZE_IMPORT_ENTRY)) {
            if ((ActualModule = GetModule((ULONG_PTR)*(PVOID*)Current)) != NULL) {
                if ((ActualExport = GetExport(ActualModule, (ULONG_PTR)*(PVOID*)Current)) != NULL) {
                    AddNewModuleApi(&pinfo.Importer, ActualModule, ActualExport, Current - (ULONG_PTR)GetModuleHandle(NULL));
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
                /* TODO: Is from module ? */
                DestAddr = *(PULONG_PTR)Addr;
                DisasOne(pActual, (ULONG_PTR)pActual, NULL);
                IATStart = SearchIATStart(BaseAddress, Addr);
                DbgMsg("[+] IATStart : "HEX_FORMAT"\n", IATStart);
                IATEnd = SearchIATEnd(BaseAddress, Addr);
                DbgMsg("[+] IATEnd : "HEX_FORMAT"\n", IATEnd);
                pinfo.Importer.StartIATRVA = (IATStart - BaseAddress);
                BuildNewImport(IATStart, IATEnd);
                //DebugBreak();
                break;
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
        if (Export->FunctionRVA == (*it)->FunctionRVA) {
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
        Exp->FunctionVA = Export->FunctionRVA;
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
                DbgMsg("[-] ORDINAL : TODO!\n");
                ExitProcess(42);
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
            *(PULONG_PTR)(pDump + dwStartIAT) = RVAModuleName;
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
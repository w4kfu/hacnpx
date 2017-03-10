#include "pestuff.h"

extern PE_INFO pinfo;

BOOL ValidateHeader(ULONG_PTR BaseAddress)
{
    PIMAGE_DOS_HEADER pDos;
    /* ULONG_PTR SizeOfImage; */
    PIMAGE_NT_HEADERS pNT;

    pDos = (PIMAGE_DOS_HEADER)BaseAddress;
    if (pDos->e_magic != 0x5A4D) {
        return FALSE;
    }
    /*
    SizeOfImage = (ULONG_PTR)GetModuleInfo(BaseAddress, MOD_SIZE);
    if (SizeOfImage == 0) {
        return FALSE;
    }
    if (pDos->e_lfanew + sizeof (IMAGE_DOS_HEADER) + sizeof (IMAGE_NT_HEADERS) >= SizeOfImage) {
        return FALSE;
    }
    */
    pNT = (PIMAGE_NT_HEADERS)(BaseAddress + pDos->e_lfanew);
    if (pNT->Signature != 0x4550) {
        return FALSE;
    }
    return TRUE;
}

ULONG_PTR ParsePEDirectory(ULONG_PTR BaseAddress, DWORD dwChamp, DWORD Index)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT;
    PIMAGE_DATA_DIRECTORY rvas;
    DWORD nmbOfRva;

    if (ValidateHeader(BaseAddress) == FALSE) {
        return 0;
    }
    pDos = (PIMAGE_DOS_HEADER)BaseAddress;
    pNT = (PIMAGE_NT_HEADERS)(BaseAddress + pDos->e_lfanew);
    nmbOfRva = pNT->OptionalHeader.NumberOfRvaAndSizes;
    rvas = (PIMAGE_DATA_DIRECTORY)&pNT->OptionalHeader.DataDirectory;
    if (nmbOfRva < (Index + 1)) {
        return 0;
    }
    switch(dwChamp) {
        case DIR_VIRTUAL_ADDRESS:
            return (ULONG_PTR)((ULONG_PTR)rvas[Index].VirtualAddress);
        case DIR_SIZE:
            return (ULONG_PTR)((ULONG_PTR)rvas[Index].Size);
    }
    return 0;
}

ULONG_PTR ParsePE(ULONG_PTR BaseAddress, DWORD dwChamp)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT;
    PIMAGE_DATA_DIRECTORY rvas;
    DWORD nmbOfRva;

    if (ValidateHeader(BaseAddress) == FALSE) {
        return NULL;
    }
    pDos = (PIMAGE_DOS_HEADER)BaseAddress;
    pNT = (PIMAGE_NT_HEADERS)(BaseAddress + pDos->e_lfanew);
    nmbOfRva = pNT->OptionalHeader.NumberOfRvaAndSizes;
    rvas = (PIMAGE_DATA_DIRECTORY) &pNT->OptionalHeader.DataDirectory;
    switch(dwChamp) {
        case SIZE_OF_IMAGE:
            return (ULONG_PTR)((ULONG_PTR)pNT->OptionalHeader.SizeOfImage);
        case NB_SECTIONS:
            return (ULONG_PTR)((ULONG_PTR)pNT->FileHeader.NumberOfSections);
        case PE_SECTIONS:
            return (ULONG_PTR)IMAGE_FIRST_SECTION(pNT);//(void*)((BYTE *)pNT + sizeof(IMAGE_NT_HEADERS64));
        case IMPORT_TABLE:
            return ParsePEDirectory(BaseAddress, DIR_VIRTUAL_ADDRESS, IMAGE_DIRECTORY_ENTRY_IMPORT);
        case IMPORT_TABLE_SIZE:
            return ParsePEDirectory(BaseAddress, DIR_SIZE, IMAGE_DIRECTORY_ENTRY_IMPORT);
        case IMPORT_ADDRESS_TABLE:
            return ParsePEDirectory(BaseAddress, DIR_VIRTUAL_ADDRESS, IMAGE_DIRECTORY_ENTRY_IAT);
        case IMPORT_ADDRESS_TABLE_SIZE:
            return ParsePEDirectory(BaseAddress, DIR_SIZE, IMAGE_DIRECTORY_ENTRY_IAT);
        case EXPORT_TABLE:
            return ParsePEDirectory(BaseAddress, DIR_VIRTUAL_ADDRESS, IMAGE_DIRECTORY_ENTRY_EXPORT);
        case EXPORT_TABLE_SIZE:
            return ParsePEDirectory(BaseAddress, DIR_SIZE, IMAGE_DIRECTORY_ENTRY_EXPORT);
        case ENTRY_POINT:
            return (ULONG_PTR)((ULONG_PTR)pNT->OptionalHeader.AddressOfEntryPoint);
    }
    return NULL;
}

ULONG_PTR GetSectionInfo(ULONG_PTR BaseAddress, ULONG_PTR dwAddr, DWORD dwChamp)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT;
    PIMAGE_SECTION_HEADER pSection;
    WORD NumberOfSections;

    if (ValidateHeader(BaseAddress) == FALSE) {
        return NULL;
    }
    pDos = (PIMAGE_DOS_HEADER)BaseAddress;
    pNT = (PIMAGE_NT_HEADERS)(BaseAddress + pDos->e_lfanew);
    pSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pNT + sizeof(IMAGE_NT_HEADERS));
    NumberOfSections = pNT->FileHeader.NumberOfSections;
    for (WORD i = 0; i < NumberOfSections; i++) {
        if ((pSection->VirtualAddress <= dwAddr) && (dwAddr < (pSection->VirtualAddress + pSection->Misc.VirtualSize))) {
            switch (dwChamp)
            {
                case SEC_NAME:
                    return (ULONG_PTR)pSection->Name;
                case SEC_VIRT_SIZE:
                    return (ULONG_PTR)((ULONG_PTR)pSection->Misc.VirtualSize);
                case SEC_VIRT_ADDR:
                    return (ULONG_PTR)((ULONG_PTR)pSection->VirtualAddress);
                case SEC_RAW_SIZE:
                    return (ULONG_PTR)((ULONG_PTR)pSection->SizeOfRawData);
                case SEC_RAW_ADDR:
                    return (ULONG_PTR)((ULONG_PTR)pSection->PointerToRawData);
                case SEC_CHARAC:
                    return (ULONG_PTR)((ULONG_PTR)pSection->Characteristics);
            }
        }
        pSection++;
    }
    return NULL;
}

ULONG_PTR GetSectionInfo(ULONG_PTR BaseAddress, const char *Name, DWORD dwChamp)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT;
    PIMAGE_SECTION_HEADER pSection;
    WORD NumberOfSections;

    if (ValidateHeader(BaseAddress) == FALSE) {
        return NULL;
    }
    pDos = (PIMAGE_DOS_HEADER)BaseAddress;
    pNT = (PIMAGE_NT_HEADERS)(BaseAddress + pDos->e_lfanew);
    pSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pNT + sizeof(IMAGE_NT_HEADERS));
    NumberOfSections = pNT->FileHeader.NumberOfSections;
    for (WORD i = 0; i < NumberOfSections; i++) {
        if (!strcmp((const char*)pSection->Name, Name)) {
            switch (dwChamp)
            {
                case SEC_NAME:
                    return (ULONG_PTR)pSection->Name;
                case SEC_VIRT_SIZE:
                    return (ULONG_PTR)((ULONG_PTR)pSection->Misc.VirtualSize);
                case SEC_VIRT_ADDR:
                    return (ULONG_PTR)((ULONG_PTR)pSection->VirtualAddress);
                case SEC_RAW_SIZE:
                    return (ULONG_PTR)((ULONG_PTR)pSection->SizeOfRawData);
                case SEC_RAW_ADDR:
                    return (ULONG_PTR)((ULONG_PTR)pSection->PointerToRawData);
                case SEC_CHARAC:
                    return (ULONG_PTR)((ULONG_PTR)pSection->Characteristics);
            }
        }
        pSection++;
    }
    return NULL;
}

ULONG_PTR RVA2Offset(ULONG_PTR BaseAddress, DWORD dwVA)
{
    ULONG_PTR VirtualAddress;
    ULONG_PTR PointerToRawData;

    VirtualAddress = (ULONG_PTR)GetSectionInfo(BaseAddress, dwVA, SEC_VIRT_ADDR);
    PointerToRawData = (ULONG_PTR)GetSectionInfo(BaseAddress, dwVA, SEC_RAW_ADDR);
    return ((dwVA - VirtualAddress) + PointerToRawData);
}

BOOL IsAddressInDirectory(ULONG_PTR BaseAddress, DWORD Index, DWORD Addr)
{
    ULONG_PTR DirectoryStart;
    ULONG_PTR DirectorySize;

    DirectoryStart = (ULONG_PTR)ParsePEDirectory(BaseAddress, DIR_VIRTUAL_ADDRESS, Index);
    DirectorySize = (ULONG_PTR)ParsePEDirectory(BaseAddress, DIR_SIZE, Index);
    if (Addr >= DirectoryStart && Addr < (DirectoryStart + DirectorySize)) {
        return TRUE;
    }
    return FALSE;
}

ULONG_PTR ResolveRedirect(LPCSTR ApiRedir)
{
    LPCSTR ApiName = NULL;
    TCHAR szModule[MAX_MODULE_NAME32 + 1];
    HMODULE BaseAddress = NULL;
    ULONG_PTR FunctionVA = 0;

    if (strncmp(ApiRedir, "ext-", 4) == 0) {
        /* DbgMsg("[-] ResolveRedirect - %s : Unhandled redirection of type 'ext-'\n", ApiRedir); */
        ExitProcess(42);
    }
    if (strncmp(ApiRedir, "api-", 4) == 0) {
        /* DbgMsg("[-] ResolveRedirect - %s : Unhandled redirection of type 'api-'\n", ApiRedir); */
        return 0;
    }
    ApiName = strchr(ApiRedir, '.');
    if (ApiName == NULL) {
        /* DbgMsg("[-] ResolveRedirect - Can't find separator '.' in \"%s\"\n", ApiRedir); */
        ExitProcess(42);
    }
    memset(szModule, 0, sizeof (szModule));
    memcpy(szModule, ApiRedir, ApiName - ApiRedir);
    ApiName += 1;
    /* DbgMsg("[+] Real : %s!%s\n", szModule, ApiName); */
    BaseAddress = GetModuleHandleA(szModule);
    if (BaseAddress == NULL) {
        /* DbgMsg("[-] ResolveRedirect - GetModuleHandleA failed %lu\n", GetLastError()); */
        return 0;
    }
    FunctionVA = (ULONG_PTR)GetProcAddress(BaseAddress, ApiName);
    if (FunctionVA == NULL) {
        /* DbgMsg("[-] ResolveRedirect - GetProcAddress failed %lu\n", GetLastError()); */
        return 0;
    }
    return FunctionVA;
}

std::list<PEXPORTENTRY> GetExportList(ULONG_PTR BaseAddress)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT;
    PIMAGE_EXPORT_DIRECTORY pExport;
    WORD NameOrdinal;
    ULONG_PTR FunctionRVA;
    //ULONG_PTR FunctionVA;
    PEXPORTENTRY Export;
    std::list<PEXPORTENTRY> lExport;

    if (ValidateHeader(BaseAddress) == FALSE) {
        DbgMsg("[-] GetExportList - ValidateHeader failed\n");
        return lExport;
    }
    pDos = (PIMAGE_DOS_HEADER)BaseAddress;
    pNT = (PIMAGE_NT_HEADERS)(BaseAddress + pDos->e_lfanew);
    pExport = (PIMAGE_EXPORT_DIRECTORY)(pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + BaseAddress);
    PUSHORT pOrdinals = (PUSHORT)(pExport->AddressOfNameOrdinals + BaseAddress);
    PULONG pAddress = (PULONG)(pExport->AddressOfFunctions + BaseAddress);
    PULONG pApiNames = (PULONG)(pExport->AddressOfNames + BaseAddress);
    for (DWORD index = 0; index < pExport->NumberOfFunctions; index++) {
        NameOrdinal = pOrdinals[index];
        if (NameOrdinal >= pExport->NumberOfFunctions)
            continue;
        FunctionRVA = pAddress[NameOrdinal];
        Export = new EXPORTENTRY();
        if (Export == NULL) {
            DbgMsg("[-] GetModuleList - malloc failed\n");
            ExitProcess(42);
        }
        Export->isRedirect = FALSE;
        //if (IsAddressInDirectory(BaseAddress, EXPORT_TABLE, (DWORD)FunctionRVA) == TRUE) {
        //    if ((FunctionVA = ResolveRedirect((LPCSTR)(FunctionRVA + BaseAddress))) != 0) {
        //        Export->isRedirect = TRUE;
        //        Export->FunctionVA = FunctionVA;
        //    }
        //    //ExitProcess(42);
        //}
        Export->Ordinal = NameOrdinal;
        Export->FunctionRVA = FunctionRVA;
        if (Export->isRedirect == FALSE)
            Export->FunctionVA = FunctionRVA + BaseAddress;
        memset(Export->FunctionName, 0, 256);
        if (index >= pExport->NumberOfNames)
            sprintf_s(Export->FunctionName, 256, "Ordinal_0x%08X", NameOrdinal);
        else
            strncpy_s(Export->FunctionName, 256, (char*)(pApiNames[index] + BaseAddress), 256 - 1);
        lExport.push_back(Export);
    }
    return lExport;
}

PEXPORTENTRY GetExport(PMODULE Module, ULONG_PTR Addr)
{
    std::list<PEXPORTENTRY>::const_iterator it;

    for (it = Module->lExport.begin(); it != Module->lExport.end(); ++it) {
        if (Addr == (ULONG_PTR)((*it)->FunctionVA)) {
            return (*it);
        }
    }
    return NULL;
}

VOID AddPESection(ULONG_PTR ImageBase, LPCSTR Name, DWORD PtrRawData, DWORD VirtualSize, DWORD VA, DWORD SizeSection, DWORD Characteristics)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT;
    PIMAGE_SECTION_HEADER pSection;

    pDos = (PIMAGE_DOS_HEADER)ImageBase;
    pNT = (PIMAGE_NT_HEADERS)(ImageBase + pDos->e_lfanew);
    pSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pNT + sizeof(IMAGE_NT_HEADERS));
    strcpy_s((char*)pSection[pNT->FileHeader.NumberOfSections].Name, 8, Name);
    pSection[pNT->FileHeader.NumberOfSections].PointerToRawData = PtrRawData;
    pSection[pNT->FileHeader.NumberOfSections].Misc.VirtualSize = VirtualSize;
    pSection[pNT->FileHeader.NumberOfSections].VirtualAddress = VA;
    pSection[pNT->FileHeader.NumberOfSections].Characteristics = Characteristics;
    pSection[pNT->FileHeader.NumberOfSections].SizeOfRawData = SizeSection;
    pNT->FileHeader.NumberOfSections += 1;
}

BOOL EditPEDirectory(ULONG_PTR BaseAddress, DWORD dwChamp, DWORD Index, ULONG_PTR Value)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT;
    PIMAGE_DATA_DIRECTORY rvas;
    DWORD nmbOfRva;

    /* if (ValidateHeader(BaseAddress) == FALSE) {
        return FALSE;
    } */
    pDos = (PIMAGE_DOS_HEADER)BaseAddress;
    pNT = (PIMAGE_NT_HEADERS)(BaseAddress + pDos->e_lfanew);
    nmbOfRva = pNT->OptionalHeader.NumberOfRvaAndSizes;
    rvas = (PIMAGE_DATA_DIRECTORY)&pNT->OptionalHeader.DataDirectory;
    if (nmbOfRva < (Index + 1)) {
        return FALSE;
    }
    switch(dwChamp) {
        case DIR_VIRTUAL_ADDRESS:
            rvas[Index].VirtualAddress = (DWORD)(Value);
            return TRUE;
        case DIR_SIZE:
            rvas[Index].Size = (DWORD)Value;
            return TRUE;
    }
    return FALSE;
}

BOOL EditPE(ULONG_PTR BaseAddress, DWORD dwChamp, ULONG_PTR Value)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT;

    /* if (ValidateHeader(BaseAddress) == FALSE) {
        DbgMsg("[-] EditPE - ValidateHeader failed\n");
        return FALSE;
    } */
    pDos = (PIMAGE_DOS_HEADER)BaseAddress;
    pNT = (PIMAGE_NT_HEADERS)(BaseAddress + pDos->e_lfanew);
    switch(dwChamp) {
        case SIZE_OF_IMAGE:
            pNT->OptionalHeader.SizeOfImage = (DWORD)Value;
            return TRUE;
        case NB_SECTIONS:
            pNT->FileHeader.NumberOfSections = (WORD)Value;
            return TRUE;
        case IMPORT_TABLE:
            return EditPEDirectory(BaseAddress, DIR_VIRTUAL_ADDRESS, IMAGE_DIRECTORY_ENTRY_IMPORT, Value);
        case IMPORT_TABLE_SIZE:
            return EditPEDirectory(BaseAddress, DIR_SIZE, IMAGE_DIRECTORY_ENTRY_IMPORT, Value);
        case IMPORT_ADDRESS_TABLE:
            return EditPEDirectory(BaseAddress, DIR_VIRTUAL_ADDRESS, IMAGE_DIRECTORY_ENTRY_IAT, Value);
        case IMPORT_ADDRESS_TABLE_SIZE:
            return EditPEDirectory(BaseAddress, DIR_SIZE, IMAGE_DIRECTORY_ENTRY_IAT, Value);
        case ENTRY_POINT:
            pNT->OptionalHeader.AddressOfEntryPoint = (DWORD)Value;
            return TRUE;
    }
    return FALSE;
}

VOID FixSectionSizeOffset(ULONG_PTR BaseAddress)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT;
    PIMAGE_SECTION_HEADER pSection;

    pDos = (PIMAGE_DOS_HEADER)BaseAddress;
    pNT = (PIMAGE_NT_HEADERS)(BaseAddress + pDos->e_lfanew);
    pSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pNT + sizeof(IMAGE_NT_HEADERS));
    for (WORD i = 0; i < pNT->FileHeader.NumberOfSections; i++ ) {
        pSection[i].PointerToRawData = pSection[i].VirtualAddress;
        pSection[i].SizeOfRawData = pSection[i].Misc.VirtualSize;
    }
}

BOOL IsAnExport(ULONG_PTR Addr)
{
    std::list<PMODULE>::const_iterator it_mod;
    std::list<PEXPORTENTRY>::const_iterator it_exp;

    for (it_mod = pinfo.lModule.begin(); it_mod != pinfo.lModule.end(); ++it_mod) {
        for (it_exp = (*it_mod)->lExport.begin(); it_exp != (*it_mod)->lExport.end(); ++it_exp) {
            if ((*it_exp)->FunctionVA == Addr)
                return TRUE;
        }
    }
    return FALSE;
}
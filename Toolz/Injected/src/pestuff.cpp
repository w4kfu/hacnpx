#include "pestuff.h"

BOOL ValidateHeader(ULONG_PTR BaseAddress)
{
    PIMAGE_DOS_HEADER pDos;
    ULONG_PTR SizeOfImage;
    PIMAGE_NT_HEADERS pNT;

    pDos = (PIMAGE_DOS_HEADER)BaseAddress;
    if (pDos->e_magic != 0x5A4D) {
        return FALSE;
    }
    SizeOfImage = (ULONG_PTR)GetModuleInfo(BaseAddress, MOD_SIZE);
    if (SizeOfImage == 0) {
        return FALSE;
    }
    if (pDos->e_lfanew + sizeof (IMAGE_DOS_HEADER) + sizeof (IMAGE_NT_HEADERS) >= SizeOfImage) {
        return FALSE;
    }
    pNT = (PIMAGE_NT_HEADERS)(BaseAddress + pDos->e_lfanew);
    if (pNT->Signature != 0x4550) {
        return FALSE;
    }
    return TRUE;
}

PVOID ParsePE(ULONG_PTR BaseAddress, DWORD dwChamp)
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
            return (PVOID)pNT->OptionalHeader.SizeOfImage;
        case NB_SECTIONS:
            return (PVOID)(DWORD)pNT->FileHeader.NumberOfSections;
        case PE_SECTIONS:
            return (PVOID)IMAGE_FIRST_SECTION(pNT);//(void*)((BYTE *)pNT + sizeof(IMAGE_NT_HEADERS64));
        case EXPORT_TABLE:
            if (nmbOfRva >= 1)
                return (PVOID)(rvas[0].VirtualAddress);
            else
                return NULL;
        case EXPORT_TABLE_SIZE:
            if (nmbOfRva >= 1)
                return (PVOID)(rvas[0].Size);
            else
                return NULL;
        case ENTRY_POINT:
            return (PVOID)pNT->OptionalHeader.AddressOfEntryPoint;
    }
    return NULL;
}

PVOID GetSectionInfo(ULONG_PTR BaseAddress, DWORD dwAddr, DWORD dwChamp)
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
        if ((pSection->VirtualAddress <= dwAddr) && (dwAddr <= (pSection->VirtualAddress + pSection->Misc.VirtualSize))) {
            switch (dwChamp)
            {
                case SEC_NAME:
                    return (PVOID)pSection->Name;
                case SEC_VIRT_SIZE:
                    return (PVOID)pSection->Misc.VirtualSize;
                case SEC_VIRT_ADDR:
                    return (PVOID)pSection->VirtualAddress;
                case SEC_RAW_SIZE:
                    return (PVOID)pSection->SizeOfRawData;
                case SEC_RAW_ADDR:
                    return (PVOID)pSection->PointerToRawData;
                case SEC_CHARAC:
                    return (PVOID)pSection->Characteristics;
            }
        }
        pSection++;
    }
    return NULL;
}

PVOID GetSectionInfo(ULONG_PTR BaseAddress, const char *Name, DWORD dwChamp)
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
                    return (PVOID)pSection->Name;
                case SEC_VIRT_SIZE:
                    return (PVOID)pSection->Misc.VirtualSize;
                case SEC_VIRT_ADDR:
                    return (PVOID)pSection->VirtualAddress;
                case SEC_RAW_SIZE:
                    return (PVOID)pSection->SizeOfRawData;
                case SEC_RAW_ADDR:
                    return (PVOID)pSection->PointerToRawData;
                case SEC_CHARAC:
                    return (PVOID)pSection->Characteristics;
            }
        }
        pSection++;
    }
    return NULL;
}

DWORD RVA2Offset(ULONG_PTR BaseAddress, DWORD dwVA)
{
    DWORD VirtualAddress;
    DWORD PointerToRawData;

    VirtualAddress = (DWORD)GetSectionInfo(BaseAddress, dwVA, SEC_VIRT_ADDR);
    PointerToRawData = (DWORD)GetSectionInfo(BaseAddress, dwVA, SEC_RAW_ADDR);
    return ((dwVA - VirtualAddress) + PointerToRawData);
}

std::list<EXPORTENTRY> GetExport(ULONG_PTR BaseAddress)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT;
    PIMAGE_EXPORT_DIRECTORY pExport;
    WORD NameOrdinal;
    ULONG_PTR FunctionRVA;
    EXPORTENTRY Export;
    std::list<EXPORTENTRY> lExport;

    if (ValidateHeader(BaseAddress) == FALSE) {
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
        if (NameOrdinal >= pExport->NumberOfNames || NameOrdinal >= pExport->NumberOfFunctions)
            continue;
        FunctionRVA = pAddress[NameOrdinal];
        Export.Ordinal = NameOrdinal;
        Export.FunctionRVA = FunctionRVA;
        Export.FunctionVA = FunctionRVA + BaseAddress;
        memset(Export.FunctionName, 0, 256);
        if (index >= pExport->NumberOfNames)
            sprintf_s(Export.FunctionName, 256, "Ordinal_0x%08X", NameOrdinal);
        else
            strncpy_s(Export.FunctionName, 256, (char*)(pApiNames[index] + BaseAddress), 256 - 1);
        lExport.push_back(Export);
    }
    return lExport;
}
#include "dump.h"

extern PE_INFO pinfo;

ULONG_PTR AlignSize(ULONG_PTR size, ULONG_PTR alignement)
{
    return (size % alignement == 0) ? size : ((size / alignement) + 1 ) * alignement;
}

PBYTE AllocDumpedPE(ULONG_PTR ImageBase, PULONG_PTR dwAllocSize)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT;
    PIMAGE_SECTION_HEADER pSection;
    PBYTE pDump = NULL;

    if (ValidateHeader(ImageBase) == FALSE) {
        return NULL;
    }
    pDos = (PIMAGE_DOS_HEADER)ImageBase;
    pNT = (PIMAGE_NT_HEADERS)(ImageBase + pDos->e_lfanew);
    pSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pNT + sizeof(IMAGE_NT_HEADERS));
    *dwAllocSize = pSection[pNT->FileHeader.NumberOfSections - 1].VirtualAddress + pSection[pNT->FileHeader.NumberOfSections - 1].Misc.VirtualSize;
    *dwAllocSize = AlignSize(*dwAllocSize, pNT->OptionalHeader.SectionAlignment);
    pDump = (PBYTE)VirtualAlloc(NULL, *dwAllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pDump) {
        return NULL;
    }
    return pDump;
}

BOOL Write2File(LPCSTR FileName, PBYTE pBuffer, DWORD Size)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD dwWritten = 0;

    if ((hFile = CreateFileA(FileName, (GENERIC_READ | GENERIC_WRITE),
                             FILE_SHARE_READ | FILE_SHARE_READ,
                             NULL, CREATE_ALWAYS, 0, NULL)) == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    WriteFile(hFile, pBuffer, Size, &dwWritten, NULL);
    if (dwWritten != Size) {
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);
    return TRUE;
}

VOID FixPEHeader(ULONG_PTR ImageBase)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT;
    PIMAGE_SECTION_HEADER pSection;

    pDos = (PIMAGE_DOS_HEADER)ImageBase;
    pNT = (PIMAGE_NT_HEADERS)(ImageBase + pDos->e_lfanew);
    pSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pNT + sizeof(IMAGE_NT_HEADERS));
    //pNT->OptionalHeader.FileAlignment = pNT->OptionalHeader.SectionAlignment;
    //pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
    //pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
    pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
    pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;
    //pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
    //pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
    pNT->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
}

BOOL DumpPE(ULONG_PTR ImageBase, LPCSTR dumpFileName, ULONG_PTR dwEntryPoint, BOOL ImportRec)
{
    PBYTE pDump = NULL;
    ULONG_PTR AllocSize;

    if (PrepareDumpPE(ImageBase, &pDump, &AllocSize) == FALSE) {
        return FALSE;
    }
    FixSectionSizeOffset((ULONG_PTR)pDump);
    FixPEHeader((ULONG_PTR)pDump);
    if (dwEntryPoint) {
        EditPE((ULONG_PTR)pDump, ENTRY_POINT, (PVOID)dwEntryPoint);
    }
    if (ImportRec == TRUE) {
        PrepareReconstruct(&pDump, &AllocSize);
        Write2File(dumpFileName, pDump, (DWORD)AllocSize);
    }
    else {
        Write2File(dumpFileName, pDump, (DWORD)AllocSize);
    }
    VirtualFree(pDump, (SIZE_T)AllocSize, 0);
    return TRUE;
}

VOID GetITSectionSizeRVA(ULONG_PTR ImageBase, PULONG_PTR SizeNewSection, PULONG_PTR RVAIT)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT;
    PIMAGE_SECTION_HEADER pSection;

    pDos = (PIMAGE_DOS_HEADER)ImageBase;
    pNT = (PIMAGE_NT_HEADERS)(ImageBase + pDos->e_lfanew);
    pSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pNT + sizeof(IMAGE_NT_HEADERS));
    *SizeNewSection = AlignSize(pinfo.Importer.TotalSizeIT, pNT->OptionalHeader.SectionAlignment);
    *RVAIT = AlignSize(pSection[pNT->FileHeader.NumberOfSections - 1].VirtualAddress + pSection[pNT->FileHeader.NumberOfSections - 1].Misc.VirtualSize, pNT->OptionalHeader.SectionAlignment);
}

BOOL PrepareReconstruct(PBYTE *pDump, PULONG_PTR AllocSize)
{
    PBYTE pNewDump = NULL;
    ULONG_PTR RVAIT;
    ULONG_PTR SizeNewSection;

    GetITSectionSizeRVA((ULONG_PTR)*pDump, &SizeNewSection, &RVAIT);
    pNewDump = (PBYTE)VirtualAlloc(NULL, *AllocSize + SizeNewSection, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pNewDump) {
        DbgMsg("[-] PrepareReconstruct - VirtualAlloc failed\n");
        return FALSE;
    }
    memset(pNewDump, 0, *AllocSize + SizeNewSection);
    memcpy(pNewDump, *pDump, *AllocSize);
    VirtualFree(pDump, (SIZE_T)AllocSize, 0);
    BuildIT(pNewDump, RVAIT);
    AddPESection((ULONG_PTR)pNewDump, ".inj", (DWORD)RVAIT, (DWORD)SizeNewSection, (DWORD)RVAIT, pinfo.Importer.TotalSizeIT);
    EditPE((ULONG_PTR)pNewDump, SIZE_OF_IMAGE, (PVOID)(RVAIT + SizeNewSection));
    EditPE((ULONG_PTR)pNewDump, IMPORT_TABLE, (PVOID)RVAIT);
    EditPE((ULONG_PTR)pNewDump, IMPORT_TABLE_SIZE, (PVOID)pinfo.Importer.TotalSizeIT);
    EditPE((ULONG_PTR)pNewDump, IMPORT_ADDRESS_TABLE, (PVOID)pinfo.Importer.StartIATRVA);
    EditPE((ULONG_PTR)pNewDump, IMPORT_ADDRESS_TABLE_SIZE, (PVOID)(pinfo.Importer.NbTotalApis * sizeof (ULONG_PTR)));
    *pDump = pNewDump;
    *AllocSize = (*AllocSize + SizeNewSection);
    return TRUE;
}

/*
    This method will fix the Raw Size and Offset of Sections
    FileAlignment = pNT->OptionalHeader.SectionAlignment;
*/
BOOL PrepareDumpPE(ULONG_PTR ImageBase, PBYTE *pDump, PULONG_PTR AllocSize)
{
    PIMAGE_DOS_HEADER pDos;
    ULONG_PTR FinalSize = 0;
    DWORD NumberOfSections = 0;
    DWORD FileAlignment = 0;
    ULONG_PTR Align = 0;
    PIMAGE_NT_HEADERS pNT;
    PIMAGE_SECTION_HEADER pSection;

    *pDump = AllocDumpedPE(ImageBase, AllocSize);
    if (*pDump == NULL) {
        DbgMsg("[-] AllocDumpedPE failed\n");
        return FALSE;
    }

    /* Copy DOS HEADER */
    memcpy(*pDump, (LPVOID)ImageBase, sizeof (IMAGE_DOS_HEADER));
    FinalSize += sizeof (IMAGE_DOS_HEADER);

    pDos = (PIMAGE_DOS_HEADER)ImageBase;
    pNT = (PIMAGE_NT_HEADERS)(ImageBase + pDos->e_lfanew);
    pSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pNT + sizeof(IMAGE_NT_HEADERS));

    /* Copy PADDING */
    memcpy(*pDump + FinalSize, (LPVOID)(ImageBase + FinalSize), (ULONG_PTR)pNT - (ULONG_PTR)((ULONG_PTR)pDos + sizeof (IMAGE_DOS_HEADER)));
    FinalSize += (DWORD)((ULONG_PTR)pNT - (ULONG_PTR)((ULONG_PTR)pDos + sizeof (IMAGE_DOS_HEADER)));

    /* Copy NT HEADER */
    memcpy(*pDump + FinalSize, (LPVOID)pNT, sizeof (IMAGE_FILE_HEADER) + pNT->FileHeader.SizeOfOptionalHeader + sizeof(DWORD));
    FinalSize += sizeof (IMAGE_FILE_HEADER) + pNT->FileHeader.SizeOfOptionalHeader + sizeof(DWORD);
    NumberOfSections = pNT->FileHeader.NumberOfSections;
    FileAlignment = pNT->OptionalHeader.FileAlignment;
    FileAlignment = pNT->OptionalHeader.SectionAlignment;

   /* Copy Sections */
    memcpy(*pDump + FinalSize, (LPVOID)pSection, sizeof (IMAGE_SECTION_HEADER) * NumberOfSections);
    FinalSize += sizeof (IMAGE_SECTION_HEADER) * NumberOfSections;
    Align = AlignSize(FinalSize, FileAlignment);
    for (; FinalSize < Align; FinalSize++)
        *(*pDump + FinalSize) = 0;
    for (DWORD i = 0; i < NumberOfSections; i++) {
        memcpy(*pDump + FinalSize, (LPVOID)(ImageBase + pSection[i].VirtualAddress), pSection[i].Misc.VirtualSize);
        FinalSize += pSection[i].Misc.VirtualSize;
        Align = AlignSize(FinalSize, FileAlignment);
        for (; FinalSize < Align; FinalSize++)
            *(*pDump + FinalSize) = 0;
    }
    return TRUE;
}
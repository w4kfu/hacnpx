#include "dump.h"

ULONG_PTR AlignSize(ULONG_PTR size, ULONG_PTR alignement)
{
    return (size % alignement == 0) ? size : ((size / alignement) + 1 ) * alignement;
}

PBYTE AllocDumpedPE(ULONG_PTR ImageBase, DWORD *dwAllocSize)
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
    //pNT->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    for (WORD i = 0; i < pNT->FileHeader.NumberOfSections; i++ ) {
        pSection[i].PointerToRawData = pSection[i].VirtualAddress;
        pSection[i].SizeOfRawData = pSection[i].Misc.VirtualSize;
    }
}

VOID FixPEOEP(ULONG_PTR ImageBase, DWORD dwEntryPoint)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT;

    pDos = (PIMAGE_DOS_HEADER)ImageBase;
    pNT = (PIMAGE_NT_HEADERS)(ImageBase + pDos->e_lfanew);
    pNT->OptionalHeader.AddressOfEntryPoint = dwEntryPoint;
}

/*
    This method will fix the Raw Size and Offset of Sections
    FileAlignment = pNT->OptionalHeader.SectionAlignment;
*/
BOOL DumpPE(ULONG_PTR ImageBase, LPCSTR dumpFileName)
{
    PIMAGE_DOS_HEADER pDos;
    PBYTE pDump = NULL;
    DWORD AllocSize = 0;
    ULONG_PTR FinalSize = 0;
    DWORD NumberOfSections = 0;
    DWORD FileAlignment = 0;
    ULONG_PTR Align = 0;
    PIMAGE_NT_HEADERS pNT;
    PIMAGE_SECTION_HEADER pSection;

    pDump = AllocDumpedPE(ImageBase, &AllocSize);
    if (pDump == NULL) {
        DbgMsg("[-] AllocDumpedPE failed\n");
        return FALSE;
    }

    /* Copy DOS HEADER */
    memcpy(pDump, (LPVOID)ImageBase, sizeof (IMAGE_DOS_HEADER));
    FinalSize += sizeof (IMAGE_DOS_HEADER);

    pDos = (PIMAGE_DOS_HEADER)ImageBase;
    pNT = (PIMAGE_NT_HEADERS)(ImageBase + pDos->e_lfanew);
    pSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pNT + sizeof(IMAGE_NT_HEADERS));

    /* Copy PADDING */
    memcpy(pDump + FinalSize, (LPVOID)(ImageBase + FinalSize), (ULONG_PTR)pNT - (ULONG_PTR)((ULONG_PTR)pDos + sizeof (IMAGE_DOS_HEADER)));
    FinalSize += (ULONG_PTR)pNT - (ULONG_PTR)((ULONG_PTR)pDos + sizeof (IMAGE_DOS_HEADER));

    /* Copy NT HEADER */
    memcpy(pDump + FinalSize, (LPVOID)pNT, sizeof (IMAGE_FILE_HEADER) + pNT->FileHeader.SizeOfOptionalHeader + sizeof(DWORD));
    FinalSize += sizeof (IMAGE_FILE_HEADER) + pNT->FileHeader.SizeOfOptionalHeader + sizeof(DWORD);
    NumberOfSections = pNT->FileHeader.NumberOfSections;
    FileAlignment = pNT->OptionalHeader.FileAlignment;
    FileAlignment = pNT->OptionalHeader.SectionAlignment;

   /* Copy Sections */
    memcpy(pDump + FinalSize, (LPVOID)pSection, sizeof (IMAGE_SECTION_HEADER) * NumberOfSections);
    FinalSize += sizeof (IMAGE_SECTION_HEADER) * NumberOfSections;
    Align = AlignSize(FinalSize, FileAlignment);
    for (; FinalSize < Align; FinalSize++)
        *(pDump + FinalSize) = 0;
    for (DWORD i = 0; i < NumberOfSections; i++) {
        memcpy(pDump + FinalSize, (LPVOID)(ImageBase + pSection[i].VirtualAddress), pSection[i].Misc.VirtualSize);
        FinalSize += pSection[i].Misc.VirtualSize;
        Align = AlignSize(FinalSize, FileAlignment);
        for (; FinalSize < Align; FinalSize++)
            *(pDump + FinalSize) = 0;
    }
    FixPEHeader((ULONG_PTR)pDump);
    Write2File(dumpFileName, pDump, AllocSize);
    VirtualFree(pDump, (SIZE_T)AllocSize, 0);
    return TRUE;
}
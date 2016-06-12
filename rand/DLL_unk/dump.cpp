#include "dump.h"

void start_reconstruct(DWORD dwOEP)
{
	struct infodump info;

	info.dwOEP = dwOEP;
	info.dwBase = (DWORD)GetModuleHandleA(NULL);

	if (dump(&info) == FALSE)
	{
		dbg_msg("[-] dump() failed\n - dwOEP : 0x%08X \n - dwBase : %08X\n", info.dwOEP, info.dwBase);
		return;
	}
	dbg_msg("[+] dump() success !\n - dwOEP : 0x%08X \n - dwBase : %08X\n", info.dwOEP, info.dwBase);
}

PBYTE AllocAndCopy(PBYTE dwBase, DWORD *dwAllocSize)
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pPE;
    PIMAGE_SECTION_HEADER pSectionHeaders;
    PBYTE pDump = NULL;

    pDosHeader = (PIMAGE_DOS_HEADER)dwBase;
    pPE = (PIMAGE_NT_HEADERS)(dwBase + pDosHeader->e_lfanew);
    pSectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)pPE + sizeof(IMAGE_FILE_HEADER) + pPE->FileHeader.SizeOfOptionalHeader + sizeof(DWORD));
    *dwAllocSize = pSectionHeaders[pPE->FileHeader.NumberOfSections-1].VirtualAddress + pSectionHeaders[pPE->FileHeader.NumberOfSections-1].Misc.VirtualSize;
    pDump = (PBYTE)VirtualAlloc(NULL, *dwAllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pDump)
        return NULL;
    memcpy(pDump, dwBase, *dwAllocSize);
    return pDump;
}

/* http://forum.exetools.com/showthread.php?t=11747							 */
/*  OllyDBG v1.10 and ImpREC v1.7f export name buffer overflow vulnerability */
/*	because of dbghelp.dll */
BOOL checknameexport(DWORD dwBase, PIMAGE_DATA_DIRECTORY pDataDirectory)
{
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
	PSTR *pNames;
	PSTR pName;

	if (pDataDirectory->VirtualAddress == 0)
		return FALSE;
	if (pDataDirectory->Size == 0)
		return FALSE;

	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dwBase + pDataDirectory->VirtualAddress);
	pNames = (PSTR*)(dwBase + pExportDirectory->AddressOfNames);
	pName = (PSTR)(dwBase + (DWORD)(*pNames));
	for (int i = 0; i < (int)pExportDirectory->NumberOfNames; i++)
	{
		if (strnlen(pName, 10) > 8)
		{
			return TRUE;
		}
		pNames++;
		pName = (PSTR)(dwBase + (DWORD)(*pNames));
	}
	return FALSE;
}

DWORD AlignSize(DWORD size, DWORD alignement)
{
    return (size % alignement == 0) ? size : ((size / alignement) + 1 ) * alignement;
}

BOOL dump(struct infodump *infodump)
{
	char bDumpedPath[MAX_PATH];
	DWORD dwLen;
    HANDLE hFile;
	DWORD dwSize;
	DWORD dwNbByteWritten;
	PBYTE pDump;
    PIMAGE_DOS_HEADER pDosHeader;
	DWORD dwAllocSize;
    PIMAGE_NT_HEADERS pPE;
    PIMAGE_SECTION_HEADER pSection;
    PIMAGE_SECTION_HEADER pSectionHeaders;
	DWORD dwCursor;
	DWORD dwALignedSize;
	DWORD dwNbSection;

	if (!infodump)
	{
		return FALSE;
	}
	if (!infodump->dwOEP)
	{
		return FALSE;
	}
	FixResource();
	if (((dwLen = GetModuleFileNameA((HMODULE)infodump->dwBase, bDumpedPath, MAX_PATH - 1)) >= MAX_PATH) || (!dwLen))
	{
        return FALSE;
	}
	sprintf_s(bDumpedPath, "%s-dumped.exe", bDumpedPath, MAX_PATH - 1);
	if ((hFile = CreateFileA(bDumpedPath,GENERIC_WRITE,
                             0,
                             NULL, CREATE_ALWAYS, 0, NULL)) == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

   if (!(pDump = AllocAndCopy((PBYTE)infodump->dwBase, &dwAllocSize)))
        return FALSE;
    pDosHeader = (PIMAGE_DOS_HEADER)pDump;
	pPE = (PIMAGE_NT_HEADERS)(pDump + pDosHeader->e_lfanew);
    pSection = (PIMAGE_SECTION_HEADER)((PCHAR)pPE + sizeof (IMAGE_FILE_HEADER) + pPE->FileHeader.SizeOfOptionalHeader + sizeof(DWORD));

	dwNbSection = pPE->FileHeader.NumberOfSections;
	dwSize = dwAllocSize;
	pPE->OptionalHeader.FileAlignment = 0x200;
	pPE->OptionalHeader.SectionAlignment = 0x1000;

	/* FIX TLS CALLBACK, and CHECK dbghelp vuln */
	if (pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0)
	{
		pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
		pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;
	}

	if (checknameexport(infodump->dwBase, &pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]) == TRUE)
	{
		dbg_msg("[+] checknameexport() fix vuln dbghelp\n");
		pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0;
		pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0;
	}
	if (pPE->OptionalHeader.SizeOfHeaders == 0)
	{
		dbg_msg("[-] dump() : pPE->OptionalHeader.SizeOfHeaders == 0\n");
		return FALSE;
	}

	/* FIX OEP */
	pPE->OptionalHeader.AddressOfEntryPoint = infodump->dwOEP - (DWORD)GetModuleHandle(NULL);

	dwCursor = 0;
	dwALignedSize = AlignSize(pPE->OptionalHeader.SizeOfHeaders, pPE->OptionalHeader.FileAlignment);
	dbg_msg("[+] Writing Header, dwAlignedSize = 0x%08X\n", dwALignedSize);
	WriteFile(hFile, pDump, pPE->OptionalHeader.SizeOfHeaders, &dwNbByteWritten, NULL);
	for (int i = 0; i < (dwALignedSize - pPE->OptionalHeader.SizeOfHeaders); i++)
	{
		WriteFile(hFile, "\x90", 1, &dwNbByteWritten, NULL);
	}
	dwCursor = dwALignedSize;

	/* FIX SECTION */
	dwNbSection = 0;
	DWORD dwVirtual = AlignSize(pPE->OptionalHeader.SizeOfHeaders, pPE->OptionalHeader.SectionAlignment);
	for (int i  = 0; i < pPE->FileHeader.NumberOfSections; i++)
	{
		memcpy(&pSection[dwNbSection],  &pSection[i], sizeof (IMAGE_SECTION_HEADER));
		dwALignedSize = AlignSize(pSection[i].Misc.VirtualSize, pPE->OptionalHeader.FileAlignment);
		pSection[dwNbSection].VirtualAddress = dwVirtual;
		pSection[dwNbSection].PointerToRawData = dwCursor;
		pSection[dwNbSection].SizeOfRawData = dwALignedSize;
		dbg_msg("[+] Writing section %s, dwAlignedSize = 0x%08X\n", pSection[i].Name, dwALignedSize);
		/* CHECK USELESS SECTION */
		/*if (!strncmp(".tls", (char*)pSection[i].Name, 4))
		{
			for (int j = 0; j < pSection[i].SizeOfRawData; j++)
			{
				if (*(pDump + pSection[i].VirtualAddress + j) != 0x00)
				{
					goto write_sect;
				}
			}
			pPE->OptionalHeader.SizeOfImage -= pSection[i].Misc.VirtualSize;
			continue;
		}
		write_sect:*/
		WriteFile(hFile, (pDump + pSection[i].VirtualAddress), pSection[i].Misc.VirtualSize, &dwNbByteWritten, NULL);
		for (int j = 0; j < (dwALignedSize - pSection[i].Misc.VirtualSize); j++)
		{
			WriteFile(hFile, "\x90", 1, &dwNbByteWritten, NULL);
		}
		dwVirtual += AlignSize(pSection[i].Misc.VirtualSize, pPE->OptionalHeader.SectionAlignment);
		dwCursor += dwALignedSize;
		dwNbSection += 1;
	}
	pPE->FileHeader.NumberOfSections = dwNbSection;

	SetFilePointer(hFile, 0, 0, FILE_BEGIN);
	WriteFile(hFile, pDump, pPE->OptionalHeader.SizeOfHeaders, &dwNbByteWritten, NULL);


	//WriteFile(hFile, pDump, dwSize, &dwNbByteWritten, NULL);
    /*if (dwNbByteWritten != dwSize)
	{
		CloseHandle(hFile);
		return FALSE;
	}*/
	CloseHandle(hFile);
	return TRUE;
}
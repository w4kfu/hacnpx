#include "af.h"

extern HWND hList;

void SortByAddress(PIMPORT_STRUCT pImport){
	PIMPORT_STRUCT pImport_temp = pImport;
	int array_size = 0;
	IMPORT_STRUCT i1;
	IMPORT_STRUCT i2;

	while (pImport_temp->is_address){
		array_size++;
		pImport_temp++;
	}
	pImport_temp = pImport;

	for (int i = array_size - 1; i > 0; i--){
		for (int j = 0; j < i; j++){
			if (pImport_temp[j].is_address > pImport_temp[j+1].is_address){
				::memcpy(&i1, &pImport[j], sizeof(IMPORT_STRUCT));
				::memcpy(&i2, &pImport[j+1], sizeof(IMPORT_STRUCT));

				::memcpy(&pImport[j+1], &i1, sizeof(IMPORT_STRUCT));
				::memcpy(&pImport[j], &i2, sizeof(IMPORT_STRUCT));
			}
		}
	}



}

void InsertImportsIntoList(PIMPORT_STRUCT pImport)
{
	PIMPORT_STRUCT pImport_temp;
	LVITEM		lvI;
	ULONG i;
	char rva[1024];
	::memset(&lvI, 0, sizeof(LVITEM));
	pImport_temp = pImport;
	LVITEM lvItem;

	while (pImport_temp->is_address)
	{
		
		/*lvI.mask		= LVIF_TEXT;
		lvI.iItem		= ListView_GetItemCount(hList);
		lvI.iSubItem	= 0;
		lvI.pszText		= NULL;
		i = ListView_InsertItem(hList, &lvI);
		sprintf_s((char *)rva, 1024, "%.08X", pImport_temp->is_address);
		ListView_SetItemText(hList, i, 0, rva);
		ListView_SetItemText(hList, i, 1, &pImport_temp->is_dllname);
		if (*(PULONG_PTR)&pImport_temp->is_apiname & 0x8000000000000000){
			::sprintf_s((char *)&rva, 1024, "%.08X", *(PULONG_PTR)&pImport_temp->is_apiname &~ 0x8000000000000000);
			ListView_SetItemText(hList, i, 2, (LPSTR)&rva);
		}else{
			ListView_SetItemText(hList, i, 2, (LPSTR)&pImport_temp->is_apiname);
		}*/
		LVITEM lvItem;
		wchar_t Buf[0x100];

		lvItem.mask = LVIF_TEXT;
		lvItem.iItem = ListView_GetItemCount(hList);

		swprintf_s(Buf, sizeof(Buf), L"%08X", pImport_temp->is_address);
		lvItem.pszText = Buf;
		lvItem.iSubItem = 0;
		SendMessage(hList, LVM_INSERTITEM, 0, (LPARAM)&lvItem);

		swprintf_s(Buf, sizeof(Buf), L"%S", pImport_temp->is_dllname);
		lvItem.pszText = Buf;
		lvItem.iSubItem = 1;
		ListView_SetItem(hList, &lvItem);

		swprintf_s(Buf, sizeof(Buf), L"%S", pImport_temp->is_apiname);
		lvItem.pszText = Buf;
		lvItem.iSubItem = 2;
		ListView_SetItem(hList, &lvItem);

		pImport_temp++;
	}
}

VOID ResoleAPI(HANDLE hProcess, struct Module *mod)
{
	PVOID pdllBase = NULL;
	SIZE_T dwRead;

	PIMAGE_DOS_HEADER mz;
	PIMAGE_NT_HEADERS64 pe64;
	PIMAGE_EXPORT_DIRECTORY pexport;

    DWORD dwNbNames;
    DWORD dwNbExports;
	WORD wOrdinal;

	LogInfo("Processing %s module", mod->pName);
	pdllBase = VirtualAlloc(0, mod->SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	if (pdllBase == NULL)
	{
		LogInfo("VirtualAlloc failed");
		return;
	}
	if (!ReadProcessMemory(hProcess, (LPVOID)mod->Base, pdllBase, mod->SizeOfImage, &dwRead))
	{
		LogInfo("ReadProcessMemory failed : %u", GetLastError());
		goto end;
	}
	mz = (PIMAGE_DOS_HEADER)pdllBase;
	pe64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)pdllBase + mz->e_lfanew);

	pexport = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pe64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (!pexport)
	{
		goto end;
	}
	pexport = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pexport + (ULONG_PTR)pdllBase);
	dwNbNames = pexport->NumberOfNames;
    dwNbExports = pexport->NumberOfFunctions;
	PUSHORT pOrdinals = (PUSHORT)(pexport->AddressOfNameOrdinals + (ULONG_PTR)pdllBase);
	PULONG pAddress = (PULONG)(pexport->AddressOfFunctions + (ULONG_PTR)pdllBase);
	PULONG pApiNames = (PULONG)(pexport->AddressOfNames + (ULONG_PTR)pdllBase);

	for (DWORD index = 0; index < dwNbExports; index++)
	{
		wOrdinal = pOrdinals[index];
		if (wOrdinal >= dwNbNames || wOrdinal >= dwNbExports)
			continue;
		ULONG_PTR Addr = pAddress[wOrdinal] + mod->Base;
		struct Api *napi;

		if (index >= dwNbNames)
		{
			napi = new Api("", Addr, wOrdinal);
		}
		else
		{
			char *name = (char *)(pApiNames[index] + (ULONG_PTR)pdllBase);
			napi = new Api(name, Addr, wOrdinal);
		}
		mod->lapi.push_back(napi);
	}
	end:
	VirtualFree(pdllBase, mod->SizeOfImage, MEM_DECOMMIT);
}

BOOL AnalyzeImports(DWORD dwpid)
{
	PIMAGE_DOS_HEADER mz;
	PIMAGE_NT_HEADERS64 pe64;
	PIMAGE_SECTION_HEADER section;
	HANDLE hFile, hMap;
	PVOID pMap, pCodeSection;
	PBYTE bCurrent;

	HMODULE hModule[4096];
	DWORD cbNeeded;
	HANDLE hProcess;
	MODULEINFO modinfo;
	char FileName[MAX_PATH];
	ULONG_PTR ImgBase;

	ULONG_PTR apiOffset, apiAddress;
	ULONG_PTR rip;

	PIMPORT_STRUCT pImport = NULL;
	PIMPORT_STRUCT pImport_temp = NULL;

	DWORD dwCodeSectSize = 0;

	std::list<struct Module*> lModule;

	LogInfo("Start analyse and imports of pid %08X", dwpid);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwpid);
	if (!hProcess)
	{
		LogInfo("[-] OpenProcess failed : %u", GetLastError());
		return FALSE;
	}
	EnumProcessModules(hProcess, hModule, 4096 * sizeof(HMODULE), &cbNeeded);
	for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
	{
		if (i != 0)
		{
			GetModuleInformation(hProcess, hModule[i], &modinfo, sizeof(MODULEINFO));
			GetModuleBaseNameA(hProcess, hModule[i], FileName, MAX_PATH);

			struct Module *mod = NULL;

			mod = new Module((PBYTE)FileName, (ULONG_PTR)modinfo.lpBaseOfDll, (ULONG_PTR)modinfo.SizeOfImage);

			ResoleAPI(hProcess, mod);

			lModule.push_back(mod);
		}
	}
	GetModuleInformation(hProcess, hModule[0], &modinfo, sizeof(MODULEINFO));
	ImgBase = (ULONG_PTR)modinfo.lpBaseOfDll;
	GetModuleFileNameExA(hProcess, hModule[0], FileName, MAX_PATH);
	LogInfo("Module Name : %s", FileName);
	LogInfo("Module Base : %016llX", ImgBase);
	hFile = CreateFileA(FileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0,0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		LogInfo("[-] CreateFileA failed : %u", GetLastError());
		return FALSE;
	}
	hMap = CreateFileMappingA(hFile, 0, PAGE_READONLY, 0, 0, 0);
	pMap = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
	if (pMap == NULL)
	{
		LogInfo("[-] MapViewOfFile failed : %u", GetLastError());
		return FALSE;
	}

	mz = (PIMAGE_DOS_HEADER)pMap;
	pe64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)pMap + mz->e_lfanew);
	section = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pe64 + 4 + sizeof(IMAGE_FILE_HEADER) + pe64->FileHeader.SizeOfOptionalHeader);

	dwCodeSectSize = section[0].VirtualAddress + section[0].Misc.VirtualSize;
	pCodeSection = GlobalAlloc(GPTR, dwCodeSectSize);
	if (pCodeSection == NULL)
	{
		LogInfo("[-] GlobalAlloc failed : %u", GetLastError());
		goto end;
	}
	ReadProcessMemory(hProcess, (PVOID)(ImgBase + section[0].VirtualAddress), pCodeSection, dwCodeSectSize, 0);

	bCurrent = (PBYTE)pCodeSection;

	pImport = (PIMPORT_STRUCT)VirtualAlloc(0, 0x10000000, MEM_COMMIT, PAGE_READWRITE);

	pImport_temp = pImport;

	while (bCurrent < ((PBYTE)pCodeSection + dwCodeSectSize - 10))
	{
		/*
		2.2.1.6 RIP-Relative Addressing
			A new addressing form, RIP-relative (relative instruction-pointer) addressing, is
			implemented in 64-bit mode. An effective address is formed by adding displacement
			to the 64-bit RIP of the next instruction.
		*/
		if (*(PWORD)bCurrent == 0x15FF ||		//call qword ptr[rip+delta]
			*(PWORD)bCurrent == 0x25FF ||		//jmp  qword ptr[rip+delta]
			*(PWORD)bCurrent == 0x35FF    		//push qword ptr[rip+delta]
			)
		{
			apiOffset = *(int *)(bCurrent + 2);
			rip = bCurrent - (PBYTE)pCodeSection;
			rip += section[0].VirtualAddress + ImgBase;
			rip += 6; //size of instruction
			apiOffset += rip;
			if (ReadProcessMemory(hProcess, (PVOID)apiOffset, &apiAddress, sizeof(ULONG_PTR), 0))
			{
				if (!IsResolved(pImport, apiOffset - ImgBase))
				{
					ResolveApi64_(lModule, apiAddress, pImport_temp);
					LogInfo("API at %.16X %s!%s\n", apiOffset, pImport_temp->is_dllname, pImport_temp->is_apiname);
					pImport_temp->is_address = apiOffset - ImgBase;
					bCurrent += 6;
					pImport_temp++;
					continue;
					/*if (ResolveApi64(dwpid, apiAddress, pImport_temp))
					{
						LogInfo("API at %.16X %s!%s\n", apiOffset, &pImport_temp->is_dllname, &pImport_temp->is_apiname);
						bCurrent += 6;
						pImport_temp++;
						continue;
					}*/
				}
			}
		}

		bCurrent++;
	}
	SortByAddress(pImport);
	InsertImportsIntoList(pImport);
end:
	GlobalFree(pCodeSection);
	UnmapViewOfFile(pMap);
	CloseHandle(hMap);
	CloseHandle(hFile);
	CloseHandle(hProcess);
	return TRUE;
}

BOOL IsResolved(PIMPORT_STRUCT pImport, DWORD rva)
{
	if (!pImport)
		return FALSE;

	while (pImport->is_address)
	{
		if (pImport->is_address == rva) 
			return TRUE;
		pImport++;
	}
	return FALSE;
}
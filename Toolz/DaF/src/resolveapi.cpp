#include "resolveapi.h"

VOID ResolveApi64_(std::list<struct Module*> &lMod, ULONG_PTR apiAddress, PIMPORT_STRUCT pImport)
{
	std::list<struct Module*>::const_iterator 
		lit (lMod.begin()), 
		lend(lMod.end());

	for (;lit != lend; ++lit)
	{
		if (((*lit)->Base <= apiAddress) && (apiAddress <= ((*lit)->Base + (*lit)->SizeOfImage)))
		{
			memcpy(pImport->is_dllname, (*lit)->pName, strlen((char*)(*lit)->pName));

			std::list<struct Api*>::const_iterator 
				lita ((*lit)->lapi.begin()), 
				lenda ((*lit)->lapi.end());

			//LogInfo("(*lita)->Address = %016llX", (*lita)->Address);
			//LogInfo("apiAddress = %016llX", apiAddress);

			for (; lita != lenda; ++lita)
			{
				if ((*lita)->Address == apiAddress)
				{
					if (strlen((*lita)->pName) > 0)
					{
						memcpy(pImport->is_apiname, (*lita)->pName, strlen((*lita)->pName));
					}
					else
					{
						sprintf((char*)pImport->is_apiname, "ORD : %d", (*lita)->Ordinal);
					}
					return;
				}
				//break;
			}
		}
	}
}

ULONG ResolveApi64(DWORD pid, ULONG_PTR apiAddress, PIMPORT_STRUCT pImport)
{
	HANDLE  phandle;
	HMODULE *hModule;
	DWORD numModules, dummy;
	MODULEINFO moduleInfo;
	PVOID dllBase = NULL;
	DWORD dllSize = 0;
	PVOID lDllBase;

	PIMAGE_DOS_HEADER mz;
	PIMAGE_NT_HEADERS64 pe64;
	PIMAGE_EXPORT_DIRECTORY pexport;
	PULONG pAddresses;
	PULONG pApiNames;
	PUSHORT pOrdinals;
	ULONG  index, index_name, i;
	ULONG  apiRva;

	memset(&pImport->is_apiname, 0, 256);
	memset(&pImport->is_dllname, 0, 256);

	phandle = OpenProcess(PROCESS_ALL_ACCESS , 0, pid);
	if (!phandle) return 0;

	hModule = (HMODULE *)GlobalAlloc(GPTR, sizeof(HMODULE) * 1024);
	if (!hModule){ CloseHandle(phandle); return 0; }

	if (!EnumProcessModules(phandle, hModule, sizeof(HMODULE) * 1024, &dummy)){
		GlobalFree(hModule);
		CloseHandle(phandle);
		return 0;
	}

	numModules = dummy / sizeof(HMODULE);

	for (i = 0; i < numModules; i++){
		if (!GetModuleInformation(phandle, hModule[i], &moduleInfo, sizeof(MODULEINFO))) continue;
		
		if (apiAddress < ((ULONG_PTR)moduleInfo.lpBaseOfDll + moduleInfo.SizeOfImage) &&
			apiAddress >= (ULONG_PTR)moduleInfo.lpBaseOfDll){
				dllBase = moduleInfo.lpBaseOfDll;
				dllSize = moduleInfo.SizeOfImage;
				break;
		}
	}

	if (!dllBase){
		GlobalFree(hModule);
		CloseHandle(phandle);
		return 0;
	}

	if (!GetModuleBaseNameA(phandle, hModule[i], (LPSTR)&pImport->is_dllname, 256)){
		GlobalFree(hModule);
		CloseHandle(phandle);
		return 0;
	}

	pImport->is_dlllen = (DWORD)strlen((const char *)&pImport->is_dllname) + 1;

	lDllBase = VirtualAlloc(0, dllSize, MEM_COMMIT, PAGE_READWRITE);
	if (!lDllBase){ CloseHandle(phandle); return 0; }

	if (!ReadProcessMemory(phandle, dllBase, lDllBase, dllSize, (SIZE_T *)&dummy)){
		VirtualFree(lDllBase, dllSize, MEM_DECOMMIT);
		CloseHandle(phandle);
		return 0;
	}


	mz = (PIMAGE_DOS_HEADER)lDllBase;
	pe64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)lDllBase + mz->e_lfanew);

	pexport = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pe64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (!pexport){
		VirtualFree(lDllBase, dllSize, MEM_DECOMMIT);
		CloseHandle(phandle);
		return 0;
	}

	pexport = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pexport + (ULONG_PTR)lDllBase);

	pAddresses = (PULONG)(pexport->AddressOfFunctions + (ULONG_PTR)lDllBase);
	apiRva = (ULONG)(apiAddress - (ULONG_PTR)dllBase);

	for (index = 0; index < pexport->NumberOfFunctions; index++){
		if (pAddresses[index] == apiRva)
			break;
	}

	if (index == pexport->NumberOfFunctions){
		VirtualFree(lDllBase, dllSize, MEM_DECOMMIT);
		CloseHandle(phandle);
		return 0;
	}

	//at this point we already have ordinal index + pexport->Base;
	pOrdinals = (PUSHORT)(pexport->AddressOfNameOrdinals + (ULONG_PTR)lDllBase);

	for (index_name = 0; index_name < pexport->NumberOfNames; index_name++){
		if (pOrdinals[index_name] == index)
			break;
	}
	//return ordinal only...
	if (index_name == pexport->NumberOfNames){
		*(ULONG_PTR *)&pImport->is_apiname = (DWORD)index + pexport->Base | 0x8000000000000000;
		pImport->is_apilen = 8;
	}else{

		pApiNames = (PULONG)(pexport->AddressOfNames + (ULONG_PTR)lDllBase);
		strcpy((char *)&pImport->is_apiname, (const char *)(pApiNames[index_name] + (ULONG_PTR)lDllBase));
		pImport->is_apilen = (DWORD)strlen((const char *)(pApiNames[index_name] + (ULONG_PTR)lDllBase)) + 1;
	}
	VirtualFree(lDllBase, dllSize, MEM_DECOMMIT);
	CloseHandle(phandle);
	return 1;
}
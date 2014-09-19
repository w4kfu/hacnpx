#include "dump.h"

VOID DumpPE64(DWORD pid, LPSTR dumpFileName)
{
	PIMAGE_DOS_HEADER mz;
	PIMAGE_NT_HEADERS64 pe64;
	PIMAGE_SECTION_HEADER section;

	DWORD SizeOfImage;
	DWORD sec_start, sec_size;

	HANDLE fhandle, shandle, d_fhandle, d_shandle;
	PVOID mhandle, d_mhandle;

	HANDLE hProcess;
	HMODULE hMod;
	DWORD cbNeeded;
	MODULEINFO modInfo;
	ULONG_PTR ImgBase;
	ULONG_PTR EntryPoint;
	char originalFileName[MAX_PATH];

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		LogInfo("[-] OpenProcess failed : %u", GetLastError());
		return;
	}
	EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded);
	GetModuleInformation(hProcess, hMod, &modInfo, sizeof(MODULEINFO));
	ImgBase = (ULONG_PTR)modInfo.lpBaseOfDll;
	//if (!oepRva)
		EntryPoint = (ULONG_PTR)modInfo.EntryPoint - ImgBase;
	//else
		//EntryPoint = oepRva;
	GetModuleFileNameExA(hProcess, hMod, originalFileName, MAX_PATH);

	/* ADD CHECK */
	fhandle = CreateFileA(originalFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0,0);
	shandle = CreateFileMappingA(fhandle, 0, PAGE_READONLY, 0,0,0);
	mhandle = MapViewOfFile(shandle, FILE_MAP_READ, 0,0,0);

	mz = (PIMAGE_DOS_HEADER)mhandle;
	pe64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)mhandle + mz->e_lfanew);

	SizeOfImage = pe64->OptionalHeader.SizeOfImage;
	if (SizeOfImage % pe64->OptionalHeader.SectionAlignment)
		SizeOfImage = SizeOfImage - (SizeOfImage % pe64->OptionalHeader.SectionAlignment) + pe64->OptionalHeader.SectionAlignment;

	d_fhandle = CreateFileA(dumpFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
	d_shandle = CreateFileMappingA(d_fhandle, 0, PAGE_READWRITE, 0, SizeOfImage, 0);
	d_mhandle = MapViewOfFile(d_shandle, FILE_MAP_ALL_ACCESS, 0, 0, SizeOfImage);

	memcpy(d_mhandle, mhandle, pe64->OptionalHeader.SizeOfHeaders);

	UnmapViewOfFile(mhandle);
	CloseHandle(shandle);
	CloseHandle(fhandle);

	mz = (PIMAGE_DOS_HEADER)d_mhandle;
	pe64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)d_mhandle + mz->e_lfanew);
	section = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pe64 + 4 + sizeof(IMAGE_FILE_HEADER) + pe64->FileHeader.SizeOfOptionalHeader);

	pe64->OptionalHeader.SizeOfImage = SizeOfImage;
	pe64->OptionalHeader.AddressOfEntryPoint = EntryPoint;
	pe64->OptionalHeader.SizeOfHeaders = 0x1000;

	for (ULONG i = 0; i < pe64->FileHeader.NumberOfSections; i++)
	{
		sec_start = section[i].VirtualAddress;
		sec_size  = section[i].Misc.VirtualSize;

		if (sec_size % pe64->OptionalHeader.SectionAlignment)
			sec_size = sec_size - (sec_size % pe64->OptionalHeader.SectionAlignment) + pe64->OptionalHeader.SectionAlignment;
		
		ReadProcessMemory(hProcess, (PVOID)(ImgBase + sec_start), (PVOID)((ULONG_PTR)d_mhandle + sec_start), sec_size, 0);
		section[i].VirtualAddress = sec_start;
		section[i].PointerToRawData = sec_start;
		section[i].SizeOfRawData    = sec_size;
		section[i].Misc.VirtualSize = sec_size;
		section[i].Characteristics  = 0xE0000020;
	}

	pe64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
	pe64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;

	UnmapViewOfFile(d_mhandle);
	CloseHandle(d_shandle);
	CloseHandle(d_fhandle);

	CloseHandle(hProcess);
}
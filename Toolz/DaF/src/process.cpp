#include "process.h"

DWORD   ProcessIDs[MAX_PROCESS];

BOOL IsProcess64Bit(HANDLE hProcess, HMODULE hMod)
{
	MODULEINFO moduleInfo;
	IMAGE_DOS_HEADER mz;
	IMAGE_NT_HEADERS64 pe64;

	GetModuleInformation(hProcess, hMod, &moduleInfo, sizeof(MODULEINFO));
	if (!ReadProcessMemory(hProcess, (PVOID)(moduleInfo.lpBaseOfDll), (PVOID)(&mz), sizeof (IMAGE_DOS_HEADER), 0))
		return FALSE;
	if (!ReadProcessMemory(hProcess, (PVOID)((ULONG_PTR)moduleInfo.lpBaseOfDll + mz.e_lfanew), (PVOID)(&pe64), sizeof (IMAGE_NT_HEADERS64), 0))
		return FALSE;
	if (pe64.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
		return FALSE;
	return TRUE;
}

VOID ListProcesses(VOID)
{
	DWORD cbNeeded, cProcesses;
	unsigned int i;
	HANDLE hProcess;
	HMODULE hMod;
	char szProcessName[MAX_PATH];
	char b[MAX_PATH];


	EnumProcesses(ProcessIDs, MAX_PROCESS * sizeof(DWORD), &cbNeeded);
	cProcesses = cbNeeded / sizeof(DWORD);
    for (i = 0; i < cProcesses; i++)
    {
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessIDs[i]);
		if (hProcess != NULL)
		{
			if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
			{
				if (IsProcess64Bit(hProcess, hMod) == TRUE)
				{
					GetModuleBaseNameA(hProcess, hMod, szProcessName, MAX_PATH);
					sprintf_s(b, MAX_PATH - 1, "%.08X - %s", ProcessIDs[i], szProcessName);
				}
				else
					goto next;
			}
			else
			{
				sprintf_s(b, MAX_PATH - 1, "%.08X - <unknown>", ProcessIDs[i]);
			}
			ComboxAdd(b);
			next:
				CloseHandle(hProcess);
		}
	}
}
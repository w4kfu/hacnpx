#include "hook_stuff.h"

DWORD dwOldProtect;
DWORD init_vector = 0;
DWORD dwTextAddr;
DWORD dwTextSize;
PVOID protVectoredHandler;

extern std::list<struct ModuleEntry*> listImg;

BOOL (__stdcall *Resume_VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) = NULL;

BOOL (__stdcall *Resume_WriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten) = NULL;

LONG CALLBACK ProtectionFaultVectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    static BOOL stepInto = FALSE;
    DWORD oldProtect;

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
    {
        DWORD address = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
        DWORD eip = ExceptionInfo->ContextRecord->Eip;

        Resume_VirtualProtect((LPVOID)dwTextAddr, dwTextSize, PAGE_EXECUTE_READWRITE, &oldProtect);
        if ((eip == address) && (address >= dwTextAddr) && (address <= (dwTextAddr + dwTextSize)))
        {
			dbg_msg("WUT OEP : %08X !?\n", eip);
            //MessageBoxA(0, "Fuck Yeah !", "OEP Found",0);
            /*print_text_addr(eip, eip);
            fixthisshit(GetModuleHandle(0), eip);
            MessageBoxA(0, "KILL DA PROCESSS !", "KILL THEM ALL",0);*/
            //
			start_reconstruct(eip);
			__asm
			{
				jmp $
			}
			//MessageBoxA(0, "KILL DA PROCESSS !", "KILL THEM ALL",0);
			//TerminateProcess(GetCurrentProcess(), 0);
        }
        else
        {
            stepInto = TRUE;
            ExceptionInfo->ContextRecord->EFlags |= 0x100;
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else if ((ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) && (stepInto))
    {
        Resume_VirtualProtect((LPVOID)dwTextAddr, dwTextSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &oldProtect);
        stepInto = FALSE;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL __stdcall Hook_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    DWORD	return_addr;

	__asm
	{
		mov eax, [ebp + 4]
		mov return_addr, eax
	}
	dbg_msg("VirtualProtect(0x%08X, 0x%08X, 0x%08X, 0x%08X) : 0x%08X\n\n", lpAddress, dwSize, flNewProtect, lpflOldProtect, return_addr);
	dwTextAddr = GetTextAddress(GetModuleHandle(NULL));
	if (lpAddress == (LPVOID)dwTextAddr && flNewProtect == 0x20)
	{
		protVectoredHandler = AddVectoredExceptionHandler(0, ProtectionFaultVectoredHandler);
		//dwTextSize = dwSize;
		dwTextSize = 0x10000;
		//dwTextSize = GetTextSize(GetModuleHandle(NULL));
		dbg_msg("Size = %08X\n", dwTextSize);
		return (Resume_VirtualProtect((LPVOID)lpAddress, dwTextSize, flNewProtect | PAGE_GUARD, &dwOldProtect));
	}
	return (Resume_VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect));
}

BOOL CheckHook(HANDLE hProcess, DWORD lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize)
{
    std::list<struct ModuleEntry*>::iterator it;
    std::list<struct ApiEntry*>::iterator itapi;

    for (it = listImg.begin(); it != listImg.end(); ++it)
    {
        if ((lpBaseAddress >= (*it)->LowOffset) && (lpBaseAddress <= (*it)->HighOffset))
        {
            // New image ?
            if ((*it)->lapi.size() == 0)
            {
				dbg_msg("\t[+] NewImage(0x%08X, \"%s\")\n", (*it)->LowOffset, (*it)->Name.c_str());
                NewImage((*it), (*it)->LowOffset);
            }
			for (itapi = (*it)->lapi.begin(); itapi != (*it)->lapi.end(); ++itapi)
			{
				if ((*itapi)->Address == lpBaseAddress)
				{
					if ((*itapi)->Name.size())
					{
						hex_dump((void*)lpBaseAddress, nSize);
						dbg_msg("\tDIFF\n");
						hex_dump((void*)lpBuffer, nSize);
						dbg_msg("\t[+] Detect Hook !! in (%s) WriteProcessMemory() on %s\n", (*it)->Name.c_str(), (*itapi)->Name.c_str());
						return TRUE;
					}
				}
			}
		}
	}
	return FALSE;
}

BOOL __stdcall Hook_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
{
    DWORD	return_addr;

	__asm
	{
		mov eax, [ebp + 4]
		mov return_addr, eax
	}
	dbg_msg("WriteProcessMemory(0x%08X, 0x%08X, 0x%08X, 0x%08X, 0x%08X) : 0x%08X\n\n", hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten, return_addr);
	GetDllsBaseAddressViaPeb();
	CheckHook(hProcess, (DWORD)lpBaseAddress, lpBuffer, nSize);
	return (Resume_WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten));
}

void	setup_hook(char *module, char *name_export, void *Hook_func, void *trampo, DWORD addr)
{
	DWORD	OldProtect;
	DWORD	len;
	FARPROC	Proc;

	if (addr != 0)
	{
		Proc = (FARPROC)addr;
	}
	else
	{
		Proc = GetProcAddress(GetModuleHandleA(module), name_export);
		if (!Proc)
		    return;
	}
	len = 0;
	while (len < 5)
		len += LDE((BYTE*)Proc + len , LDE_X86);
	memcpy(trampo, Proc, len);
	*(BYTE *)((BYTE*)trampo + len) = 0xE9;
	*(DWORD *)((BYTE*)trampo + len + 1) = (BYTE*)Proc - (BYTE*)trampo - 5;
	VirtualProtect(Proc, len, PAGE_EXECUTE_READWRITE, &OldProtect);
	*(BYTE*)Proc = 0xE9;
	*(DWORD*)((char*)Proc + 1) = (BYTE*)Hook_func - (BYTE*)Proc - 5;
	Resume_VirtualProtect(Proc, len, OldProtect, &OldProtect);
}

void setup_Hook_VirtualProtect(void)
{
	Resume_VirtualProtect = (BOOL(__stdcall *)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect))VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memset(Resume_VirtualProtect, 0x90, 0x1000);
	setup_hook("kernel32.dll", "VirtualProtect", &Hook_VirtualProtect, Resume_VirtualProtect, 0);
}

void setup_Hook_WriteProcessMemory(void)
{
	Resume_WriteProcessMemory = (BOOL(__stdcall *)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten))VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memset(Resume_WriteProcessMemory, 0x90, 0x1000);
	setup_hook("kernel32.dll", "WriteProcessMemory", &Hook_WriteProcessMemory, Resume_WriteProcessMemory, 0);
}

void setup_all_hook(void)
{
	setup_Hook_VirtualProtect();
	setup_Hook_WriteProcessMemory();
}
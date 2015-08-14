#include "ressource.h"

BOOL CheckHook_Ressource(LPCSTR lpModuleName, LPCSTR lpProcName)
{
	HMODULE hBase;
	FARPROC	Proc;
	DWORD dwDest;

	if ((lpModuleName == NULL) || (lpProcName == NULL))
		return FALSE;

	hBase = GetModuleHandleA(lpModuleName);
	if (hBase == NULL)
	{
		dbg_msg("In CheckHook_Ressource(), GetModuleHandleA(\"%s\") return null\n", lpModuleName);
		return FALSE;
	}
	Proc = GetProcAddress(hBase, lpProcName);
	if (Proc == NULL)
	{
		dbg_msg("In CheckHook_Ressource(), GetProcAddress(\"%s\", \"%s\") return null\n", lpModuleName, lpProcName);
		return FALSE;
	}
	if (*(BYTE*)Proc == 0xE9) // jmp ?
	{
		dwDest = *(DWORD*)((BYTE*)Proc + 1);
		dbg_msg("In CheckHook_Ressource(), GetProcAddress(\"%s\", \"%s\") Hook Destination : 0x%08X\n", lpModuleName, lpProcName, (DWORD)((DWORD)Proc + dwDest + 5));
		return TRUE;
	}
	return FALSE;
}

BOOL FixResource(void)
{
	CheckHook_Ressource("ntdll.dll", "LdrFindResource_U");
	CheckHook_Ressource("ntdll.dll", "LdrAccessResource");
	CheckHook_Ressource("user32.dll", "LoadStringA");
	CheckHook_Ressource("user32.dll", "LoadStringW");
	return TRUE;
}

BOOL CheckHook_LdrFindResource_U(void)
{


}

BOOL CheckHook_LdrAccessResource(void)
{


}

BOOL CheckHook_LoadStringA(void)
{

}

BOOL CheckHook_LoadStringW(void)
{

}
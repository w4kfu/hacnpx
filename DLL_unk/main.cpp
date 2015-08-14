#include "hook_stuff.h"
#include "dbg.h"
#include <Windows.h>

/*#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "LDE64.lib")*/

BOOL WINAPI DllMain(HINSTANCE hDLL, DWORD dwReason, LPVOID lpReserved)
{
	DisableThreadLibraryCalls((HMODULE)hDLL);
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		setup_all_hook();
		dbg_msg("[+] setup_all_hook()\n");
	}
	return TRUE;
}
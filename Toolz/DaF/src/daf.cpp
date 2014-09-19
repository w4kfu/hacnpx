#include "daf.h"

HWND hList;
HWND hCombo;
HWND hLogList;

/* TODO : replace global module info */
DWORD dwPid = 0;

void LogInfo(char *format, ...)
{
	char buffer[512];
	va_list args;

	va_start(args, format);
	vsprintf_s(buffer, sizeof (buffer) - 1, format, args);
	SendMessageA(hLogList, LB_ADDSTRING, 0, (LPARAM)buffer);
	va_end(args);
}

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) 
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError()); 
		return FALSE; 
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else
	{
		tp.Privileges[0].Attributes = 0;
	}
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError() ); 
		return FALSE; 
	} 
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	} 
	return TRUE;
}

BOOL GetSeDebugPrivilege(VOID)
{
	HANDLE hToken;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		return FALSE;
	}
	if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
	{
		return FALSE;
	}
	return TRUE;
}

int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	if (GetSeDebugPrivilege() == FALSE)
	{
		MessageBoxA(0, "[-] Can't set SeDebugPrivilege", "DaF", MB_ICONERROR); 
	}
	InitCommonControlsEx(NULL);
	DialogBoxParamA(hInstance, MAKEINTRESOURCEA(IDD_DIALOG1), 0, DialogProc, 0);
	ExitProcess(0);
}

VOID ComboxAdd(LPCSTR txt)
{
	SendMessageA(hCombo, CB_ADDSTRING, 0, (LPARAM)txt);
}

VOID InitColumn(HWND hWin)
{
	LVCOLUMN lvc;

	memset(&lvc, 0, sizeof(LVCOLUMN));
	lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
	lvc.fmt = LVCFMT_LEFT;
	lvc.iSubItem = 0;
	lvc.cx = 100;
	lvc.pszText	= L"RVA";
	lvc.fmt	= LVCFMT_LEFT;
	ListView_InsertColumn(hList, 0, &lvc);
	lvc.cx = 175;
	lvc.pszText	= L"DLL";
	lvc.fmt	= LVCFMT_LEFT;
	ListView_InsertColumn(hList, 1, &lvc);
	lvc.cx = 300;
	lvc.pszText	= L"API";
	lvc.fmt	= LVCFMT_LEFT;
	ListView_InsertColumn(hList, 2, &lvc);
}

VOID DumpFile(HWND hwndDlg)
{
	OPENFILENAMEA ofn;
	char DumpFileName[MAX_PATH];
	
	memset(&ofn, 0, sizeof(OPENFILENAME));
	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.lpstrFilter = "Executable files\0*.exe\0\0";
	ofn.lpstrFile = DumpFileName;
	ofn.nMaxFile = MAX_PATH;
	ofn.hwndOwner = hwndDlg;
	strcpy_s(DumpFileName, MAX_PATH, "dumped.exe");
	if (GetSaveFileNameA(&ofn))
	{
		//::memset(&text, 0, 1024);
		//GetDlgItemTextA(hDlg, IDC_OEPRVA, (LPSTR)&text, 8);
		//::DumpAndFixOep(g_pid, htodw((LPSTR)&text), dumpFileName);
		//::SetDlgItemTextA(hDlg, IDC_STATUS, "Dumping done...");
		DumpPE64(dwPid, DumpFileName);
	}
}

INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	ULONG_PTR i;
	char text[MAX_PATH];

	switch (uMsg)
	{
		case WM_CLOSE:
			EndDialog(hwndDlg, 0);
			return 1;
		case WM_INITDIALOG:
			hCombo = GetDlgItem(hwndDlg, IDC_COMBO1);
			hList = GetDlgItem(hwndDlg, IDC_LIST1);
			hLogList = GetDlgItem(hwndDlg, IDC_LIST2);
			InitColumn(hwndDlg);
			ListProcesses();
			return 1;
		case WM_COMMAND:
			switch (LOWORD(wParam))
			{
				case IDC_COMBO1:
					if (HIWORD(wParam) == CBN_SELENDOK)
					{
						i = SendMessageA(hCombo, CB_GETCURSEL, 0, 0);
						SendMessageA(hCombo, CB_GETLBTEXT, i, (LPARAM)&text);
						SendMessageA(hList, LVM_DELETEALLITEMS, 0, 0);
						SendMessageA(hLogList, LB_RESETCONTENT, 0, 0);
						dwPid = strtol(text, NULL, 16);
						AnalyzeImports(dwPid);
					}
					return 0;
				case ID_DUMP:
					if (dwPid == 0)
					{
						MessageBoxA(hwndDlg, "[-] Plz select a process", "DaF", MB_ICONERROR); 
					}
					else
					{
						DumpFile(hwndDlg);
					}
					return 0;
			}
			return 0;
		default:
			return 0;
	}
	return 0;
}
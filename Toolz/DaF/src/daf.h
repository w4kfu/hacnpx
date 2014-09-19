#ifndef __DAF_H__
#define __DAF_H__

#include <Windows.h>
#include <Commctrl.h>
#include <stdio.h>
#include "resource.h"

#include "process.h"
#include "af.h"
#include "dump.h"

#pragma comment(lib, "Comctl32.lib")

INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
VOID ComboxAdd(LPCSTR txt);
void LogInfo(char *format, ...);

#endif // __DAF_H__
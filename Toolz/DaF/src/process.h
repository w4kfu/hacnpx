#ifndef __PROCESS_H__
#define __PROCESS_H__

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <list>

#include "daf.h"

#define MAX_PROCESS 4096

#pragma comment(lib,"Psapi.lib")

VOID ListProcesses(VOID);

#endif // __PROCESS_H__
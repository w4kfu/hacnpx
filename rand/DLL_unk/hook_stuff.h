#ifndef HOOK_STUFF_H_
#define HOOK_STUFF_H_

#include <windows.h>
#include <stddef.h>

#include "dbg.h"
#include "pestuff.h"
#include "dump.h"
#include "module.h"

#define LDE_X86 0

#ifdef __cplusplus
extern "C"
#endif
int __stdcall LDE(void* address , DWORD type);

# define DLL_NAME "dll.dll"

void setup_all_hook(void);
LONG CALLBACK ProtectionFaultVectoredHandler(PEXCEPTION_POINTERS ExceptionInfo);

#endif // HOOK_STUFF_H_
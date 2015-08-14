#ifndef __RESOURCE_H__
#define __RESOURCE_H__

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include "dbg.h"

BOOL FixResource(void);

BOOL CheckHook_Ressource(void);

BOOL CheckHook_LdrFindResource_U(void);
BOOL CheckHook_LdrAccessResource(void);
BOOL CheckHook_LoadStringA(void);
BOOL CheckHook_LoadStringW(void);

#endif // __RESOURCE_H__
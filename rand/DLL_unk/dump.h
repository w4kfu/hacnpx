#ifndef __DUMP_H__
#define __DUMP_H__

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include "dbg.h"
#include "ressource.h"

#define DUMP_NAME "dumped.exe"

struct infodump
{
	DWORD dwOEP;
	// struct iat, ...

	DWORD dwBase;
};

BOOL dump(struct infodump *infodump);
void start_reconstruct(DWORD dwOEP);

#endif // __DUMP_H__
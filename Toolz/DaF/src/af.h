#ifndef __AF_H__
#define __AF_H__

#include <Windows.h>
#include <psapi.h>

#include <list>

typedef struct Api
{
	char pName[MAX_PATH];
	ULONG_PTR Address;
	WORD Ordinal;

	Api(char *_pName, ULONG_PTR _Address, WORD _Ordinal) :
		Address(_Address),
		Ordinal(_Ordinal)
	{
		memcpy(pName, _pName, MAX_PATH);
	}
} *PApi;

typedef struct Module
{
	char pName[MAX_PATH];
	ULONG_PTR Base;
	ULONG_PTR SizeOfImage;
	std::list<struct Api*> lapi;

	Module(PBYTE _pName, ULONG_PTR _Base, ULONG_PTR _SizeOfImage) :
		Base(_Base),
		SizeOfImage(_SizeOfImage)
	{
		memcpy(pName, _pName, MAX_PATH);
	}
} *PModule;

typedef struct IMPORT_STRUCT
{
	DWORD is_address;			
	DWORD is_apilen;
	DWORD is_dlllen;
	BYTE is_dllname[256];
	BYTE is_apiname[256];

	IMPORT_STRUCT()
	{

	}

	IMPORT_STRUCT(DWORD _is_address, DWORD _is_apilen, DWORD _is_dlllen, BYTE *_is_dllname, BYTE *_is_apiname) :
	is_address(_is_address),
    is_apilen(_is_apilen),
    is_dlllen(_is_dlllen)
	{
		memcpy(is_dllname, _is_dllname, 256);
		memcpy(is_apiname, _is_apiname, 256);
	}

} *PIMPORT_STRUCT;

#include "daf.h"
#include "resolveapi.h"

BOOL AnalyzeImports(DWORD dwpid);
BOOL IsResolved(PIMPORT_STRUCT pImport_c, DWORD rva);

#endif // __AF_H__
#ifndef __MODULE_H__
#define __MODULE_H__

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>


#include <iostream>
#include <list>
#include <string>

#include "dbg.h"

struct ApiEntry
{
    DWORD Address;
    std::string Name;

    ApiEntry(char *AName, DWORD AAddress)
    {
            Name = std::string(AName);
            Address = AAddress;
    }
};

struct ModuleEntry
{
    DWORD LowOffset;
    DWORD HighOffset;
    std::string NamePath;
	std::string Name;
    std::list<struct ApiEntry*> lapi;

    ModuleEntry(DWORD ALowOffset, DWORD AHighOffset, std::string AName)
    {
		unsigned found = AName.find_last_of("/\\");
	
        LowOffset = ALowOffset;
        HighOffset = AHighOffset;
        NamePath = AName;
		Name = AName.substr(found + 1);
    }
};

typedef struct _LSA_UNICODE_STRING 
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} 	LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA 
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
}	PEB_LDR_DATA, *PPEB_LDR_DATA;


typedef struct _LDR_MODULE 
{
  LIST_ENTRY              InLoadOrderModuleList;
  LIST_ENTRY              InMemoryOrderModuleList;
  LIST_ENTRY              InInitializationOrderModuleList;
  PVOID                   BaseAddress;
  PVOID                   EntryPoint;
  ULONG                   SizeOfImage;
  UNICODE_STRING          FullDllName;
  UNICODE_STRING          BaseDllName;
  ULONG                   Flags;
  SHORT                   LoadCount;
  SHORT                   TlsIndex;
  LIST_ENTRY              HashTableEntry;
  ULONG                   TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

#define MIN(a,b) (((a)<(b))?(a):(b))

DWORD GetDllsBaseAddressViaPeb(void);
BOOL IsInModuleList(DWORD dwALowOffset);
VOID NewImage(struct ModuleEntry* entry, UINT32 offset);


#endif // __MODULE_H__
#ifndef __INJECTED_H__
#define __INJECTED_H__

#include <Winsock2.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#pragma warning (push)
#pragma warning (disable:4091)
#include <dbghelp.h>
#pragma warning (pop)
#include <TlHelp32.h>

#include <list>
#include <map>

#include "capstone.h"

typedef struct _EXPORTENTRY {
    WORD Ordinal;
    ULONG_PTR FunctionVA;
    ULONG_PTR FunctionRVA;
    CHAR FunctionName[256];
    ULONG_PTR RVA;
    BOOL isRedirect;
} EXPORTENTRY, *PEXPORTENTRY;

typedef struct _MODULE {
    DWORD dwSize;
    DWORD th32ModuleID;
    DWORD th32ProcessID;
    DWORD GlblcntUsage;
    DWORD ProccntUsage;
    BYTE *modBaseAddr;
    DWORD modBaseSize;
    HMODULE hModule;
    TCHAR szModule[MAX_MODULE_NAME32 + 1];
    TCHAR szExePath[MAX_PATH];
    std::list<PEXPORTENTRY> lExport;
} MODULE, *PMODULE;

typedef struct _IMPORTER
{
    std::list<PMODULE> lModule;
    ULONG_PTR StartIATRVA;
    ULONG_PTR ModulesNameLength;
    ULONG_PTR APIsNameLength;
    DWORD TotalSizeIT;
    ULONG_PTR NbTotalApis;
} IMPORTER, *PIMPORTER;

#include "breakpoint.h"
#include "dbg.h"
#include "disas.h"
#include "dump.h"
#include "hookstuff.h"
#include "iatstuff.h"
#include "injected.h"
#include "memory.h"
#include "modules.h"
#include "pestuff.h"
#include "utils.h"

#ifdef _WIN64
    typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
    typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;
#else
    typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS;
    typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;
#endif

typedef struct UNICODE_STRING32
{
    WORD Length;
    WORD MaximumLength;
    //DWORD alignment;
    union
    {
        DWORD _Buffer;
        WORD* Buffer;
    };
} UNICODE_STRING32;

typedef struct UNICODE_STRING64
{
    WORD Length;
    WORD MaximumLength;
    //DWORD alignment;
    union
    {
        DWORD64 _Buffer;
        WORD* Buffer;
    };
} UNICODE_STRING64;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32                InLoadOrderLinks;
    LIST_ENTRY32                InMemoryOrderLinks;
    LIST_ENTRY32                InInitializationOrderLinks;
    PVOID                       BaseAddress;
    PVOID                       EntryPoint;
    DWORD                       SizeOfImage;
    UNICODE_STRING32            FullDllName;
    UNICODE_STRING32            BaseDllName;
    /*
    +0x000 InLoadOrderLinks : _LIST_ENTRY
    +0x010 InMemoryOrderLinks : _LIST_ENTRY
    +0x020 InInitializationOrderLinks : _LIST_ENTRY
    +0x030 DllBase          : Ptr64 Void
    +0x038 EntryPoint       : Ptr64 Void
    +0x040 SizeOfImage      : Uint4B
    +0x048 FullDllName      : _UNICODE_STRING
    +0x058 BaseDllName      : _UNICODE_STRING
    +0x068 Flags            : Uint4B
    +0x06c LoadCount        : Uint2B
    +0x06e TlsIndex         : Uint2B
    +0x070 HashLinks        : _LIST_ENTRY
    +0x070 SectionPointer   : Ptr64 Void
    +0x078 CheckSum         : Uint4B
    +0x080 TimeDateStamp    : Uint4B
    +0x080 LoadedImports    : Ptr64 Void
    +0x088 EntryPointActivationContext : Ptr64 _ACTIVATION_CONTEXT
    +0x090 PatchInformation : Ptr64 Void
    +0x098 ForwarderLinks   : _LIST_ENTRY
    +0x0a8 ServiceTagLinks  : _LIST_ENTRY
    +0x0b8 StaticLinks      : _LIST_ENTRY
    +0x0c8 ContextInformation : Ptr64 Void
    +0x0d0 OriginalBase     : Uint8B
    */
} LDR_DATA_TABLE_ENTRY32;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY64                InLoadOrderLinks;
    LIST_ENTRY64                InMemoryOrderLinks;
    LIST_ENTRY64                InInitializationOrderLinks;
    PVOID                       BaseAddress;
    PVOID                       EntryPoint;
    DWORD64                     SizeOfImage;
    UNICODE_STRING64            FullDllName;
    UNICODE_STRING64            BaseDllName;
    /*
    +0x000 InLoadOrderLinks : _LIST_ENTRY
    +0x010 InMemoryOrderLinks : _LIST_ENTRY
    +0x020 InInitializationOrderLinks : _LIST_ENTRY
    +0x030 DllBase          : Ptr64 Void
    +0x038 EntryPoint       : Ptr64 Void
    +0x040 SizeOfImage      : Uint4B
    +0x048 FullDllName      : _UNICODE_STRING
    +0x058 BaseDllName      : _UNICODE_STRING
    +0x068 Flags            : Uint4B
    +0x06c LoadCount        : Uint2B
    +0x06e TlsIndex         : Uint2B
    +0x070 HashLinks        : _LIST_ENTRY
    +0x070 SectionPointer   : Ptr64 Void
    +0x078 CheckSum         : Uint4B
    +0x080 TimeDateStamp    : Uint4B
    +0x080 LoadedImports    : Ptr64 Void
    +0x088 EntryPointActivationContext : Ptr64 _ACTIVATION_CONTEXT
    +0x090 PatchInformation : Ptr64 Void
    +0x098 ForwarderLinks   : _LIST_ENTRY
    +0x0a8 ServiceTagLinks  : _LIST_ENTRY
    +0x0b8 StaticLinks      : _LIST_ENTRY
    +0x0c8 ContextInformation : Ptr64 Void
    +0x0d0 OriginalBase     : Uint8B
    */
} LDR_DATA_TABLE_ENTRY64;

typedef struct _PEB_LDR_DATA32
{
      DWORD                     Length;
      DWORD                     Initialized;
      DWORD                     SsHandle;
      LIST_ENTRY                InLoadOrderLinks;
      LIST_ENTRY                InMemoryOrderLinks;
      LIST_ENTRY                InInitializationOrderLinks;
      DWORD                     EntryInProgress;
      DWORD                     ShutdownInProgress;
      DWORD                     ShutdownThreadId;
      /*
      +0x000 Length           : Uint4B
      +0x004 Initialized      : UChar
      +0x008 SsHandle         : Ptr64 Void
      +0x010 InLoadOrderModuleList : _LIST_ENTRY
      +0x020 InMemoryOrderModuleList : _LIST_ENTRY
      +0x030 InInitializationOrderModuleList : _LIST_ENTRY
      +0x040 EntryInProgress  : Ptr64 Void
      +0x048 ShutdownInProgress : UChar
      +0x050 ShutdownThreadId : Ptr64 Void
      */
} PEB_LDR_DATA32;

typedef struct _PEB_LDR_DATA64
{
      DWORD                     Length;
      DWORD                     Initialized;
      DWORD64                   SsHandle;
      LIST_ENTRY                InLoadOrderLinks;
      LIST_ENTRY                InMemoryOrderLinks;
      LIST_ENTRY                InInitializationOrderLinks;
      DWORD64                   EntryInProgress;
      DWORD64                   ShutdownInProgress;
      DWORD64                   ShutdownThreadId;
      /*
      +0x000 Length           : Uint4B
      +0x004 Initialized      : UChar
      +0x008 SsHandle         : Ptr64 Void
      +0x010 InLoadOrderModuleList : _LIST_ENTRY
      +0x020 InMemoryOrderModuleList : _LIST_ENTRY
      +0x030 InInitializationOrderModuleList : _LIST_ENTRY
      +0x040 EntryInProgress  : Ptr64 Void
      +0x048 ShutdownInProgress : UChar
      +0x050 ShutdownThreadId : Ptr64 Void
      */
}PEB_LDR_DATA64;

#ifdef _WIN64
typedef PEB_LDR_DATA64 PEB_LDR_DATA;
typedef PEB_LDR_DATA* PPEB_LDR_DATA;
typedef LDR_DATA_TABLE_ENTRY64 LDR_DATA_TABLE_ENTRY;
typedef LDR_DATA_TABLE_ENTRY* PLDR_DATA_TABLE_ENTRY;
#else
typedef PEB_LDR_DATA32 PEB_LDR_DATA;
typedef PEB_LDR_DATA* PPEB_LDR_DATA;
typedef LDR_DATA_TABLE_ENTRY32 LDR_DATA_TABLE_ENTRY;
typedef LDR_DATA_TABLE_ENTRY* PLDR_DATA_TABLE_ENTRY;
#endif

typedef struct _PEB 
{
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
/*
kd> dt nt!_PEB
   +0x000 InheritedAddressSpace : UChar
   +0x001 ReadImageFileExecOptions : UChar
   +0x002 BeingDebugged    : UChar
   +0x003 BitField         : UChar
   +0x003 ImageUsesLargePages : Pos 0, 1 Bit
   +0x003 IsProtectedProcess : Pos 1, 1 Bit
   +0x003 IsImageDynamicallyRelocated : Pos 2, 1 Bit
   +0x003 SkipPatchingUser32Forwarders : Pos 3, 1 Bit
   +0x003 IsPackagedProcess : Pos 4, 1 Bit
   +0x003 IsAppContainer   : Pos 5, 1 Bit
   +0x003 IsProtectedProcessLight : Pos 6, 1 Bit
   +0x003 SpareBits        : Pos 7, 1 Bit
   +0x004 Padding0         : [4] UChar
   +0x008 Mutant           : Ptr64 Void
   +0x010 ImageBaseAddress : Ptr64 Void
   +0x018 Ldr              : Ptr64 _PEB_LDR_DATA
   ...
*/
} PEB, *PPEB;

VOID StartInjected(VOID);

#endif // __INJECTED_H__

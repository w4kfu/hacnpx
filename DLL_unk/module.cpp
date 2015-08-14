#include "module.h"

std::list<struct ModuleEntry*> listImg;

BOOL IsInModuleList(DWORD dwALowOffset)
{
	for (std::list<struct ModuleEntry*>::iterator it = listImg.begin(); it != listImg.end(); ++it)
	{
		if ((*it)->LowOffset == dwALowOffset)
			return TRUE;
	}
	return FALSE;
}

DWORD GetDllsBaseAddressViaPeb(void)
{
	DWORD Ret = 0;
	ULONG_PTR ldr_addr;
	PPEB_LDR_DATA ldr_data;
	PLDR_MODULE LdMod;
	LPSTR psznameA;
	char Name[500];

	__asm mov eax, fs:[0x30]  //get the PEB ADDR   
	__asm add eax, 0xc           
	__asm mov eax, [eax] // get LoaderData ADDR   
	__asm mov ldr_addr, eax   

  

	ldr_data = (PPEB_LDR_DATA)ldr_addr;
	LdMod = (PLDR_MODULE)ldr_data->InLoadOrderModuleList.Flink;
	while(LdMod->BaseAddress != 0)
	{
		LdMod = (PLDR_MODULE)LdMod->InLoadOrderModuleList.Flink;
		if (IsInModuleList((DWORD)LdMod->BaseAddress) == FALSE)
		{
			sprintf(Name, "%S", LdMod->BaseDllName.Buffer);
			listImg.push_back(new ModuleEntry((DWORD)LdMod->BaseAddress, ((DWORD)LdMod->BaseAddress + LdMod->SizeOfImage), std::string(Name)));
		}
		//printf("%S 0x%x\n", LdMod->BaseDllName.Buffer, (ULONG_PTR)LdMod->BaseAddress);
	}
	return Ret;
}


VOID NewImage(struct ModuleEntry* entry, UINT32 offset)
{
    PIMAGE_DOS_HEADER pIDH = NULL;
    PIMAGE_NT_HEADERS pINTH = NULL;
    PIMAGE_EXPORT_DIRECTORY pIED = NULL;

	pIDH = (PIMAGE_DOS_HEADER)offset;
    pINTH = (PIMAGE_NT_HEADERS)(offset + pIDH->e_lfanew);
    pIED = (PIMAGE_EXPORT_DIRECTORY)(offset + pINTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	
    unsigned long *address_of_names = (unsigned long *)(offset + pIED->AddressOfNames);
    unsigned long *address_of_functions = (unsigned long *)(offset + pIED->AddressOfFunctions);
    unsigned short *address_of_name_ordinals = (unsigned short *)(offset + pIED->AddressOfNameOrdinals);
    unsigned long number_of_names = MIN(pIED->NumberOfFunctions, pIED->NumberOfNames);
    for (unsigned long i = 0; i < number_of_names; i++) 
	{
        char *name = (char *)(offset + address_of_names[i]);
        unsigned char *addr = (unsigned char*)(offset + address_of_functions[address_of_name_ordinals[i]]);
		entry->lapi.push_back(new ApiEntry(name, (DWORD)addr));
	}
}